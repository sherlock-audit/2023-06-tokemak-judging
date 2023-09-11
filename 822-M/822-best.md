Faint Raisin Monkey

medium

# OOG / unexpected reverts due to incorrect usage of staticcall.
## Summary

OOG / unexpected reverts due to incorrect usage of staticcall.

## Vulnerability Detail

The function `checkReentrancy` in `BalancerUtilities.sol` is used to check if the balancer contract has been re-entered or not. It does this by doing a `staticcall` on the pool contract and checking the return value. According to the solidity docs, if a staticcall encounters a state change, it burns up all gas and returns. The `checkReentrancy` tries to call `manageUserBalance` on the vault contract, and returns if it finds a state change.

The issue is that this burns up all the gas sent with the call. According to EIP150, a call gets allocated 63/64 bits of the gas, and the entire 63/64 parts of the gas is burnt up after the staticcall, since the staticcall will always encounter a storage change. This is also highlighted in the balancer monorepo, which has guidelines on how to check re-entrancy [here](https://github.com/balancer/balancer-v2-monorepo/blob/227683919a7031615c0bc7f144666cdf3883d212/pkg/pool-utils/contracts/lib/VaultReentrancyLib.sol#L43-L55).

This can also be shown with a simple POC.

```solidity
unction testAttack() public {
        mockRootPrice(WSTETH, 1_123_300_000_000_000_000); //wstETH
        mockRootPrice(CBETH, 1_034_300_000_000_000_000); //cbETH

        IBalancerMetaStablePool pool = IBalancerMetaStablePool(WSTETH_CBETH_POOL);

        address[] memory assets = new address[](2);
        assets[0] = WSTETH;
        assets[1] = CBETH;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10_000 ether;
        amounts[1] = 0;

        IBalancerVault.JoinPoolRequest memory joinRequest = IBalancerVault.JoinPoolRequest({
            assets: assets,
            maxAmountsIn: amounts, // maxAmountsIn,
            userData: abi.encode(
                IBalancerVault.JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT,
                amounts, //maxAmountsIn,
                0
            ),
            fromInternalBalance: false
        });

        IBalancerVault.SingleSwap memory swapRequest = IBalancerVault.SingleSwap({
            poolId: 0x9c6d47ff73e0f5e51be5fd53236e3f595c5793f200020000000000000000042c,
            kind: IBalancerVault.SwapKind.GIVEN_IN,
            assetIn: WSTETH,
            assetOut: CBETH,
            amount: amounts[0],
            userData: abi.encode(
                IBalancerVault.JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT,
                amounts, //maxAmountsIn,
                0
            )
        });

        IBalancerVault.FundManagement memory funds = IBalancerVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        emit log_named_uint("Gas before price1", gasleft());
        uint256 price1 = oracle.getPriceInEth(WSTETH_CBETH_POOL);
        emit log_named_uint("price1", price1);
        emit log_named_uint("Gas after price1 ", gasleft());
    }
```

The oracle is called to get a price. This oracle calls the `checkReentrancy` function and burns up the gas. The gas left is checked before and after this call.

The output shows this:

```bash
[PASS] testAttack() (gas: 9203730962297323943)
Logs:
Gas before price1: 9223372036854745204
price1: 1006294352158612428
Gas after price1 : 425625349158468958
```

This shows that 96% of the gas sent is burnt up in the oracle call.

## Impact

This causes the contract to burn up 63/64 bits of gas in a single check. If there are lots of operations after this call, the call can revert due to running out of gas. This can lead to a DOS of the contract.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/libs/BalancerUtilities.sol#L19-L28

## Tool used

Foundry

## Recommendation

According to the monorepo [here](https://github.com/balancer/balancer-v2-monorepo/blob/227683919a7031615c0bc7f144666cdf3883d212/pkg/pool-utils/contracts/lib/VaultReentrancyLib.sol#L43-L55), the staticall must be allocated a fixed amount of gas. Change the reentrancy check to the following.

```solidity
(, bytes memory revertData) = address(vault).staticcall{ gas: 10_000 }(
            abi.encodeWithSelector(vault.manageUserBalance.selector, 0)
        );
```

This ensures gas isn't burnt up without reason.
