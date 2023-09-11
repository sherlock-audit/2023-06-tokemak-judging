Macho Shamrock Huskie

high

# ETH deposited by the user may be stolen.
## Summary
Due to the fact that the WETH obtained through `_processEthIn` belongs to the contract, and `pullToken` transfers assets from `msg.sender`, it is possible for users to transfer excess WETH to the contract, allowing attackers to steal WETH from within the contract using `sweepToken`.

Both `mint` and `deposit` in `LMPVaultRouterBase` have this problem.
## Vulnerability Detail
In the `deposit` function, if the user pays with ETH, it will first call `_processEthIn` to wrap it and then call `pullToken` to transfer.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L43-L57
```solidity
    /// @inheritdoc ILMPVaultRouterBase
    function deposit(
        ILMPVault vault,
        address to,
        uint256 amount,
        uint256 minSharesOut
    ) public payable virtual override returns (uint256 sharesOut) {
        // handle possible eth
        _processEthIn(vault);

        IERC20 vaultAsset = IERC20(vault.asset());
        pullToken(vaultAsset, amount, address(this));

        return _deposit(vault, to, amount, minSharesOut);
    }
```

`_processEthIn` will wrap ETH into WETH, and these WETH belong to the contract itself.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L111-L122
```solidity
    function _processEthIn(ILMPVault vault) internal {
        // if any eth sent, wrap it first
        if (msg.value > 0) {
            // if asset is not weth, revert
            if (address(vault.asset()) != address(weth9)) {
                revert InvalidAsset();
            }

            // wrap eth
            weth9.deposit{ value: msg.value }();
        }
    }
```

However, `pullToken` transfers from `msg.sender` and does not use the WETH obtained in `_processEthIn`.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L54-L56
```solidity
    function pullToken(IERC20 token, uint256 amount, address recipient) public payable {
        token.safeTransferFrom(msg.sender, recipient, amount);
    }
```

If the user deposits 10 ETH and approves 10 WETH to the contract, when the deposit amount is 10, all of the user's 20 WETH will be transferred into the contract.

However, due to the `amount` being 10, only 10 WETH will be deposited into the vault, and the remaining 10 WETH can be stolen by the attacker using `sweepToken`.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L58-L65
```solidity
    function sweepToken(IERC20 token, uint256 amountMinimum, address recipient) public payable {
        uint256 balanceToken = token.balanceOf(address(this));
        if (balanceToken < amountMinimum) revert InsufficientToken();

        if (balanceToken > 0) {
            token.safeTransfer(recipient, balanceToken);
        }
    }
```

Both `mint` and `deposit` in `LMPVaultRouterBase` have this problem.

## Impact
ETH deposited by the user may be stolen.
## Code Snippet
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L43-L57
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L54-L56
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L58-L65
## Tool used

Manual Review

## Recommendation
Perform operations based on the size of `msg.value` and `amount`:
1. `msg.value == amount`: transfer WETH from contract not `msg.sender`
2. `msg.value > amount`: transfer WETH from contract not `msg.sender` and refund to `msg.sender`
3. `msg.value < amount`: transfer WETH from contract and transfer remaining from `msg.sender`