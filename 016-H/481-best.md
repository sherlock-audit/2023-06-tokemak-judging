Tangy Honeysuckle Dragonfly

high

# Curve V2 Vaults can be drained because CurveV2CryptoEthOracle can be reentered with WETH tokens
## Summary
CurveV2CryptoEthOracle assumes that Curve pools that could be reentered must have `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` token. But this is a wrong assumption cause tokens with WETH token could be reentered too.

## Vulnerability Detail
`CurveV2CryptoEthOracle.registerPool` takes `checkReentrancy` parameters and this should be True only for pools that have `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` tokens and this is validated [here](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L122).
```solidity
address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

...

// Only need ability to check for read-only reentrancy for pools containing native Eth.
if (checkReentrancy) {
    if (tokens[0] != ETH && tokens[1] != ETH) revert MustHaveEthForReentrancy();
}
```

This Oracle is meant for Curve V2 pools and the ones I've seen so far use WETH address instead of `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (like Curve V1) and this applies to all pools listed by Tokemak. 

For illustration, I'll use the same pool used to [test proper registration](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/test/oracles/providers/CurveV2CryptoEthOracle.t.sol#L126-L136). The test is for `CRV_ETH_CURVE_V2_POOL` but this applies to other V2 pools including [rETH/ETH](https://etherscan.io/address/0x0f3159811670c117c372428d4e69ac32325e4d0f). The pool address for `CRV_ETH_CURVE_V2_POOL` is [0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511](https://etherscan.io/address/0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511#code) while token address is [0xEd4064f376cB8d68F770FB1Ff088a3d0F3FF5c4d](https://etherscan.io/address/0xEd4064f376cB8d68F770FB1Ff088a3d0F3FF5c4d).

If you interact with the pool, the coins are:
0 - WETH - 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
1 - CRV - 0xD533a949740bb3306d119CC777fa900bA034cd52

**So how can WETH be reentered?!**
Because Curve can accept ETH for WETH pools.

A look at the [pool](https://etherscan.io/address/0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511#code) again shows that Curve uses python kwargs and it includes a variable `use_eth` for `exchange`, `add_liquidity`, `remove_liquidity` and `remove_liquidity_one_coin`. 

```vyper
def exchange(i: uint256, j: uint256, dx: uint256, min_dy: uint256, use_eth: bool = False) -> uint256:
def add_liquidity(amounts: uint256[N_COINS], min_mint_amount: uint256, use_eth: bool = False) -> uint256:
def remove_liquidity(_amount: uint256, min_amounts: uint256[N_COINS], use_eth: bool = False):
def remove_liquidity_one_coin(token_amount: uint256, i: uint256, min_amount: uint256, use_eth: bool = False) -> uint256:
```

When `use_eth` is `true`, it would take `msg.value` instead of transfer WETH from user. And it would make a raw call instead of transfer WETH to user.

If raw call is sent to user, then they could reenter LMP vault and attack the protocol and it would be successful cause CurveV2CryptoEthOracle would not check for reentrancy in [getPriceInEth](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L160-L163)

```solidity
// Checking for read only reentrancy scenario.
if (poolInfo.checkReentrancy == 1) {
    // This will fail in a reentrancy situation.
    cryptoPool.claim_admin_fees();
}
```

A profitable attack that could be used to drain the vault involves
* Deposit shares at fair price
* Remove liquidity on Curve and updateDebtReporting in LMPVault with view only reentrancy
* Withdraw shares at unfair price

## Impact
The protocol could be attacked with price manipulation using Curve read only reentrancy. The consequence would be fatal because `getPriceInEth` is used for evaluating debtValue and this evaluation decides shares and debt that would be burned in a withdrawal. Therefore, an inflated value allows attacker to withdraw too many asset for their shares. This could be abused to drain assets on LMPVault.

The attack is cheap, easy and could be bundled in as a flashloan attack. And it puts the whole protocol at risk cause a large portion of their deposit would be on Curve V2 pools with WETH token.

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L121-L123
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L160-L163
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/test/oracles/providers/CurveV2CryptoEthOracle.t.sol#L126-L136
https://etherscan.io/address/0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511#code

## Tool used

Manual Review

## Recommendation
If CurveV2CryptoEthOracle is meant for CurveV2 pools with WETH (and no 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE), then change the ETH address to weth. As far as I can tell Curve V2 uses WETH address for ETH but this needs to be verified.

```solidity
-   if (tokens[0] != ETH && tokens[1] != ETH) revert MustHaveEthForReentrancy();
+   if (tokens[0] != WETH && tokens[1] != WETH) revert MustHaveEthForReentrancy();
```
