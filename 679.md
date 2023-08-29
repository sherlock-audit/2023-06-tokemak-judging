Blurry Green Yak

medium

# LMPVault: DoS when `feeSink` balance hits `perWalletLimit`
## Summary

The LMPVault token share has a per-wallet limit. LMPVault collects fees as share tokens to the `feeSink` address. `_collectFees` will revert if it mints shares that make the `feeSink` balance hit the `perWalletLimit`.

## Vulnerability Detail

`_collectFees` mints shares to `feeSink`.

```solidity
function _collectFees(uint256 idle, uint256 debt, uint256 totalSupply) internal {
    address sink = feeSink;
    ....
    if (fees > 0 && sink != address(0)) {
        // Calculated separate from other mints as normal share mint is round down
        shares = _convertToShares(fees, Math.Rounding.Up);
        _mint(sink, shares);
        emit Deposit(address(this), sink, fees, shares);
    }
    ....
}
```

`_mint` calls `_beforeTokenTransfer` internally to check if the target wallet exceeds `perWalletLimit`.

```solidity
function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override whenNotPaused {
    ....
    if (balanceOf(to) + amount > perWalletLimit) {
        revert OverWalletLimit(to);
    }
}
```

`_collectFees` function will revert if `balanceOf(feeSink) + fee shares > perWalletLimit`. `updateDebtReporting`, `rebalance` and `flashRebalance` call `_collectFees` internally so they will be unfunctional.

## Impact

`updateDebtReporting`, `rebalance` and `flashRebalance` won't be working if `feeSink` balance hits `perWalletLimit`.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L823

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L849-L851

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L797

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L703

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L727

## Tool used

Manual Review

## Recommendation

Allow `feeSink` to exceeds `perWalletLimit`.