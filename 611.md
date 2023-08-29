Clean Mulberry Gecko

high

# Differences between actual and cached total assets can be arbitraged
## Summary

The difference between $totalAssets_{cached}$ and $totalAssets_{actual}$ could be arbitraged or exploited by malicious users for their gain, leading to a loss to other vault shareholders.

## Vulnerability Detail

The actual total amount of assets that are owned by a LMPVault on-chain can be derived via the following formula:

$$
totalAssets_{actual} = \sum_{n=1}^{x}debtValue(DV_n)
$$

When `LMPVault.totalAssets()` function is called, it returns the cached total assets of the LMPVault instead.

$$
totalAssets_{cached} = totalIdle + totalDebt
$$

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L304

```solidity
File: LMPVault.sol
304:     function totalAssets() public view override returns (uint256) {
305:         return totalIdle + totalDebt;
306:     }
```

Thus, the $totalAssets_{cached}$ will deviate from $totalAssets_{actual}$. This difference could be arbitraged or exploited by malicious users for their gain.

Certain actions such as `previewDeposit`, `previewMint`, `previewWithdraw,` and `previewRedeem` functions rely on the $totalAssets_{cached}$ value while other actions such as `_withdraw` and `_calcUserWithdrawSharesToBurn` functions rely on $totalAssets_{actual}$ value.

The following shows one example of the issue.

The `previewDeposit(assets)` function computed the number of shares to be received after depositing a specific amount of assets:

$$
shareReceived = \frac{assets_{deposited}}{totalAssets_{cached}} \times totalSupply
$$

Assume that $totalAssets_{cached} < totalAssets_{actual}$, and the values of the variables are as follows:

- $totalAssets_{cached}$ = 110 WETH
- $totalAssets_{actual}$ = 115 WETH
- $totalSupply$ = 100 shares

Assume Bob deposited 10 WETH when the total assets are 110 WETH (when $totalAssets_{cached} < totalAssets_{actual}$), he would receive:

$$
\begin{align}
shareReceived &= \frac{10 ETH}{110 ETH} \times 100e18\ shares \\
&= 9.090909091e18\ shares
\end{align}
$$

If a user deposited 10 WETH while the total assets are updated to the actual worth of 115 WETH (when $totalAssets_{cached} == totalAssets_{actual}$, they would receive:

$$
\begin{align}
shareReceived &= \frac{10 ETH}{115 ETH} \times 100e18\ shares \\
&= 8.695652174e18\ shares \\
\end{align}
$$

Therefore, Bob is receiving more shares than expected.

If Bob redeems all his nine (9) shares after the $totalAssets_{cached}$ has been updated to $totalAssets_{actual}$, he will receive 10.417 WETH back.

$$
\begin{align}
assetsReceived &= \frac{9.090909091e18\ shares}{(100e18 + 9.090909091e18)\ shares} \times (115 + 10)\ ETH \\
&= \frac{9.090909091e18\ shares}{109.090909091e18\ shares} \times 125 ETH \\
&= 10.41666667\ ETH
\end{align}
$$

Bob profits 0.417 WETH simply by arbitraging the difference between the cached and actual values of the total assets. Bob gains is the loss of other vault shareholders.

The $totalAssets_{cached}$ can be updated to $totalAssets_{actual}$ by calling the permissionless `LMPVault.updateDebtReporting` function. Alternatively, one could also perform a sandwich attack against the `LMPVault.updateDebtReporting` function by front-run it to take advantage of the lower-than-expected price or NAV/share, and back-run it to sell the shares when the price or NAV/share rises after the update.

One could also reverse the attack order, where an attacker withdraws at a higher-than-expected price or NAV/share, perform an update on the total assets, and deposit at a lower price or NAV/share.

## Impact

Loss assets for vault shareholders. Attacker gains are the loss of other vault shareholders.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L304

## Tool used

Manual Review

## Recommendation

Consider updating $totalAssets_{cached}$ to $totalAssets_{actual}$ before any withdrawal or deposit to mitigate this issue.