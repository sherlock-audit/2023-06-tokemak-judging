Clean Mulberry Gecko

high

# Incorrect number of shares minted as fee
## Summary

An incorrect number of shares was minted as fees during fee collection, resulting in a loss of fee.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L818

```solidity
File: LMPVault.sol
818:             profit = (currentNavPerShare - effectiveNavPerShareHighMark) * totalSupply;
819:             fees = profit.mulDiv(performanceFeeBps, (MAX_FEE_BPS ** 2), Math.Rounding.Up);
820:             if (fees > 0 && sink != address(0)) {
821:                 // Calculated separate from other mints as normal share mint is round down
822:                 shares = _convertToShares(fees, Math.Rounding.Up);
823:                 _mint(sink, shares);
824:                 emit Deposit(address(this), sink, fees, shares);
825:             }
```

Assume that the following states:

- The `profit` is 100 WETH
- The fee is 20%, so the `fees` will be 20 WETH.
- `totalSupply` is 100 shares and `totalAssets()` is 1000 WETH

Let the number of shares to be minted be $shares2mint$. The current implementation uses the following formula (simplified) to determine $shares2mint$.

$$
\begin{align}
shares2mint &= fees \times \frac{totalSupply}{totalAsset()} \\
&= 20\ WETH \times \frac{100\ shares}{1000\ WETH} \\
&= 2\ shares
\end{align}
$$

In this case, two (2) shares will be minted to the `sink` address as the fee is taken.

However, the above formula used in the codebase is incorrect. The total cost/value of the newly-minted shares does not correspond to the fee taken. Immediately after the mint, the value of the two (2) shares is worth only 19.60 WETH, which does not correspond to the 20 WETH fee that the `sink` address is entitled to.

$$
\begin{align}
value &= 2\ shares \times \frac{1000\ WETH}{100 + 2\ shares} \\
&= 2\ shares \times 9.8039\ WETH\\
&= 19.6078\ WETH
\end{align}
$$

## Impact

Loss of fee. Fee collection is an integral part of the protocol; thus the loss of fee is considered a High issue.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L818

## Tool used

Manual Review

## Recommendation

The correct formula to compute the number of shares minted as fee should be as follows: 

$$
\begin{align}
shares2mint &= \frac{profit \times performanceFeeBps \times totalSupply}{(totalAsset() \times MAX\_FEE\_BPS) - (performanceFeeBps \times profit) } \\
&= \frac{100\epsilon \times 2000 \times 100 shares}{(1000\epsilon \times 10000) - (2000 \times 100\epsilon)} \\
&= 2.0408163265306122448979591836735\ shares
\end{align}
$$

The above formula is the same as the one LIDO used (https://docs.lido.fi/guides/steth-integration-guide/#fees)

The following is the proof to show that `2.0408163265306122448979591836735` shares are worth 20 WETH after the mint.

$$
\begin{align}
value &= 2.0408163265306122448979591836735\ shares \times \frac{1000\ WETH}{100 + 2.0408163265306122448979591836735\ shares} \\
&= 2.0408163265306122448979591836735\ shares \times 9.8039\ WETH\\
&= 20\ WETH
\end{align}
$$