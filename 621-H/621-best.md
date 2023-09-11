Clean Mulberry Gecko

high

# Incorrect pricing for CurveV2 LP Token
## Summary

The price of the CurveV2 LP Tokens is incorrect as the incorrect quote currency is being used when computing the value, resulting in a loss of assets due to the overvaluing or undervaluing of the assets.

## Vulnerability Detail

Using the Curve rETH/frxETH pool (0xe7c6e0a739021cdba7aac21b4b728779eef974d9) to illustrate the issue:

The price of the LP token of Curve rETH/frxETH pool can be obtained via the following `lp_price` function:

https://etherscan.io/address/0xe7c6e0a739021cdba7aac21b4b728779eef974d9#code#L1308

```python
def lp_price() -> uint256:
    """
    Approximate LP token price
    """
    return 2 * self.virtual_price * self.sqrt_int(self.internal_price_oracle()) / 10**18
```

Thus, the formula to obtain the price of the LP token is as follows:

$$
price_{LP} = 2 \times virtualPrice \times \sqrt{internalPriceOracle}
$$

Information about the $internalPriceOracle$ can be obtained from the `pool.price_oracle()` function or from the Curve's Pool page (https://curve.fi/#/ethereum/pools/factory-crypto-218/swap). Refer to the Price Data's Price Oracle section.

https://etherscan.io/address/0xe7c6e0a739021cdba7aac21b4b728779eef974d9#code#L1341

```python
def price_oracle() -> uint256:
    return self.internal_price_oracle()
```

The $internalPriceOracle$ is the price of `coins[1]`(frxETH) with `coins[0]`(rETH) as the quote currency, which means how many rETH (quote) are needed to purchase one frxETH (base).

$$
base/quote \\
frxETH/rETH
$$

During pool registration, the `poolInfo.tokenToPrice` is always set to the second coin (`coins[1]`) as per Line 131 below. In this example, `poolInfo.tokenToPrice` will be set to frxETH token address (`coins[1]`).

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L107

```solidity
File: CurveV2CryptoEthOracle.sol
107:     function registerPool(address curvePool, address curveLpToken, bool checkReentrancy) external onlyOwner {
..SNIP..
125:         /**
126:          * Curve V2 pools always price second token in `coins` array in first token in `coins` array.  This means that
127:          *    if `coins[0]` is Weth, and `coins[1]` is rEth, the price will be rEth as base and weth as quote.  Hence
128:          *    to get lp price we will always want to use the second token in the array, priced in eth.
129:          */
130:         lpTokenToPool[lpToken] =
131:             PoolData({ pool: curvePool, checkReentrancy: checkReentrancy ? 1 : 0, tokenToPrice: tokens[1] });
```

Note that `assetPrice` variable below is equivalent to $internalPriceOracle$ in the above formula.

When fetching the price of the LP token, Line 166 computes the price of frxETH with ETH as the quote currency ($frxETH/ETH$) via the `getPriceInEth` function, and assigns to the `assetPrice` variable.

However, the $internalPriceOracle$ or `assetPrice` should be $frxETH/rETH$ instead of $frxETH/ETH$. Thus, the price of the LP token computed will be incorrect.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L151

```solidity
File: CurveV2CryptoEthOracle.sol
151:     function getPriceInEth(address token) external returns (uint256 price) {
152:         Errors.verifyNotZero(token, "token");
153: 
154:         PoolData memory poolInfo = lpTokenToPool[token];
155:         if (poolInfo.pool == address(0)) revert NotRegistered(token);
156: 
157:         ICryptoSwapPool cryptoPool = ICryptoSwapPool(poolInfo.pool);
158: 
159:         // Checking for read only reentrancy scenario.
160:         if (poolInfo.checkReentrancy == 1) {
161:             // This will fail in a reentrancy situation.
162:             cryptoPool.claim_admin_fees();
163:         }
164: 
165:         uint256 virtualPrice = cryptoPool.get_virtual_price();
166:         uint256 assetPrice = systemRegistry.rootPriceOracle().getPriceInEth(poolInfo.tokenToPrice);
167: 
168:         return (2 * virtualPrice * sqrt(assetPrice)) / 10 ** 18;
169:     }
```

## Impact

The protocol relies on the oracle to provide accurate pricing for many critical operations, such as determining the debt values of DV, calculators/stats used during the rebalancing process, NAV/shares of the LMPVault, and determining how much assets the users should receive during withdrawal. 

Incorrect pricing of LP tokens would result in many implications that lead to a loss of assets, such as users withdrawing more or fewer assets than expected due to over/undervalued vaults or strategy allowing an unprofitable rebalance to be executed.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L151

## Tool used

Manual Review

## Recommendation

Update the `getPriceInEth` function to ensure that the $internalPriceOracle$ or `assetPrice` return the price of `coins[1]` with `coins[0]` as the quote currency.