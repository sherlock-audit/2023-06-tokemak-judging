Nutty Admiral Scorpion

high

# Incorrect calculation of lp token value for legacy balancer vaults
## Summary
 Incorrect calculation of lp token value for legacy balancer vaults

## Vulnerability Detail

On the `BalancerLPMetaStableEthOracle` contract, the function `getPriceInEth()` calculates the price of the Lp by getting it's totalSupply as `uint256 totalSupply = pool.totalSupply();`

```solidity
uint256 virtualPrice = pool.getRate(); // e18
uint256 totalSupply = pool.totalSupply();
```
According to Balancer's docs, this is not the way to do it for all the vaults. `totalSupply()` should only be used for old "legacy" [pools](https://docs.balancer.fi/concepts/advanced/valuing-bpt/valuing-bpt.html#totalsupply). Currently, [getActualSupply](https://docs.balancer.fi/concepts/advanced/valuing-bpt/valuing-bpt.html#getactualsupply) should be used instead because it accounts for the pre-minted BPT and fees.

## Impact
This will cause an  incorrect calculation of lp token value for legacy balancer vaults

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/oracles/providers/BalancerLPMetaStableEthOracle.sol#L35C56-L77

## Tool used

Manual Review

## Recommendation

Do use a differentiation between balancer pools. The ones that are legacy should be treated differently than the ones that are not.:

```solidity
if (legacy == true) {
supply = pool.totalSupply(); 
} else {
supply = pool.getActualSupply(); 
}
```