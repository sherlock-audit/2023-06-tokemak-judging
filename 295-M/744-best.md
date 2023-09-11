Melodic Peanut Salamander

high

# Potential vulnerabilities with a 30-Minute Delay in TellorOracle
## Summary

The protocol primarily uses Chainlink as its primary oracle service but falls back to Tellor in case Chainlink is down. However, the Tellor oracle is used with a 30-minute delay, which introduces a  potential risk.

## Vulnerability Detail
In the TellorOracle.sol contract, the following statement is used to retrieve data from the Tellor oracle:

(bytes memory data, uint256 timestamp) = getDataBefore(_queryId, block.timestamp - 30 minutes);

The vulnerability arises from the 30-minute delay in the getPriceInEth function of the TellorOracle contract. This delay means that, in the event of a fallback to Tellor, the system will be using a price that is at least 30 minutes old, which can lead to significant discrepancies in volatile markets.

There is a recent analysis by [Liquity ](https://www.liquity.org/blog/tellor-issue-and-fix) in which they are using 15 minutes for ETH after making some analysis of ETH volatility behaviour. 

Basically, there is a tradeoff between the volatility of an asset and the dispute time. More time is safer to have time to dispute but more likely to read an old value. 

## Impact

The 30-minute delay could lead to a larger differential between the price the system sees and the real market price. This is particularly important in the case of a fallback, as it increases the chances of the system using a stale price. Liquity chose 15 minute to give plenty of time for disputers to respond to fake prices while keeping any adverse impacts on the system to a minimum. Using a 30-minute delay could lead to adverse impacts that Liquity sought to minimize.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/oracles/providers/TellorOracle.sol#L105

## Tool used

Manual Review

## Recommendation

Reduce the delay to a shorter period, such as 15 minutes, as used by Liquity.