Future Spruce Fox

medium

# LMPVault exchange rate can potentially be reset by flashloan causing loss of user funds
## Summary
It is possible for the exchange rate of shares/tokens to be reset to 1:1 via flashloan, causing loss of funds for protocol/users. Further detail can be found in this twitter thread: https://twitter.com/kankodu/status/1685320718870032384.

## Vulnerability Detail
Consider the following thought experiment: 

Lets start with an LMPVault that accepts WETH as the underlying and has share token tokWETH. Lets assume the strategy for the vault involves staking all share tokens in a protocol, which we'll call protocolF, that allows flashloans. Lets further assume that the vault is in a state such that  the exchange rate for 1 tokWETH is 2 WETH ie, to mint 1 tokWETH token at S0 (current state) a user must supply 2 WETH. 

A malicious user would be able to flashloan the entire supply of the LMPVault from protocolF. They would then redeem all underlying assets in the LMPVault and receive 2 WETH for each tokWETH redeemed. They then remint the same number of tokWETH by supplying an equal number of WETH at a 1:1 ratio plus any additional WETH needed to repay a fee denominated in tokWETH, and repay the flashloan, thereby stealing almost half of the underlying WETH in the vault. This would give us S1, a state where the totalSupply of tokWETH is unchanged, however the exchange rate and underlying assets are cut in half to 1:1. 

Submitting this a medium level vulnerability because while user funds are potentially directly at risk, this exploit requires many different factors aligning to be exploited, (singular destination vault etc) and thus is unlikely to happen in (most) cases.

## Impact
This vulnerability does require the vault to be in a specific state, however as the twitter thread above provided shows, this state is not outside the realms of possibility. The impact of such a transaction would be that all users in the vault have realized ~50% loss of funds due to our malicious actor. 

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L591

## Tool used
Manual Review

## Recommendation
Per this issue thread on OpenZeppelins 4626 implementation: https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3800, I recommend implementing a requirement that once a vault has been initialized and funded, totalSupply must remain greater than some threshold. A common threshold used for this is 1 gwei. This ensures that the current exchange rate will always be kept track of and prevent this attack vector. 
