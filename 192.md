Crazy Lace Nuthatch

high

# MaverickDestinationVault does not claim the extra veMav
## Summary
[MaverickDestinationVault](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/MaverickDestinationVault.sol) lacks the function/method to claim the **veMav** that is airdropped to liquidity providers.

## Vulnerability Detail
As stating in the Maveric [docs](https://docs.mav.xyz/mav-token/maverick-ecosystem-rewards-pre-season-airdrop#vemav) currently season 1 of the airdrop rewards is going where liquidity provider are amounts are [recorded  from](https://docs.mav.xyz/mav-token/maverick-ecosystem-rewards-pre-season-airdrop#whats-next) **June 22, 2023** up to where the season will end. Afterwards more season are expected. These rewards are gonna be airdropped to liquidity providers (to the Vaults in our case), and since there is currently no mechanism to be claimed/used by users, they are gonna remain stuck in the vaults. Admins have [recover](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/DestinationVault.sol#L293-L315), however **veMav**, like any other **ve** token is not transferable. 

**Note:**
There is currently a function to [claim](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/destinations/adapters/rewards/MaverickRewardsAdapter.sol#L38-L76) rewards, but it will only claim the one in their boosted LP positing, not the veMav.

## Impact
Users will not be able to claim their fair share of rewards veMav rewards.

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/MaverickDestinationVault.sol
## Tool used

Manual Review

## Recommendation
Implement a function for users to claim it or at least use it in some way.