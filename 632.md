Modern Iris Lemur

medium

# Incorrect handling of Stash Tokens within the `ConvexRewardsAdapter._claimRewards()`
## Summary
The `ConvexRewardsAdapter._claimRewards()` function incorrectly handles Stash tokens, leading to potential vulnerabilities.

## Vulnerability Detail
The primary task of the `ConvexRewardAdapter._claimRewards()` function revolves around claiming rewards for Convex/Aura staked LP tokens.

```solidity=
function _claimRewards(
    address gauge,
    address defaultToken,
    address sendTo
) internal returns (uint256[] memory amounts, address[] memory tokens) {
    ... 

    // Record balances before claiming
    for (uint256 i = 0; i < totalLength; ++i) {
        // The totalSupply check is used to identify stash tokens, which can
        // substitute as rewardToken but lack a "balanceOf()"
        if (IERC20(rewardTokens[i]).totalSupply() > 0) {
            balancesBefore[i] = IERC20(rewardTokens[i]).balanceOf(account);
        }
    }

    // Claim rewards
    bool result = rewardPool.getReward(account, /*_claimExtras*/ true);
    if (!result) {
        revert RewardAdapter.ClaimRewardsFailed();
    }

    // Record balances after claiming and calculate amounts claimed
    for (uint256 i = 0; i < totalLength; ++i) {
        uint256 balance = 0;
        // Same check for "stash tokens"
        if (IERC20(rewardTokens[i]).totalSupply() > 0) {
            balance = IERC20(rewardTokens[i]).balanceOf(account);
        }

        amountsClaimed[i] = balance - balancesBefore[i];

        if (sendTo != address(this) && amountsClaimed[i] > 0) {
            IERC20(rewardTokens[i]).safeTransfer(sendTo, amountsClaimed[i]);
        }
    }

    RewardAdapter.emitRewardsClaimed(rewardTokens, amountsClaimed);

    return (amountsClaimed, rewardTokens);
}
``` 

An intriguing aspect of this function's logic lies in its management of "stash tokens" from AURA staking. The check to identify whether `rewardToken[i]` is a stash token involves attempting to invoke `IERC20(rewardTokens[i]).totalSupply()`. If the returned total supply value is `0`, the implementation assumes the token is a stash token and bypasses it. However, this check is flawed since the total supply of stash tokens can indeed be non-zero. For instance, at this [address](https://etherscan.io/address/0x2f5c611420c8ba9e7ec5c63e219e3c08af42a926#readContract), the stash token has `totalSupply = 150467818494283559126567`, which is definitely not zero.

This misstep in checking can potentially lead to a Denial-of-Service (DOS) situation when calling the `claimRewards()` function. This stems from the erroneous attempt to call the `balanceOf` function on stash tokens, which lack the `balanceOf()` method. Consequently, such incorrect calls might incapacitate the destination vault from claiming rewards from AURA, resulting in protocol losses.

## Impact
* The `AuraRewardsAdapter.claimRewards()` function could suffer from a Denial-of-Service (DOS) scenario.
* The destination vault's ability to claim rewards from AURA staking might be hampered, leading to protocol losses.

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/destinations/adapters/rewards/ConvexRewardsAdapter.sol#L80-L86

## Tool used
Manual Review

## Recommendation
To accurately determine whether a token is a stash token, it is advised to perform a low-level `balanceOf()` call to the token and subsequently validate the call's success.