Modern Iris Lemur

medium

# Attacker can spam trigger `_updateReward()` to prevent user receiving reward from rewarder
## Summary
Read Vulnerability Detail

## Vulnerability Detail
The function `AbstractRewarder.rewardPerToken()` serves the purpose of computing the present value of rewards per token. This computation involves aggregating the `rewardPerTokenStored` value with the rewards distributed per token share within the interval from `lastUpdateBlock` to the point at which the most recent applicable reward was granted, denoted as `lastBlockRewardApplicable()`.

```solidity=
function rewardPerToken() public view returns (uint256) {
    uint256 total = totalSupply();
    if (total == 0) {
        return rewardPerTokenStored;
    }

    return rewardPerTokenStored + (
        (lastBlockRewardApplicable() - lastUpdateBlock) * rewardRate * 1e18 / total
    );
}
```

The issue surfaces when the computation of `(lastBlockRewardApplicable() - lastUpdateBlock) * rewardRate * 1e18` ends up being smaller than `totalSupply()`. This situation causes the returned value of `AbstractRewarder.rewardPerToken()` to become `0`. Notably, this function finds application within the `earned()` function, responsible for determining the accrued rewards for a specific account. Consequently, a malicious actor could exploit this flaw by manipulating the `lastUpdateBlock` value to drive the reward amount for each account down to `0`.

```solidity=
function earned(address account) public view returns (uint256) {
    return (
        balanceOf(account) 
        * (rewardPerToken() - userRewardPerTokenPaid[account]) 
        / 1e18
    ) + rewards[account];
}
```

For this manipulation to occur, the reward contract must fulfill a prerequisite where `rewardRate * 1e18 < totalSupply()`. When this condition is met, the attacker gains the ability to trigger the sequence `MainRewarder.getReward() -> AbstractRewarder._updateReward()` with each block, resulting in `lastBlockRewardApplicable() - lastUpdateBlock` being equal to or less than `1`. As a consequence of satisfying this requirement, the value of `rewardPerToken()` becomes `0`.

This particular scenario is likely to transpire if the rewardToken involves a token with a small decimal value and significant valuation, like USDC, while the total supply (`totalSupply()`) of the vault is substantial.

For instance:
- `totalSupply() = 1e26`
- `rewardAmount = 1000$ = 1e9 USDC`, `durationInBlock = 1000` --> `rewardRate = 1e9 / 1000 = 1e6`
- `rewardRate * 1e18 = 1e24 < 1e26 = totalSupply()`

## Impact
Users can't receive the reward from rewarder 

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L174-L181

## Tool used
Manual Review

## Recommendation
Consider using the remainder of the division `(lastBlockRewardApplicable() - lastUpdateBlock) * rewardRate * 1e18 / totalSupply()` for the next calculation of `rewardPerTokenStored`:
```solidity=
function rewardPerToken() public view returns (uint256, uint256) {
    uint256 total = totalSupply();
    if (total == 0) {
        return rewardPerTokenStored;
    }
    
    uint256 quotient = rewardPerTokenStored + (((lastBlockRewardApplicable() - lastUpdateBlock) * rewardRate * 1e18 + lastestRemainder) / total);
    uint256 remainder = (((lastBlockRewardApplicable() - lastUpdateBlock) * rewardRate * 1e18 + lastestRemainder) % total);
    return (quotient, remainder);
}
```
```solidity=
function _updateReward(address account) internal {
    uint256 earnedRewards = 0;
    (rewardPerTokenStored, lastestRemainder) = rewardPerToken();
    ...
}
```