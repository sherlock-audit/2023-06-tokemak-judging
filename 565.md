Clean Mulberry Gecko

medium

# Unable to withdraw extra rewards
## Summary

Users are unable to withdraw extra rewards due to staking of TOKE that is less than `MIN_STAKE_AMOUNT`, resulting in them being stuck in the contracts.

## Vulnerability Detail

Suppose Bob only has 9999 Wei TOKE tokens as main rewards and 100e18 DAI as extra rewards in this account.

When attempting to get the rewards, the code will always get the main rewards, followed by the extra rewards, as shown below.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/MainRewarder.sol#L108

```solidity
File: MainRewarder.sol
108:     function _processRewards(address account, bool claimExtras) internal {
109:         _getReward(account);
110: 
111:         //also get rewards from linked rewards
112:         if (claimExtras) {
113:             for (uint256 i = 0; i < extraRewards.length; ++i) {
114:                 IExtraRewarder(extraRewards[i]).getReward(account);
115:             }
116:         }
117:     }
```

If the main reward is TOKE, they will be staked to the `GPToke` at Line 376 below.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L354

```solidity
File: AbstractRewarder.sol
354:     function _getReward(address account) internal {
355:         Errors.verifyNotZero(account, "account");
356: 
357:         uint256 reward = earned(account);
358:         (IGPToke gpToke, address tokeAddress) = (systemRegistry.gpToke(), address(systemRegistry.toke()));
359: 
360:         // slither-disable-next-line incorrect-equality
361:         if (reward == 0) return;
362: 
363:         rewards[account] = 0;
364:         emit RewardPaid(account, reward);
365: 
366:         // if NOT toke, or staking is turned off (by duration = 0), just send reward back
367:         if (rewardToken != tokeAddress || tokeLockDuration == 0) {
368:             IERC20(rewardToken).safeTransfer(account, reward);
369:         } else {
370:             // authorize gpToke to get our reward Toke
371:             // slither-disable-next-line unused-return
372:             IERC20(address(tokeAddress)).approve(address(gpToke), reward);
373: 
374:             // stake Toke
375:             gpToke.stake(reward, tokeLockDuration, account);
376:         }
377:     }
```

However, if the staked amount is less than the minimum stake amount (`MIN_STAKE_AMOUNT`), the function will revert.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/staking/GPToke.sol#L98

```solidity
File: GPToke.sol
32:     uint256 public constant MIN_STAKE_AMOUNT = 10_000;
..SNIP..
098:     function _stake(uint256 amount, uint256 duration, address to) internal whenNotPaused {
099:         //
100:         // validation checks
101:         //
102:         if (to == address(0)) revert ZeroAddress();
103:         if (amount < MIN_STAKE_AMOUNT) revert StakingAmountInsufficient();
104:         if (amount > MAX_STAKE_AMOUNT) revert StakingAmountExceeded();
```

In this case, Bob will not be able to redeem his 100 DAI reward when processing the reward. The code will always attempt to stake 9999 Wei Toke and revert because it fails to meet the minimum stake amount.

## Impact

There is no guarantee that the users' TOKE rewards will always be larger than `MIN_STAKE_AMOUNT` as it depends on various factors such as the following:

- The number of vault shares they hold. If they hold little shares, their TOKE reward will be insignificant
- If their holding in the vault is small compared to the others and the entire vault, the TOKE reward they received will be insignificant
- The timing they join the vault. If they join after the reward is distributed, they will not be entitled to it.

As such, the affected users will not be able to withdraw their extra rewards, and they will be stuck in the contract.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/MainRewarder.sol#L108

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L354

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/staking/GPToke.sol#L98

## Tool used

Manual Review

## Recommendation

To remediate the issue, consider collecting TOKE and staking it to the `GPToke` contract only if it meets the minimum stake amount.

```diff
function _getReward(address account) internal {
    Errors.verifyNotZero(account, "account");

    uint256 reward = earned(account);
    (IGPToke gpToke, address tokeAddress) = (systemRegistry.gpToke(), address(systemRegistry.toke()));

    // slither-disable-next-line incorrect-equality
    if (reward == 0) return;

-    rewards[account] = 0;
-    emit RewardPaid(account, reward);

    // if NOT toke, or staking is turned off (by duration = 0), just send reward back
    if (rewardToken != tokeAddress || tokeLockDuration == 0) {
+		rewards[account] = 0;
+		emit RewardPaid(account, reward);
        IERC20(rewardToken).safeTransfer(account, reward);
    } else {
+    	if (reward >= MIN_STAKE_AMOUNT) {
+			rewards[account] = 0;
+			emit RewardPaid(account, reward);
+
            // authorize gpToke to get our reward Toke
            // slither-disable-next-line unused-return
            IERC20(address(tokeAddress)).approve(address(gpToke), reward);

            // stake Toke
            gpToke.stake(reward, tokeLockDuration, account);
+		}
    }
}
```