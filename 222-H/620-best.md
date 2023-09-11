Clean Mulberry Gecko

high

# Gain From LMPVault Can Be Stolen
## Summary

An attacker can steal the gain of the LMPVault.

## Vulnerability Detail

Assume the following:

- LMPVault called $LV$ integrates with three (3) destination vaults of different protocols ($DV_{curve}$, $DV_{Balancer}$, $DV_{Maverick}$)
- The Tokemak's liquidator had called the `LiquidatorRow.claimsVaultRewards` function against all three DVs, and carried out the necessary liquidation of the reward tokens received from Covex, Aura, and Maverick. After the liquidation, 10 WETH of rewards is queued to each of the DV's MainRewarder contracts.
- If the `LMPVault.updateDebtReporting` function is triggered against the three DVs, $LV$ will be able to collect 30 WETH of reward tokens (10 WETH from each DV's MainRewarder), and $LV$'s total assets will increase by 30 WETH.

For simplicity's sake, assume that there are 100 shares and the total assets are 100 ETH. Thus, the NAV per share is 1.0. If the `LMPVault.updateDebtReporting` function is triggered, the total assets will become 130 ETH (100 ETH + 30 ETH), and the NAV per share will increase to 1.3.

If Alice owned all the 100 shares in the $LV$ where she invested 100 ETH when the vault first accepted deposits from the public, she should gain a profit of 30 ETH.

However, malicious users could perform the following actions within a single transaction to steal most of the gains from Alice (also other users). Protocol fees collected from gain are ignored for simplicity's sake.

1. Assume that the liquidator has queued the rewards of 30 WETH.
2. Bob, a malicious user, could perform a flash loan to borrow 1,000,000 WETH OR perform this attack without a flash loan if he is well-funded.
3. Bob deposited 1,000,000 WETH and minted around 1,000,000 shares.
4. At this point, the vault has 1,000,100 WETH and 1,000,100 shares. The NAV per share is still 1.0.
5. Bob triggers the `LMPVault.updateDebtReporting` function, and the  $LV$'s total assets will increase by 30 WETH to 1,000,130 WETH. The NAV per share is now 1.00002999700029997000299970003.
6. Bob withdrew all his 1,000,000 shares and received back 1000029.997 WETH. 
7. If Bob uses a flash-loan earlier, repay the flash-loan of 1,000,000 WETH and flash-loan fee, which is negligible (2 WEI on dydx).
8. Bob gains 29.997 WETH within a single transaction.
9. Alice only gained a profit of 0.003 WETH, significantly less than the 30 WETH she was supposed to get.

## Impact

Loss of assets for the users as their gain can be stolen.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L37

## Tool used

Manual Review

## Recommendation

Following are the list of root causes of the issue and some recommendation to mitigate them.

- `updateDebtReporting` function is permissionless and can be called by anyone. It is recommended to implement access control to ensure that this function can only be triggered by Tokemak team. Do note that even if the attacker cannot trigger the `updateDebtReporting` function, it is still possible for the attacker to front-run and back-end the `updateDebtReporting` transaction to carry out the attack if they see this transaction in the public mempool. Thus, consider sending the `updateDebtReporting` transaction as a private transaction via Flashbot so that the attacker cannot sandwich the transaction.
- There is no withdrawal fee and/or deposit fee. Therefore, this attack is mostly profitable. It is recommended to impose a fee on the users of the vault. All users should be charged a fee for the use of the vault. This will make the attack less likely to be profitable in most cases.
- Users can enter and exit the vault within the same transaction/block. This allows the attacker to leverage the flash-loan facility to reduce the cost of the attack to almost nothing. It is recommended to prevent users from entering and exiting the vault within the same transaction/block. If the user entered the vault in this block, he/she could only exit at the next block.
- There is no snapshotting to keep track of the deposit to ensure that gains are weighted according to deposit duration. Thus, a whale could deposit right before the `updateDebtReporting` function is triggered and exit the vault afterward and reap most of the gains. Consider implementing snapshotting within the vault.