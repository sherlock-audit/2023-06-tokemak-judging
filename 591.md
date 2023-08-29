Clean Mulberry Gecko

high

# Losses are not distributed equally
## Summary

The losses are not distributed equally, leading to slower users suffering significant losses.

## Vulnerability Detail

Assume that three (3) destination vaults (DVs) and the withdrawal queue are arranged in this order: $DV_A$, $DV_B$, $DV_C$.

Assume the following appreciation and depreciation of the price of the underlying LP tokens of the DV:

- Underlying LP Tokens of $DV_A$ appreciate 5% every T period (Vault in Profit)
- Underlying LP Tokens of $DV_B$ depreciate 5% every T period (Vault in Loss)
- Underlying LP Tokens of $DB_C$ depreciate 10% every T period (Vault in Loss)

For simplicity's sake, all three (3) DVs have the same debt value.

In the current design, if someone withdraws the assets, they can burn as many $DV_A$ shares as needed since $DV_A$ is in profit. If $DV_A$ manages to satisfy the withdrawal amount, the loop will stop here. If not, it will move to $DV_B$ and $DB_C$ to withdraw the remaining amount. 

However, malicious users (also faster users) can abuse this design. Once they notice that LP tokens of $DV_B$ and $DV_C$ are depreciating, they could quickly withdraw as many shares as possible from the $DV_A$ to minimize their loss. As shown in the chart below, once they withdrew all the assets in $DV_A$ at $T14$, the rest of the vault users would suffer a much faster rate of depreciation (~6%). 

Thus, the loss of the LMPVault is not evenly distributed across all participants. The faster actors will incur less or no loss, while slower users suffer a more significant higher loss.

![](https://user-images.githubusercontent.com/102820284/262656636-5bf1e842-e523-4f6a-bbaa-50510331c35a.png)

![](https://user-images.githubusercontent.com/102820284/262656643-0d03b367-7d76-4014-b89a-9882d704e5b4.png)

## Impact 

The losses are not distributed equally, leading to slower users suffering significant losses.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L37

## Tool used

Manual Review

## Recommendation

Consider burning the shares proportionately across all the DVs during user withdrawal so that loss will be distributed equally among all users regardless of the withdrawal timing.