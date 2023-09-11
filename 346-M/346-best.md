Macho Shamrock Huskie

high

# Malicious attackers can perform a DoS attack by executing Router.approve in advance.
## Summary
Malicious attackers can perform a DoS attack by executing `Router.approve` in advance.
## Vulnerability Detail
The protocol has added the `approve` public function in `PeripheryPayments`, which calls `safeApprove`.
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L35-L37
```solidity
    function approve(IERC20 token, address to, uint256 amount) public payable {
        token.safeApprove(to, amount);
    }
```

`safeApprove` only allows the allowance to change from 0 to non-zero, not from non-zero to another non-zero value.
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.8.1/contracts/token/ERC20/utils/SafeERC20.sol#L39-L60
```solidity
    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }
```

In the `_deposit` function of the Router, the `approve` function is called.
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L60-L70
```solidity
    function _deposit(
        ILMPVault vault,
        address to,
        uint256 amount,
        uint256 minSharesOut
    ) internal returns (uint256 sharesOut) {
        approve(IERC20(vault.asset()), address(vault), amount);
        if ((sharesOut = vault.deposit(amount, to)) < minSharesOut) {
            revert MinSharesError();
        }
    }
```

Since `approve` is a public function, an attacker can execute `approve` once before a user's deposit, making the allowance non-zero. When the user tries to deposit, because the allowance is non-zero, the `approve` function will revert, preventing the user from completing the deposit.

Code PoC:
```diff
diff --git a/v2-core-audit-2023-07-14/test/vault/LMPVaultRouter.t.sol b/v2-core-audit-2023-07-14/test/vault/LMPVaultRouter.t.sol
index 93809f8..71b2e27 100644
--- a/v2-core-audit-2023-07-14/test/vault/LMPVaultRouter.t.sol
+++ b/v2-core-audit-2023-07-14/test/vault/LMPVaultRouter.t.sol
@@ -116,7 +116,7 @@ contract LMPVaultRouterTest is BaseTest {
     }

     // TODO: fuzzing
-    function test_deposit() public {
+    function test_deposit_after_approve() public {
         uint256 amount = depositAmount; // TODO: fuzz
         baseAsset.approve(address(lmpVaultRouter), amount);

@@ -127,6 +127,7 @@ contract LMPVaultRouterTest is BaseTest {
         lmpVaultRouter.deposit(lmpVault, address(this), amount, minSharesExpected);

         // -- now do a successful scenario -- //
+        lmpVaultRouter.approve(baseAsset, address(lmpVault), amount);
         _deposit(lmpVault, amount);
     }
```

```shell
forge test --mt 'test_deposit_after_approve' -vv
[⠑] Compiling...
No files changed, compilation skipped

Running 1 test for test/vault/LMPVaultRouter.t.sol:LMPVaultRouterTest
[FAIL. Reason: SafeERC20: approve from non-zero to non-zero allowance] test_deposit_after_approve() (gas: 297037)
Test result: FAILED. 0 passed; 1 failed; finished in 893.76ms

Failing tests:
Encountered 1 failing test in test/vault/LMPVaultRouter.t.sol:LMPVaultRouterTest
[FAIL. Reason: SafeERC20: approve from non-zero to non-zero allowance] test_deposit_after_approve() (gas: 297037)

Encountered a total of 1 failing tests, 0 tests succeeded
```
## Impact
Performing a DoS attack on the core functionality of the protocol.
## Code Snippet
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L35-L37
- https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.8.1/contracts/token/ERC20/utils/SafeERC20.sol#L39-L60
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L60-L70
## Tool used

Manual Review

## Recommendation

Since `safeApprove` is already deprecated, it is recommended to use `safeIncreaseAllowance` as a replacement for `safeApprove`.