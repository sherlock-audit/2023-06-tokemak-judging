Amusing Merlot Octopus

high

# Incorrect amount given as input to `_handleRebalanceIn` when `flashRebalance` is called
## Summary

When `flashRebalance` is called, the wrong deposit amount is given to the `_handleRebalanceIn` function as the whole `tokenInBalanceAfter` amount is given as input instead of the delta value `tokenInBalanceAfter - tokenInBalanceBefore`, this will result in an incorrect rebalance operation and can potentialy lead to a DOS due to the insufficient amount error.

## Vulnerability Detail

The issue occurs in the `flashRebalance` function below :

```solidity
function flashRebalance(
    DestinationInfo storage destInfoOut,
    DestinationInfo storage destInfoIn,
    IERC3156FlashBorrower receiver,
    IStrategy.RebalanceParams memory params,
    FlashRebalanceParams memory flashParams,
    bytes calldata data
) external returns (uint256 idle, uint256 debt) {
    ...

    // Handle increase (shares coming "In", getting underlying from the swapper and trading for new shares)
    if (params.amountIn > 0) {
        IDestinationVault dvIn = IDestinationVault(params.destinationIn);

        // get "before" counts
        uint256 tokenInBalanceBefore = IERC20(params.tokenIn).balanceOf(address(this));

        // Give control back to the solver so they can make use of the "out" assets
        // and get our "in" asset
        bytes32 flashResult = receiver.onFlashLoan(msg.sender, params.tokenIn, params.amountIn, 0, data);

        // We assume the solver will send us the assets
        uint256 tokenInBalanceAfter = IERC20(params.tokenIn).balanceOf(address(this));

        // Make sure the call was successful and verify we have at least the assets we think
        // we were getting
        if (
            flashResult != keccak256("ERC3156FlashBorrower.onFlashLoan")
                || tokenInBalanceAfter < tokenInBalanceBefore + params.amountIn
        ) {
            revert Errors.FlashLoanFailed(params.tokenIn, params.amountIn);
        }

        if (params.tokenIn != address(flashParams.baseAsset)) {
            // @audit should be `tokenInBalanceAfter - tokenInBalanceBefore` given to `_handleRebalanceIn`
            (uint256 debtDecreaseIn, uint256 debtIncreaseIn) =
                _handleRebalanceIn(destInfoIn, dvIn, params.tokenIn, tokenInBalanceAfter);
            idleDebtChange.debtDecrease += debtDecreaseIn;
            idleDebtChange.debtIncrease += debtIncreaseIn;
        } else {
            idleDebtChange.idleIncrease += tokenInBalanceAfter - tokenInBalanceBefore;
        }
    }
    ...
}
```

As we can see from the code above, the function executes a flashloan in order to receive th tokenIn amount which should be the difference between `tokenInBalanceAfter` (balance of the contract after the flashloan) and `tokenInBalanceBefore` (balance of the contract before the flashloan) : `tokenInBalanceAfter - tokenInBalanceBefore`.

But when calling the `_handleRebalanceIn` function the wrong deposit amount is given as input, as the total balance `tokenInBalanceAfter` is used instead of the received amount `tokenInBalanceAfter - tokenInBalanceBefore`.

Because the `_handleRebalanceIn` function is supposed to deposit the input amount to the destination vault, this error can result in sending a larger amount of funds to DV then what was intended or this error can cause a DOS of the `flashRebalance` function (due to the insufficient amount error when performing the transfer to DV), all of this will make the rebalance operation fail (or not done correctely) which can have a negative impact on the LMPVault.

## Impact

See summary

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/libs/LMPDebt.sol#L185-L215

## Tool used

Manual Review

## Recommendation

Use the correct received tokenIn amount `tokenInBalanceAfter - tokenInBalanceBefore` as input to the `_handleRebalanceIn` function :

```solidity
function flashRebalance(
    DestinationInfo storage destInfoOut,
    DestinationInfo storage destInfoIn,
    IERC3156FlashBorrower receiver,
    IStrategy.RebalanceParams memory params,
    FlashRebalanceParams memory flashParams,
    bytes calldata data
) external returns (uint256 idle, uint256 debt) {
    ...

    // Handle increase (shares coming "In", getting underlying from the swapper and trading for new shares)
    if (params.amountIn > 0) {
        IDestinationVault dvIn = IDestinationVault(params.destinationIn);

        // get "before" counts
        uint256 tokenInBalanceBefore = IERC20(params.tokenIn).balanceOf(address(this));

        // Give control back to the solver so they can make use of the "out" assets
        // and get our "in" asset
        bytes32 flashResult = receiver.onFlashLoan(msg.sender, params.tokenIn, params.amountIn, 0, data);

        // We assume the solver will send us the assets
        uint256 tokenInBalanceAfter = IERC20(params.tokenIn).balanceOf(address(this));

        // Make sure the call was successful and verify we have at least the assets we think
        // we were getting
        if (
            flashResult != keccak256("ERC3156FlashBorrower.onFlashLoan")
                || tokenInBalanceAfter < tokenInBalanceBefore + params.amountIn
        ) {
            revert Errors.FlashLoanFailed(params.tokenIn, params.amountIn);
        }

        if (params.tokenIn != address(flashParams.baseAsset)) {
            // @audit Use `tokenInBalanceAfter - tokenInBalanceBefore` as input
            (uint256 debtDecreaseIn, uint256 debtIncreaseIn) =
                _handleRebalanceIn(destInfoIn, dvIn, params.tokenIn, tokenInBalanceAfter - tokenInBalanceBefore);
            idleDebtChange.debtDecrease += debtDecreaseIn;
            idleDebtChange.debtIncrease += debtIncreaseIn;
        } else {
            idleDebtChange.idleIncrease += tokenInBalanceAfter - tokenInBalanceBefore;
        }
    }
    ...
}
```