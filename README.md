# Issue H-1: ETH deposited by the user may be stolen. 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/1 

## Found by 
0x007, 0x3b, 0xComfyCat, 0xDjango, 0xJuda, 0xSurena, 0xbepresent, 0xdeadbeef, 0xmuxyz, 0xvj, Breeje, Flora, SaharDevep, TangYuanShen, VAD37, asui, berndartmueller, bin2chen, caelumimperium, chaduke, ck, duc, enfrasico, harisnabeel, lemonmon, lodelux, n33k, nobody2018, p0wd3r, pengun, rvierdiiev, saidam017, shogoki, talfao, vagrant, warRoom, xiaoming90
Due to the fact that the WETH obtained through `_processEthIn` belongs to the contract, and `pullToken` transfers assets from `msg.sender`, it is possible for users to transfer excess WETH to the contract, allowing attackers to steal WETH from within the contract using `sweepToken`.

Both `mint` and `deposit` in `LMPVaultRouterBase` have this problem.
## Vulnerability Detail
In the `deposit` function, if the user pays with ETH, it will first call `_processEthIn` to wrap it and then call `pullToken` to transfer.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L43-L57
```solidity
    /// @inheritdoc ILMPVaultRouterBase
    function deposit(
        ILMPVault vault,
        address to,
        uint256 amount,
        uint256 minSharesOut
    ) public payable virtual override returns (uint256 sharesOut) {
        // handle possible eth
        _processEthIn(vault);

        IERC20 vaultAsset = IERC20(vault.asset());
        pullToken(vaultAsset, amount, address(this));

        return _deposit(vault, to, amount, minSharesOut);
    }
```

`_processEthIn` will wrap ETH into WETH, and these WETH belong to the contract itself.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L111-L122
```solidity
    function _processEthIn(ILMPVault vault) internal {
        // if any eth sent, wrap it first
        if (msg.value > 0) {
            // if asset is not weth, revert
            if (address(vault.asset()) != address(weth9)) {
                revert InvalidAsset();
            }

            // wrap eth
            weth9.deposit{ value: msg.value }();
        }
    }
```

However, `pullToken` transfers from `msg.sender` and does not use the WETH obtained in `_processEthIn`.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L54-L56
```solidity
    function pullToken(IERC20 token, uint256 amount, address recipient) public payable {
        token.safeTransferFrom(msg.sender, recipient, amount);
    }
```

If the user deposits 10 ETH and approves 10 WETH to the contract, when the deposit amount is 10, all of the user's 20 WETH will be transferred into the contract.

However, due to the `amount` being 10, only 10 WETH will be deposited into the vault, and the remaining 10 WETH can be stolen by the attacker using `sweepToken`.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L58-L65
```solidity
    function sweepToken(IERC20 token, uint256 amountMinimum, address recipient) public payable {
        uint256 balanceToken = token.balanceOf(address(this));
        if (balanceToken < amountMinimum) revert InsufficientToken();

        if (balanceToken > 0) {
            token.safeTransfer(recipient, balanceToken);
        }
    }
```

Both `mint` and `deposit` in `LMPVaultRouterBase` have this problem.

## Impact
ETH deposited by the user may be stolen.
## Code Snippet
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouterBase.sol#L43-L57
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L54-L56
- https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/utils/PeripheryPayments.sol#L58-L65
## Tool used

Manual Review

## Recommendation
Perform operations based on the size of `msg.value` and `amount`:
1. `msg.value == amount`: transfer WETH from contract not `msg.sender`
2. `msg.value > amount`: transfer WETH from contract not `msg.sender` and refund to `msg.sender`
3. `msg.value < amount`: transfer WETH from contract and transfer remaining from `msg.sender`

# Issue H-2: Destination Vault rewards are not added to idleIncrease when info.totalAssetsPulled > info.totalAssetsToPull 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/5 

## Found by 
0x73696d616f, 0xbepresent, Aymen0909, Ch\_301, Kalyan-Singh, TangYuanShen, berndartmueller, bin2chen, bitsurfer, carrotsmuggler, duc, lemonmon, nobody2018, p0wd3r, pengun, rvierdiiev, saidam017, talfao, warRoom, xiaoming90
Destination Vault rewards are not added to `idleIncrease` when `info.totalAssetsPulled > info.totalAssetsToPull` in `_withdraw` of `LMPVault`.

This result in rewards not being recorded by `LMPVault` and ultimately frozen in the contract.
## Vulnerability Detail
In the `_withdraw` function, Destination Vault rewards will be first recorded in `info.IdleIncrease` by `info.idleIncrease += _baseAsset.balanceOf(address(this)) - assetPreBal - assetPulled;`.

But when `info.totalAssetsPulled > info.totalAssetsToPull`, `info.idleIncrease` is directly assigned as `info.totalAssetsPulled - info.totalAssetsToPull`, and `info.totalAssetsPulled` is `assetPulled` without considering Destination Vault rewards.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L482-L497
```solidity
                uint256 assetPreBal = _baseAsset.balanceOf(address(this));
                uint256 assetPulled = destVault.withdrawBaseAsset(sharesToBurn, address(this));

                // Destination Vault rewards will be transferred to us as part of burning out shares
                // Back into what that amount is and make sure it gets into idle
                info.idleIncrease += _baseAsset.balanceOf(address(this)) - assetPreBal - assetPulled;
                info.totalAssetsPulled += assetPulled;
                info.debtDecrease += totalDebtBurn;

                // It's possible we'll get back more assets than we anticipate from a swap
                // so if we do, throw it in idle and stop processing. You don't get more than we've calculated
                if (info.totalAssetsPulled > info.totalAssetsToPull) {
                    info.idleIncrease = info.totalAssetsPulled - info.totalAssetsToPull;
                    info.totalAssetsPulled = info.totalAssetsToPull;
                    break;
                }
```

For example,
```solidity
                    // preBal == 100 pulled == 10 reward == 5 toPull == 6
                    // idleIncrease = 115 - 100 - 10 == 5
                    // totalPulled(0) += assetPulled == 10 > toPull
                    // idleIncrease = totalPulled - toPull == 4 < reward
```

The final `info.idleIncrease` does not record the reward, and these assets are not ultimately recorded by the Vault.

## Impact
The final `info.idleIncrease` does not record the reward, and these assets are not ultimately recorded by the Vault.

Meanwhile, due to the `recover` function's inability to extract the `baseAsset`, this will result in no operations being able to handle these Destination Vault rewards, ultimately causing these assets to be frozen within the contract.
## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L482-L497
## Tool used

Manual Review

## Recommendation
`info.idleIncrease = info.totalAssetsPulled - info.totalAssetsToPull;` -> `info.idleIncrease += info.totalAssetsPulled - info.totalAssetsToPull;`

# Issue H-3: Liquidations miss delegate call to swapper 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/205 

## Found by 
0x007, 0x3b, 0x73696d616f, 0xDjango, 0xJuda, 0xSurena, 0xTheC0der, 0xbepresent, 0xvj, ADM, Angry\_Mustache\_Man, Ch\_301, Kalyan-Singh, MrjoryStewartBaxter, berndartmueller, bin2chen, duc, lil.eth, lodelux, nobody2018, p0wd3r, pengun, rvierdiiev, saidam017, shaka, talfao, xiaoming90

LiquidationRow acts as an orchestrator of claiming process. It liquidates tokens across vaults using the **liquidateVaultsForToken** function. This function has a flaw and will revert. Swapper contract is called during the function call, but tokens are not transferred to it nor tokens are transferred back from the swapper to the calling contract. Based on other parts of the codebase the problem is that swapper should be invoked with a low-level delegatecall instead of a normal call.

## Vulnerability Detail

The LiquidationRow contract is an orchestrator for the claiming process. It is primarily used to collect rewards for vaults. It has a method called **liquidateVaultsForToken**. Based on docs this method is for: *Conducts the liquidation process for a specific token across a list of vaults, performing the necessary balance adjustments, initiating the swap process via the asyncSwapper, taking a fee from the received amount, and queues the remaining swapped tokens in the MainRewarder associated with each vault.*

```solidity
function liquidateVaultsForToken(
    address fromToken,
    address asyncSwapper,
    IDestinationVault[] memory vaultsToLiquidate,
    SwapParams memory params
) external nonReentrant hasRole(Roles.LIQUIDATOR_ROLE) onlyWhitelistedSwapper(asyncSwapper) {
    uint256 gasBefore = gasleft();

    (uint256 totalBalanceToLiquidate, uint256[] memory vaultsBalances) =
        _prepareForLiquidation(fromToken, vaultsToLiquidate);
    _performLiquidation(
        gasBefore, fromToken, asyncSwapper, vaultsToLiquidate, params, totalBalanceToLiquidate, vaultsBalances
    );
}
```

> [https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L167C5-L180C6](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L167C5-L180C6)

The second part of the function is performing the liquidation by calling **_performLiquidation**. A problem is at the beginning of it. IAsyncSwapper is called to swap tokens.

```solidity
function _performLiquidation(
    uint256 gasBefore,
    address fromToken,
    address asyncSwapper,
    IDestinationVault[] memory vaultsToLiquidate,
    SwapParams memory params,
    uint256 totalBalanceToLiquidate,
    uint256[] memory vaultsBalances
) private {
    uint256 length = vaultsToLiquidate.length;
    // the swapper checks that the amount received is greater or equal than the params.buyAmount
    uint256 amountReceived = IAsyncSwapper(asyncSwapper).swap(params);
    // ...
}
```

> [https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L251C8-L251C75](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L251C8-L251C75)

As you can see the LiquidationRow doesn't transfer the tokens to swapper and swapper doesn't pul them either ([swap function here](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/BaseAsyncSwapper.sol#L19C5-L64C6)). Because of this the function reverses.

I noticed that there is no transfer back to LiquidationRow from Swapper either. Tokens can't get in or out.

When I searched the codebase, I found that Swapper is being called on another place using the delegatecall method. This way it can operate with the tokens of the caller. The call can be found here - [LMPVaultRouter.sol:swapAndDepositToVault](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouter.sol#L53C8-L55C11). So I think that instead of missing transfer, the problem is actually in the way how swapper is called.

## Impact

Rewards collected through LiquidationRow **claimsVaultRewards** get stuck in the contract. Liquidation can't be called because it reverts when Swapper tries to work with tokens it doesn't possess.

## Code Snippet

[https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L167C5-L180C6](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L167C5-L180C6)

[https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L251C8-L251C75](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/LiquidationRow.sol#L251C8-L251C75)

[https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/BaseAsyncSwapper.sol#L19C5-L64C6](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/liquidation/BaseAsyncSwapper.sol#L19C5-L64C6)

[https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouter.sol#L53C8-L55C11](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVaultRouter.sol#L53C8-L55C11)

## Tool used

Manual Review

## Recommendation

Change the async swapper call from the normal function call to the low-level delegatecall function the same way it is done in LMPVaultRouter.sol:swapAndDepositToVault.

I would like to address that AsyncSwapperMock in LiquidationRow.t.sol is a poorly written mock and should be updated to represent how the AsyncSwapper work. It would be nice to update the test suite for LiquidationRow because its current state won't catch this. If you check the LiquidationRow.t.sol tests, the mock swap function only mints tokens, no need to use delegatecall. This is why tests missed this vulnerability.

# Issue H-4: When `queueNewRewards` is called, caller could transfer tokens more than it should be 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/379 

## Found by 
0xVolodya, 0xbepresent, 0xvj, 1nc0gn170, Angry\_Mustache\_Man, Aymen0909, BPZ, Kalyan-Singh, berndartmueller, bin2chen, bitsurfer, bulej93, caelumimperium, chaduke, duc, l3r0ux, lemonmon, lil.eth, p0wd3r, pengun, saidam017, shaka, wangxx2026, xiaoming90

`queueNewRewards` is used for Queues the specified amount of new rewards for distribution to stakers. However, it used wrong calculated value when pulling token funds from the caller, could make caller transfer tokens more that it should be.

## Vulnerability Detail

Inside `queueNewRewards`, irrespective of whether we're near the start or the end of a reward period, if the accrued rewards are too large relative to the new rewards (`queuedRatio` is greater than `newRewardRatio`), the new rewards will be added to the queue (`queuedRewards`) rather than being immediately distributed.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L235-L261

```solidity
    function queueNewRewards(uint256 newRewards) external onlyWhitelisted {
        uint256 startingQueuedRewards = queuedRewards;
        uint256 startingNewRewards = newRewards;

        newRewards += startingQueuedRewards;

        if (block.number >= periodInBlockFinish) {
            notifyRewardAmount(newRewards);
            queuedRewards = 0;
        } else {
            uint256 elapsedBlock = block.number - (periodInBlockFinish - durationInBlock);
            uint256 currentAtNow = rewardRate * elapsedBlock;
            uint256 queuedRatio = currentAtNow * 1000 / newRewards;

            if (queuedRatio < newRewardRatio) {
                notifyRewardAmount(newRewards);
                queuedRewards = 0;
            } else {
                queuedRewards = newRewards;
            }
        }

        emit QueuedRewardsUpdated(startingQueuedRewards, startingNewRewards, queuedRewards);

        // Transfer the new rewards from the caller to this contract.
        IERC20(rewardToken).safeTransferFrom(msg.sender, address(this), newRewards);
    }
```

However, when this function tried to pull funds from sender via `safeTransferFrom`, it used `newRewards` amount, which already added  by `startingQueuedRewards`. If previously `queuedRewards` already have value, the processed amount will be wrong.


## Impact

There are two possible issue here : 

1. If previously `queuedRewards` is not 0, and the caller don't have enough funds or approval, the call will revert due to this logic error.
2. If previously `queuedRewards` is not 0,  and the caller have enough funds and approval, the caller funds will be pulled more than it should (reward param + `queuedRewards` )

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L236-L239
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L260

## Tool used

Manual Review

## Recommendation

Update the transfer to use `startingNewRewards` instead of `newRewards`  : 

```diff
    function queueNewRewards(uint256 newRewards) external onlyWhitelisted {
        uint256 startingQueuedRewards = queuedRewards;
        uint256 startingNewRewards = newRewards;

        newRewards += startingQueuedRewards;

        if (block.number >= periodInBlockFinish) {
            notifyRewardAmount(newRewards);
            queuedRewards = 0;
        } else {
            uint256 elapsedBlock = block.number - (periodInBlockFinish - durationInBlock);
            uint256 currentAtNow = rewardRate * elapsedBlock;
            uint256 queuedRatio = currentAtNow * 1000 / newRewards;

            if (queuedRatio < newRewardRatio) {
                notifyRewardAmount(newRewards);
                queuedRewards = 0;
            } else {
                queuedRewards = newRewards;
            }
        }

        emit QueuedRewardsUpdated(startingQueuedRewards, startingNewRewards, queuedRewards);

        // Transfer the new rewards from the caller to this contract.
-        IERC20(rewardToken).safeTransferFrom(msg.sender, address(this), newRewards);
+        IERC20(rewardToken).safeTransferFrom(msg.sender, address(this), startingNewRewards);
    }
```

# Issue H-5: Curve V2 Vaults can be drained because CurveV2CryptoEthOracle can be reentered with WETH tokens 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/481 

## Found by 
0x007, 0xVolodya, Kalyan-Singh
CurveV2CryptoEthOracle assumes that Curve pools that could be reentered must have `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` token. But this is a wrong assumption cause tokens with WETH token could be reentered too.

## Vulnerability Detail
`CurveV2CryptoEthOracle.registerPool` takes `checkReentrancy` parameters and this should be True only for pools that have `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` tokens and this is validated [here](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L122).
```solidity
address public constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

...

// Only need ability to check for read-only reentrancy for pools containing native Eth.
if (checkReentrancy) {
    if (tokens[0] != ETH && tokens[1] != ETH) revert MustHaveEthForReentrancy();
}
```

This Oracle is meant for Curve V2 pools and the ones I've seen so far use WETH address instead of `0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE` (like Curve V1) and this applies to all pools listed by Tokemak. 

For illustration, I'll use the same pool used to [test proper registration](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/test/oracles/providers/CurveV2CryptoEthOracle.t.sol#L126-L136). The test is for `CRV_ETH_CURVE_V2_POOL` but this applies to other V2 pools including [rETH/ETH](https://etherscan.io/address/0x0f3159811670c117c372428d4e69ac32325e4d0f). The pool address for `CRV_ETH_CURVE_V2_POOL` is [0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511](https://etherscan.io/address/0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511#code) while token address is [0xEd4064f376cB8d68F770FB1Ff088a3d0F3FF5c4d](https://etherscan.io/address/0xEd4064f376cB8d68F770FB1Ff088a3d0F3FF5c4d).

If you interact with the pool, the coins are:
0 - WETH - 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
1 - CRV - 0xD533a949740bb3306d119CC777fa900bA034cd52

**So how can WETH be reentered?!**
Because Curve can accept ETH for WETH pools.

A look at the [pool](https://etherscan.io/address/0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511#code) again shows that Curve uses python kwargs and it includes a variable `use_eth` for `exchange`, `add_liquidity`, `remove_liquidity` and `remove_liquidity_one_coin`. 

```vyper
def exchange(i: uint256, j: uint256, dx: uint256, min_dy: uint256, use_eth: bool = False) -> uint256:
def add_liquidity(amounts: uint256[N_COINS], min_mint_amount: uint256, use_eth: bool = False) -> uint256:
def remove_liquidity(_amount: uint256, min_amounts: uint256[N_COINS], use_eth: bool = False):
def remove_liquidity_one_coin(token_amount: uint256, i: uint256, min_amount: uint256, use_eth: bool = False) -> uint256:
```

When `use_eth` is `true`, it would take `msg.value` instead of transfer WETH from user. And it would make a raw call instead of transfer WETH to user.

If raw call is sent to user, then they could reenter LMP vault and attack the protocol and it would be successful cause CurveV2CryptoEthOracle would not check for reentrancy in [getPriceInEth](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L160-L163)

```solidity
// Checking for read only reentrancy scenario.
if (poolInfo.checkReentrancy == 1) {
    // This will fail in a reentrancy situation.
    cryptoPool.claim_admin_fees();
}
```

A profitable attack that could be used to drain the vault involves
* Deposit shares at fair price
* Remove liquidity on Curve and updateDebtReporting in LMPVault with view only reentrancy
* Withdraw shares at unfair price

## Impact
The protocol could be attacked with price manipulation using Curve read only reentrancy. The consequence would be fatal because `getPriceInEth` is used for evaluating debtValue and this evaluation decides shares and debt that would be burned in a withdrawal. Therefore, an inflated value allows attacker to withdraw too many asset for their shares. This could be abused to drain assets on LMPVault.

The attack is cheap, easy and could be bundled in as a flashloan attack. And it puts the whole protocol at risk cause a large portion of their deposit would be on Curve V2 pools with WETH token.

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L121-L123
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L160-L163
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/test/oracles/providers/CurveV2CryptoEthOracle.t.sol#L126-L136
https://etherscan.io/address/0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511#code

## Tool used

Manual Review

## Recommendation
If CurveV2CryptoEthOracle is meant for CurveV2 pools with WETH (and no 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE), then change the ETH address to weth. As far as I can tell Curve V2 uses WETH address for ETH but this needs to be verified.

```solidity
-   if (tokens[0] != ETH && tokens[1] != ETH) revert MustHaveEthForReentrancy();
+   if (tokens[0] != WETH && tokens[1] != WETH) revert MustHaveEthForReentrancy();
```

# Issue H-6: updateDebtReporting can be front run, putting all the loss on later withdrawals but taking the profit 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/531 

## Found by 
Kalyan-Singh, berndartmueller, lemonmon
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

# Issue H-7: Inflated price due to unnecessary precision scaling 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/600 

## Found by 
0xVolodya, Aymen0909, bin2chen, enfrasico, nobody2018, saidam017, talfao, xiaoming90

The price returned by the stat calculators will be excessively inflated, which could lead to multiple implications that lead to losses to the protocol.

## Vulnerability Detail

The `price` at Line 137 below is denominated in 18 decimals as the `getPriceInEth` function always returns the price in 18 decimals precision.

There is no need to scale the accumulated price by 1e18.

- It will cause the average price (`existing._initAcc`) to be inflated significantly
- The numerator will almost always be larger than the denominator (INIT_SAMPLE_COUNT = 18). There is no risk of it rounding to zero, so any scaling is unnecessary.

Assume that throughout the initialization process, the `getPriceInEth(XYZ)` always returns 2 ETH (2e18). After 18 rounds (`INIT_SAMPLE_COUNT == 18`) of initialization, `existing._initAcc` will equal 36 ETH (36e18). As such, the `averagePrice` will be as follows:

```solidity
averagePrice = existing._initAcc * 1e18 / INIT_SAMPLE_COUNT;
averagePrice = 36e18 * 1e18 / 18
averagePrice = 36e36 / 18
averagePrice = 2e36
```

`existing.fastFilterPrice` and `existing.slowFilterPrice` will be set to `2e36` at Lines 157 and 158 below.

In the post-init phase, the `getPriceInEth` function return 3 ETH (3e18). Thus, the following code will be executed at Line 144s and 155 below:

```solidity
existing.slowFilterPrice = Stats.getFilteredValue(SLOW_ALPHA, existing.slowFilterPrice, price);
existing.fastFilterPrice = Stats.getFilteredValue(FAST_ALPHA, existing.fastFilterPrice, price);

existing.slowFilterPrice = Stats.getFilteredValue(SLOW_ALPHA, 2e36, 3e18); // SLOW_ALPHA = 645e14; // 0.0645
existing.fastFilterPrice = Stats.getFilteredValue(FAST_ALPHA, 2e36, 3e18); // FAST_ALPHA = 33e16; // 0.33
```

As shown above, the existing filter prices are significantly inflated by the scale of 1e18, which results in the prices being extremely skewed.

Using the formula of fast filter, the final fast filter price computed will be as follows:

```solidity
((priorValue * (1e18 - alpha)) + (currentValue * alpha)) / 1e18
((priorValue * (1e18 - 33e16)) + (currentValue * 33e16)) / 1e18
((priorValue * 67e16) + (currentValue * 33e16)) / 1e18
((2e36 * 67e16) + (3e18 * 33e16)) / 1e18
1.34e36 (1340000000000000000 ETH)
```

The token is supposed only to be worth around 3 ETH. However, the fast filter price wrongly determine that it is worth around 1340000000000000000 ETH

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/stats/calculators/IncentivePricingStats.sol#L125

```solidity
File: IncentivePricingStats.sol
125:     function updatePricingInfo(IRootPriceOracle pricer, address token) internal {
..SNIP..
137:         uint256 price = pricer.getPriceInEth(token);
138: 
139:         // update the timestamp no matter what phase we're in
140:         existing.lastSnapshot = uint40(block.timestamp);
141: 
142:         if (existing._initComplete) {
143:             // post-init phase, just update the filter values
144:             existing.slowFilterPrice = Stats.getFilteredValue(SLOW_ALPHA, existing.slowFilterPrice, price);
145:             existing.fastFilterPrice = Stats.getFilteredValue(FAST_ALPHA, existing.fastFilterPrice, price);
146:         } else {
147:             // still the initialization phase
148:             existing._initCount += 1;
149:             existing._initAcc += price;
150: 
151:             // snapshot count is tracked internally and cannot be manipulated
152:             // slither-disable-next-line incorrect-equality
153:             if (existing._initCount == INIT_SAMPLE_COUNT) { // @audit-info INIT_SAMPLE_COUNT = 18;
154:                 // if this sample hits the target number, then complete initialize and set the filters
155:                 existing._initComplete = true;
156:                 uint256 averagePrice = existing._initAcc * 1e18 / INIT_SAMPLE_COUNT;
157:                 existing.fastFilterPrice = averagePrice;
158:                 existing.slowFilterPrice = averagePrice;
159:             }
160:         }
```

## Impact

The price returned by the stat calculators will be excessively inflated. The purpose of the stats/calculators contracts is to store, augment, and clean data relevant to the LMPs. When the solver proposes a rebalance, the strategy uses the stats contracts to calculate a composite return (score) for the proposed destinations. Using that composite return, it determines if the swap is beneficial for the vault.

If a stat calculator provides incorrect and inflated pricing, it can cause multiple implications that lead to losses to the protocol, such as false signals allowing the unprofitable rebalance to be executed.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/stats/calculators/IncentivePricingStats.sol#L125

## Tool used

Manual Review

## Recommendation

Remove the 1e18 scaling.

```diff
if (existing._initCount == INIT_SAMPLE_COUNT) {
    // if this sample hits the target number, then complete initialize and set the filters
    existing._initComplete = true;
-    uint256 averagePrice = existing._initAcc * 1e18 / INIT_SAMPLE_COUNT;
+    uint256 averagePrice = existing._initAcc / INIT_SAMPLE_COUNT;
    existing.fastFilterPrice = averagePrice;
    existing.slowFilterPrice = averagePrice;
}
```

# Issue H-8: Immediately start getting rewards belonging to others after staking 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/603 

## Found by 
0x73696d616f, 0xGoodess, 0xJuda, 0xTheC0der, 0xdeadbeef, 0xvj, Ch\_301, Kalyan-Singh, MrjoryStewartBaxter, VAD37, berndartmueller, bin2chen, caelumimperium, carrotsmuggler, jecikpo, l3r0ux, lemonmon, pengun, saidam017, talfao, wangxx2026, xiaoming90

Malicious users could abuse the accounting error to immediately start getting rewards belonging to others after staking, leading to a loss of reward tokens.

## Vulnerability Detail

> **Note**
> This issue affects both LMPVault and DV since they use the same underlying reward contract.

Assume a new user called Bob mints 100 LMPVault or DV shares. The ERC20's `_mint` function will be called, which will first increase Bob's balance at Line 267 and then trigger the `_afterTokenTransfer` hook at Line 271.

https://github.com/OpenZeppelin/openzeppelin-contracts/blob/0457042d93d9dfd760dbaa06a4d2f1216fdbe297/contracts/token/ERC20/ERC20.sol#L259

```solidity
File: ERC20.sol
259:     function _mint(address account, uint256 amount) internal virtual {
..SNIP..
262:         _beforeTokenTransfer(address(0), account, amount);
263: 
264:         _totalSupply += amount;
265:         unchecked {
266:             // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.
267:             _balances[account] += amount;
268:         }
..SNIP..
271:         _afterTokenTransfer(address(0), account, amount);
272:     }
```

The `_afterTokenTransfer` hook will automatically stake the newly minted shares to the rewarder contracts on behalf of Bob.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L854

```solidity
File: LMPVault.sol
854:     function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual override {
..SNIP..
862:         if (to != address(0)) {
863:             rewarder.stake(to, amount);
864:         }
865:     }
```

Within the `MainRewarder.stake` function, it will first call the `_updateReward` function at Line 87 to take a snapshot of accumulated rewards. Since Bob is a new user, his accumulated rewards should be zero. However, this turned out to be false due to the bug described in this report.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/MainRewarder.sol#L86

```solidity
File: MainRewarder.sol
86:     function stake(address account, uint256 amount) public onlyStakeTracker {
87:         _updateReward(account);
88:         _stake(account, amount);
89: 
90:         for (uint256 i = 0; i < extraRewards.length; ++i) {
91:             IExtraRewarder(extraRewards[i]).stake(account, amount);
92:         }
93:     }
```

When the `_updateReward` function is executed, it will compute Bob's earned rewards.  It is important to note that at this point, Bob's balance has already been updated to 100 shares in the `stakeTracker` contract, and `userRewardPerTokenPaid[Bob]` is zero.

Bob's earned reward will be as follows, where $r$ is the `rewardPerToken()`:

$$
earned(Bob) = 100\ {shares \times (r - 0)} = 100r
$$

Bob immediately accumulated a reward of $100r$ upon staking into the rewarder contract, which is incorrect. Bob could withdraw $100r$ reward tokens that do not belong to him.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L128

```solidity
File: AbstractRewarder.sol
128:     function _updateReward(address account) internal {
129:         uint256 earnedRewards = 0;
130:         rewardPerTokenStored = rewardPerToken();
131:         lastUpdateBlock = lastBlockRewardApplicable();
132: 
133:         if (account != address(0)) {
134:             earnedRewards = earned(account);
135:             rewards[account] = earnedRewards;
136:             userRewardPerTokenPaid[account] = rewardPerTokenStored;
137:         }
138: 
139:         emit UserRewardUpdated(account, earnedRewards, rewardPerTokenStored, lastUpdateBlock);
140:     }
..SNIP..
155:     function balanceOf(address account) public view returns (uint256) {
156:         return stakeTracker.balanceOf(account);
157:     }
..SNIP..
204:     function earned(address account) public view returns (uint256) {
205:         return (balanceOf(account) * (rewardPerToken() - userRewardPerTokenPaid[account]) / 1e18) + rewards[account];
206:     }
```

## Impact

Loss of reward tokens for the vault shareholders.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L854

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/MainRewarder.sol#L86

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L128

## Tool used

Manual Review

## Recommendation

Ensure that the balance of the users in the rewarder contract is only incremented after the `_updateReward` function is executed.

One option is to track the balance of the staker and total supply internally within the rewarder contract and avoid reading the states in the `stakeTracker` contract, commonly seen in many reward contracts.

```diff
File: AbstractRewarder.sol
function balanceOf(address account) public view returns (uint256) {
-   return stakeTracker.balanceOf(account);
+	return _balances[account];
}
```

```diff
File: AbstractRewarder.sol
function _stake(address account, uint256 amount) internal {
    Errors.verifyNotZero(account, "account");
    Errors.verifyNotZero(amount, "amount");
    
+    _totalSupply += amount
+    _balances[account] += amount

    emit Staked(account, amount);
}
```

# Issue H-9: Differences between actual and cached total assets can be arbitraged 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/611 

## Found by 
0x007, 0xWeiss, Ch\_301, Flora, Kalyan-Singh, caelumimperium, lemonmon, n33k, xiaoming90

The difference between $totalAssets_{cached}$ and $totalAssets_{actual}$ could be arbitraged or exploited by malicious users for their gain, leading to a loss to other vault shareholders.

## Vulnerability Detail

The actual total amount of assets that are owned by a LMPVault on-chain can be derived via the following formula:

$$
totalAssets_{actual} = \sum_{n=1}^{x}debtValue(DV_n)
$$

When `LMPVault.totalAssets()` function is called, it returns the cached total assets of the LMPVault instead.

$$
totalAssets_{cached} = totalIdle + totalDebt
$$

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L304

```solidity
File: LMPVault.sol
304:     function totalAssets() public view override returns (uint256) {
305:         return totalIdle + totalDebt;
306:     }
```

Thus, the $totalAssets_{cached}$ will deviate from $totalAssets_{actual}$. This difference could be arbitraged or exploited by malicious users for their gain.

Certain actions such as `previewDeposit`, `previewMint`, `previewWithdraw,` and `previewRedeem` functions rely on the $totalAssets_{cached}$ value while other actions such as `_withdraw` and `_calcUserWithdrawSharesToBurn` functions rely on $totalAssets_{actual}$ value.

The following shows one example of the issue.

The `previewDeposit(assets)` function computed the number of shares to be received after depositing a specific amount of assets:

$$
shareReceived = \frac{assets_{deposited}}{totalAssets_{cached}} \times totalSupply
$$

Assume that $totalAssets_{cached} < totalAssets_{actual}$, and the values of the variables are as follows:

- $totalAssets_{cached}$ = 110 WETH
- $totalAssets_{actual}$ = 115 WETH
- $totalSupply$ = 100 shares

Assume Bob deposited 10 WETH when the total assets are 110 WETH (when $totalAssets_{cached} < totalAssets_{actual}$), he would receive:

$$
\begin{align}
shareReceived &= \frac{10 ETH}{110 ETH} \times 100e18\ shares \\
&= 9.090909091e18\ shares
\end{align}
$$

If a user deposited 10 WETH while the total assets are updated to the actual worth of 115 WETH (when $totalAssets_{cached} == totalAssets_{actual}$, they would receive:

$$
\begin{align}
shareReceived &= \frac{10 ETH}{115 ETH} \times 100e18\ shares \\
&= 8.695652174e18\ shares \\
\end{align}
$$

Therefore, Bob is receiving more shares than expected.

If Bob redeems all his nine (9) shares after the $totalAssets_{cached}$ has been updated to $totalAssets_{actual}$, he will receive 10.417 WETH back.

$$
\begin{align}
assetsReceived &= \frac{9.090909091e18\ shares}{(100e18 + 9.090909091e18)\ shares} \times (115 + 10)\ ETH \\
&= \frac{9.090909091e18\ shares}{109.090909091e18\ shares} \times 125 ETH \\
&= 10.41666667\ ETH
\end{align}
$$

Bob profits 0.417 WETH simply by arbitraging the difference between the cached and actual values of the total assets. Bob gains is the loss of other vault shareholders.

The $totalAssets_{cached}$ can be updated to $totalAssets_{actual}$ by calling the permissionless `LMPVault.updateDebtReporting` function. Alternatively, one could also perform a sandwich attack against the `LMPVault.updateDebtReporting` function by front-run it to take advantage of the lower-than-expected price or NAV/share, and back-run it to sell the shares when the price or NAV/share rises after the update.

One could also reverse the attack order, where an attacker withdraws at a higher-than-expected price or NAV/share, perform an update on the total assets, and deposit at a lower price or NAV/share.

## Impact

Loss assets for vault shareholders. Attacker gains are the loss of other vault shareholders.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L304

## Tool used

Manual Review

## Recommendation

Consider updating $totalAssets_{cached}$ to $totalAssets_{actual}$ before any withdrawal or deposit to mitigate this issue.

# Issue H-10: Gain From LMPVault Can Be Stolen 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/620 

## Found by 
0x007, 0xvj, Ch\_301, Flora, TangYuanShen, berndartmueller, saidam017, xiaoming90

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

# Issue H-11: Incorrect pricing for CurveV2 LP Token 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/621 

## Found by 
xiaoming90

The price of the CurveV2 LP Tokens is incorrect as the incorrect quote currency is being used when computing the value, resulting in a loss of assets due to the overvaluing or undervaluing of the assets.

## Vulnerability Detail

Using the Curve rETH/frxETH pool (0xe7c6e0a739021cdba7aac21b4b728779eef974d9) to illustrate the issue:

The price of the LP token of Curve rETH/frxETH pool can be obtained via the following `lp_price` function:

https://etherscan.io/address/0xe7c6e0a739021cdba7aac21b4b728779eef974d9#code#L1308

```python
def lp_price() -> uint256:
    """
    Approximate LP token price
    """
    return 2 * self.virtual_price * self.sqrt_int(self.internal_price_oracle()) / 10**18
```

Thus, the formula to obtain the price of the LP token is as follows:

$$
price_{LP} = 2 \times virtualPrice \times \sqrt{internalPriceOracle}
$$

Information about the $internalPriceOracle$ can be obtained from the `pool.price_oracle()` function or from the Curve's Pool page (https://curve.fi/#/ethereum/pools/factory-crypto-218/swap). Refer to the Price Data's Price Oracle section.

https://etherscan.io/address/0xe7c6e0a739021cdba7aac21b4b728779eef974d9#code#L1341

```python
def price_oracle() -> uint256:
    return self.internal_price_oracle()
```

The $internalPriceOracle$ is the price of `coins[1]`(frxETH) with `coins[0]`(rETH) as the quote currency, which means how many rETH (quote) are needed to purchase one frxETH (base).

$$
base/quote \\
frxETH/rETH
$$

During pool registration, the `poolInfo.tokenToPrice` is always set to the second coin (`coins[1]`) as per Line 131 below. In this example, `poolInfo.tokenToPrice` will be set to frxETH token address (`coins[1]`).

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L107

```solidity
File: CurveV2CryptoEthOracle.sol
107:     function registerPool(address curvePool, address curveLpToken, bool checkReentrancy) external onlyOwner {
..SNIP..
125:         /**
126:          * Curve V2 pools always price second token in `coins` array in first token in `coins` array.  This means that
127:          *    if `coins[0]` is Weth, and `coins[1]` is rEth, the price will be rEth as base and weth as quote.  Hence
128:          *    to get lp price we will always want to use the second token in the array, priced in eth.
129:          */
130:         lpTokenToPool[lpToken] =
131:             PoolData({ pool: curvePool, checkReentrancy: checkReentrancy ? 1 : 0, tokenToPrice: tokens[1] });
```

Note that `assetPrice` variable below is equivalent to $internalPriceOracle$ in the above formula.

When fetching the price of the LP token, Line 166 computes the price of frxETH with ETH as the quote currency ($frxETH/ETH$) via the `getPriceInEth` function, and assigns to the `assetPrice` variable.

However, the $internalPriceOracle$ or `assetPrice` should be $frxETH/rETH$ instead of $frxETH/ETH$. Thus, the price of the LP token computed will be incorrect.

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L151

```solidity
File: CurveV2CryptoEthOracle.sol
151:     function getPriceInEth(address token) external returns (uint256 price) {
152:         Errors.verifyNotZero(token, "token");
153: 
154:         PoolData memory poolInfo = lpTokenToPool[token];
155:         if (poolInfo.pool == address(0)) revert NotRegistered(token);
156: 
157:         ICryptoSwapPool cryptoPool = ICryptoSwapPool(poolInfo.pool);
158: 
159:         // Checking for read only reentrancy scenario.
160:         if (poolInfo.checkReentrancy == 1) {
161:             // This will fail in a reentrancy situation.
162:             cryptoPool.claim_admin_fees();
163:         }
164: 
165:         uint256 virtualPrice = cryptoPool.get_virtual_price();
166:         uint256 assetPrice = systemRegistry.rootPriceOracle().getPriceInEth(poolInfo.tokenToPrice);
167: 
168:         return (2 * virtualPrice * sqrt(assetPrice)) / 10 ** 18;
169:     }
```

## Impact

The protocol relies on the oracle to provide accurate pricing for many critical operations, such as determining the debt values of DV, calculators/stats used during the rebalancing process, NAV/shares of the LMPVault, and determining how much assets the users should receive during withdrawal. 

Incorrect pricing of LP tokens would result in many implications that lead to a loss of assets, such as users withdrawing more or fewer assets than expected due to over/undervalued vaults or strategy allowing an unprofitable rebalance to be executed.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/CurveV2CryptoEthOracle.sol#L151

## Tool used

Manual Review

## Recommendation

Update the `getPriceInEth` function to ensure that the $internalPriceOracle$ or `assetPrice` return the price of `coins[1]` with `coins[0]` as the quote currency.

# Issue H-12: Incorrect number of shares minted as fee 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/624 

## Found by 
0x007, xiaoming90

An incorrect number of shares was minted as fees during fee collection, resulting in a loss of fee.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L818

```solidity
File: LMPVault.sol
818:             profit = (currentNavPerShare - effectiveNavPerShareHighMark) * totalSupply;
819:             fees = profit.mulDiv(performanceFeeBps, (MAX_FEE_BPS ** 2), Math.Rounding.Up);
820:             if (fees > 0 && sink != address(0)) {
821:                 // Calculated separate from other mints as normal share mint is round down
822:                 shares = _convertToShares(fees, Math.Rounding.Up);
823:                 _mint(sink, shares);
824:                 emit Deposit(address(this), sink, fees, shares);
825:             }
```

Assume that the following states:

- The `profit` is 100 WETH
- The fee is 20%, so the `fees` will be 20 WETH.
- `totalSupply` is 100 shares and `totalAssets()` is 1000 WETH

Let the number of shares to be minted be $shares2mint$. The current implementation uses the following formula (simplified) to determine $shares2mint$.

$$
\begin{align}
shares2mint &= fees \times \frac{totalSupply}{totalAsset()} \\
&= 20\ WETH \times \frac{100\ shares}{1000\ WETH} \\
&= 2\ shares
\end{align}
$$

In this case, two (2) shares will be minted to the `sink` address as the fee is taken.

However, the above formula used in the codebase is incorrect. The total cost/value of the newly-minted shares does not correspond to the fee taken. Immediately after the mint, the value of the two (2) shares is worth only 19.60 WETH, which does not correspond to the 20 WETH fee that the `sink` address is entitled to.

$$
\begin{align}
value &= 2\ shares \times \frac{1000\ WETH}{100 + 2\ shares} \\
&= 2\ shares \times 9.8039\ WETH\\
&= 19.6078\ WETH
\end{align}
$$

## Impact

Loss of fee. Fee collection is an integral part of the protocol; thus the loss of fee is considered a High issue.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L818

## Tool used

Manual Review

## Recommendation

The correct formula to compute the number of shares minted as fee should be as follows: 

$$
\begin{align}
shares2mint &= \frac{profit \times performanceFeeBps \times totalSupply}{(totalAsset() \times MAX\_FEE\_BPS) - (performanceFeeBps \times profit) } \\
&= \frac{100\epsilon \times 2000 \times 100 shares}{(1000\epsilon \times 10000) - (2000 \times 100\epsilon)} \\
&= 2.0408163265306122448979591836735\ shares
\end{align}
$$

The above formula is the same as the one LIDO used (https://docs.lido.fi/guides/steth-integration-guide/#fees)

The following is the proof to show that `2.0408163265306122448979591836735` shares are worth 20 WETH after the mint.

$$
\begin{align}
value &= 2.0408163265306122448979591836735\ shares \times \frac{1000\ WETH}{100 + 2.0408163265306122448979591836735\ shares} \\
&= 2.0408163265306122448979591836735\ shares \times 9.8039\ WETH\\
&= 20\ WETH
\end{align}
$$

# Issue H-13: Maverick oracle can be manipulated 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/635 

## Found by 
Bauchibred, ctf\_sec, duc, lemonmon, rvierdiiev, saidam017, xiaoming90
The MavEthOracle.getPriceInEth() function uses the reserves of the Maverick pool to calculate the price of Maverick LP tokens. These reserves can be manipulated, which can lead to incorrect results of Maverick oracle.
## Vulnerability Detail
In the MavEthOracle contract, `getPriceInEth` function utilizes the reserves of the Maverick pool and multiplies them with the external prices of the tokens (obtained from the rootPriceOracle contract) to calculate the total value of the Maverick position.
```solidity=
// Get reserves in boosted position.
(uint256 reserveTokenA, uint256 reserveTokenB) = boostedPosition.getReserves();

// Get total supply of lp tokens from boosted position.
uint256 boostedPositionTotalSupply = boostedPosition.totalSupply();

IRootPriceOracle rootPriceOracle = systemRegistry.rootPriceOracle();

// Price pool tokens.
uint256 priceInEthTokenA = rootPriceOracle.getPriceInEth(address(pool.tokenA()));
uint256 priceInEthTokenB = rootPriceOracle.getPriceInEth(address(pool.tokenB()));

// Calculate total value of each token in boosted position.
uint256 totalBoostedPositionValueTokenA = reserveTokenA * priceInEthTokenA;
uint256 totalBoostedPositionValueTokenB = reserveTokenB * priceInEthTokenB;

// Return price of lp token in boosted position.
return (totalBoostedPositionValueTokenA + totalBoostedPositionValueTokenB) / boostedPositionTotalSupply;
```
However, the reserves of a Maverick position can fluctuate when the price of the Maverick pool changes. Therefore, the returned price of this function can be manipulated by swapping a significant amount of tokens into the Maverick pool. An attacker can utilize a flash loan to initiate a swap, thereby changing the price either upwards or downwards, and subsequently swapping back to repay the flash loan.

Attacker can decrease the returned price of MavEthOracle by swapping a large amount of the higher value token for the lower value token, and vice versa.

Here is a test file that demonstrates how the price of the MavEthOracle contract can be manipulated by swapping to change the reserves.

```solidity=
pragma solidity 0.8.17;

import { Test } from "forge-std/Test.sol";
import 'forge-std/console.sol';

import { WETH9_ADDRESS, TOKE_MAINNET, WSTETH_MAINNET } from "test/utils/Addresses.sol";

import { IPool } from "src/interfaces/external/maverick/IPool.sol";
import { MavEthOracle } from "src/oracles/providers/MavEthOracle.sol";
import { SystemRegistry, ISystemRegistry } from "src/SystemRegistry.sol";
import { RootPriceOracle } from "src/oracles/RootPriceOracle.sol";
import { AccessController, IAccessController } from "src/security/AccessController.sol";
import { IPriceOracle } from "src/interfaces/oracles/IPriceOracle.sol";
import { SwEthEthOracle} from "src/oracles/providers/SwEthEthOracle.sol";
import { EthPeggedOracle} from "src/oracles/providers/EthPeggedOracle.sol";
import { IswETH } from "src/interfaces/external/swell/IswETH.sol";
import { IPoolPositionDynamicSlim } from "src/interfaces/external/maverick/IPoolPositionDynamicSlim.sol";
import { IERC20 } from "openzeppelin-contracts/token/ERC20/IERC20.sol";

contract NewTest is Test {
  SystemRegistry public registry;
  AccessController public accessControl;
  RootPriceOracle public rootOracle;
  MavEthOracle public mavOracle;

  function setUp() external {
    vm.createSelectFork("https://rpc.ankr.com/eth", 17224221);
    registry = new SystemRegistry(TOKE_MAINNET, WETH9_ADDRESS);
    accessControl = new AccessController(address(registry));
    registry.setAccessController(address(accessControl));
    rootOracle = new RootPriceOracle(registry);
    registry.setRootPriceOracle(address(rootOracle));
    mavOracle = new MavEthOracle(registry);
  }

  function swapCallback(
    uint256 amountToPay,
    uint256 amountOut,
    bytes calldata _data
  ) external {
    address tokenIn = abi.decode(_data, (address));
    IERC20(tokenIn).transfer(msg.sender, amountToPay);
  }

  function test_MaverickOracleManipulation() external {
    IswETH swETH = IswETH(0xf951E335afb289353dc249e82926178EaC7DEd78);
    address weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address boostedPosition = 0xF917FE742C530Bd66BcEbf64B42c777B13aac92c;
    SwEthEthOracle swEthOracle = new SwEthEthOracle(registry, swETH);
    EthPeggedOracle ethOracle = new EthPeggedOracle(registry);
    rootOracle.registerMapping(address(swETH), swEthOracle);
    rootOracle.registerMapping(weth, ethOracle);

    (uint256 reserveA, uint256 reserveB) = IPoolPositionDynamicSlim(boostedPosition).getReserves();
    console.log("reserves", reserveA, reserveB);
    uint256 mavPriceBefore = mavOracle.getPriceInEth(boostedPosition);
    console.log("mavOracle price before", mavPriceBefore);

    //swap
    deal(address(swETH), address(this), 1e24);
    address pool = IPoolPositionDynamicSlim(boostedPosition).pool();
    IPool(pool).swap(
        address(this),
        1e18,
        false,
        false,
        0,
        abi.encode(address(swETH))
    );

    (reserveA, reserveB) = IPoolPositionDynamicSlim(boostedPosition).getReserves();
    console.log("reserves", reserveA, reserveB);
    uint256 mavPriceAfter = mavOracle.getPriceInEth(boostedPosition);
    console.log("mavOracle price after", mavPriceAfter);
    
    require(mavPriceBefore != mavPriceAfter);
  }
}
```

## Impact
There are multiple impacts that an attacker can exploit by manipulating the price of MavEthOracle:

* Decreasing the oracle price to lower the totalDebt of LMPVault, in order to receive more LMPVault shares.
* Increasing the oracle price to raise the totalDebt of LMPVault, in order to receive more withdrawn tokens.
* Manipulating the results of the Stats contracts to cause miscalculations for the protocol.
## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/MavEthOracle.sol#L59-L72

## Tool used
Manual Review
Foundry

## Recommendation
Use another calculation for Maverick oracle

# Issue H-14: Aura/Convex rewards are stuck after DOS 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/738 

## Found by 
0x007, 0x73696d616f, ADM, bin2chen, caelumimperium, ck, ctf\_sec, minhtrng, nobody2018, pengun, pks\_, saidam017, tives, xiaoming90

Since `_claimRewards` accounts for rewards with balanceBefore/After, and anyone can claim Convex rewards, then attacker can DOS the rewards and make them stuck in the LiquidationRow contract.

## Vulnerability Detail

Anyone can claim Convex rewards for any account.

https://etherscan.io/address/0x0A760466E1B4621579a82a39CB56Dda2F4E70f03#code

```solidity
function getReward(address _account, bool _claimExtras) public updateReward(_account) returns(bool){
    uint256 reward = earned(_account);
    if (reward > 0) {
        rewards[_account] = 0;
        rewardToken.safeTransfer(_account, reward);
        IDeposit(operator).rewardClaimed(pid, _account, reward);
        emit RewardPaid(_account, reward);
    }

    //also get rewards from linked rewards
    if(_claimExtras){
        for(uint i=0; i < extraRewards.length; i++){
            IRewards(extraRewards[i]).getReward(_account);
        }
    }
    return true;
}
```

In ConvexRewardsAdapter, the rewards are accounted for by using balanceBefore/after.

```solidity
function _claimRewards(
    address gauge,
    address defaultToken,
    address sendTo
) internal returns (uint256[] memory amounts, address[] memory tokens) {

		uint256[] memory balancesBefore = new uint256[](totalLength);
    uint256[] memory amountsClaimed = new uint256[](totalLength);
...

		for (uint256 i = 0; i < totalLength; ++i) {
        uint256 balance = 0;
        // Same check for "stash tokens"
        if (IERC20(rewardTokens[i]).totalSupply() > 0) {
            balance = IERC20(rewardTokens[i]).balanceOf(account);
        }

        amountsClaimed[i] = balance - balancesBefore[i];

	return (amountsClaimed, rewardTokens);
```

Adversary can call the external convex contract’s  `getReward(tokemakContract)`. After this, the reward tokens are transferred to Tokemak without an accounting hook.

Now, when Tokemak calls claimRewards, then no new rewards are transferred, because the attacker already transferred them. `amountsClaimed` will be 0.

## Impact

Rewards are stuck in the LiquidationRow contract and not queued to the MainRewarder.

## Code Snippet

```solidity
// get balances after and calculate amounts claimed
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
```

https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/destinations/adapters/rewards/ConvexRewardsAdapter.sol/#L102

## Tool used

Manual Review

## Recommendation

Don’t use balanceBefore/After. You could consider using `balanceOf(address(this))` after claiming to see the full amount of tokens in the contract. This assumes that only the specific rewards balance is in the contract.

# Issue M-1: LMPVault exchange rate can potentially be reset by flashloan causing loss of user funds 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/53 

## Found by 
Jigsaw
It is possible for the exchange rate of shares/tokens to be reset to 1:1 via flashloan, causing loss of funds for protocol/users. Further detail can be found in this twitter thread: https://twitter.com/kankodu/status/1685320718870032384.

## Vulnerability Detail
Consider the following thought experiment: 

Lets start with an LMPVault that accepts WETH as the underlying and has share token tokWETH. Lets assume the strategy for the vault involves staking all share tokens in a protocol, which we'll call protocolF, that allows flashloans. Lets further assume that the vault is in a state such that  the exchange rate for 1 tokWETH is 2 WETH ie, to mint 1 tokWETH token at S0 (current state) a user must supply 2 WETH. 

A malicious user would be able to flashloan the entire supply of the LMPVault from protocolF. They would then redeem all underlying assets in the LMPVault and receive 2 WETH for each tokWETH redeemed. They then remint the same number of tokWETH by supplying an equal number of WETH at a 1:1 ratio plus any additional WETH needed to repay a fee denominated in tokWETH, and repay the flashloan, thereby stealing almost half of the underlying WETH in the vault. This would give us S1, a state where the totalSupply of tokWETH is unchanged, however the exchange rate and underlying assets are cut in half to 1:1. 

Submitting this a medium level vulnerability because while user funds are potentially directly at risk, this exploit requires many different factors aligning to be exploited, (singular destination vault etc) and thus is unlikely to happen in (most) cases.

## Impact
This vulnerability does require the vault to be in a specific state, however as the twitter thread above provided shows, this state is not outside the realms of possibility. The impact of such a transaction would be that all users in the vault have realized ~50% loss of funds due to our malicious actor. 

## Code Snippet
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L591

## Tool used
Manual Review

## Recommendation
Per this issue thread on OpenZeppelins 4626 implementation: https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3800, I recommend implementing a requirement that once a vault has been initialized and funded, totalSupply must remain greater than some threshold. A common threshold used for this is 1 gwei. This ensures that the current exchange rate will always be kept track of and prevent this attack vector. 



## Discussion

**sherlock-admin2**

1 comment(s) were left on this issue during the judging contest.

**Trumpero** commented:
> valid, but require a lot of factors which can reduce to low: 
> - all partcipants must provide liquidity to that lending 
> - the integrated lending should a mechanism handle the maximum shares holding by each wallet defined by the tokemak ? which is hard and no lending have this mechanism yet ? 



# Issue M-2: Malicious attackers can perform a DoS attack by executing Router.approve in advance. 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/346 

## Found by 
0x73696d616f, VAD37, nobody2018, p0wd3r, shaka, xiaoming90
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

# Issue M-3: Missing access control on #ExtraRewarder.getReward() 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/369 

## Found by 
0x007, BPZ, BTK, th13vn, xiaoming90

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

# Issue M-4: Lost rewards when the supply is `0`, which always happens if the rewards are queued before anyone has `StakeTracker` tokens 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/387 

## Found by 
0x73696d616f, chaduke, hassan-truscova, lucifero, p0wd3r
If the supply of `StakeTracker` tokens is `0`, the `rewardPerTokenStored` won't increase, but the `lastUpdateBlock` will, leading to lost rewards. 

## Vulnerability Detail
The rewards are destributed in a [`MasterChef`](https://medium.com/coinmonks/analysis-of-the-billion-dollar-algorithm-sushiswaps-masterchef-smart-contract-81bb4e479eb6) style, which takes snapshots of the total accrued rewards over time and whenever someone wants to get the rewards, it subtracts the snapshot of the user from the most updated, global snapshot. 

The [`rewardsPerToken()`](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L180) calculation factors the blocks passed times the reward rate by the `totalSupply()`, to get the reward per token in a specific interval (and then accrues to the previous intervals, as stated in the last paragraph). When the `totalSupply()` is `0`, there is 0 `rewardPerToken()` increment as there is no supply to factor the rewards by.

The current solution is to [maintain](https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/rewarders/AbstractRewarder.sol#L176-L178) the same `rewardsPerToken()` if the `totalSupply()` is `0`, but the `lastUpdateBlock` is still updated. This means that, during the interval in which the `totalSupply()` is `0`, no rewards are destributed but the block numbers still move forward, leaving the tokens stuck in the `MainRewarder` and `ExtraRewarder` smart contracts.

This will always happen if the rewards are quewed before the `totalSupply()` is bigger than `0` (before an initial deposit to either `DestinationVault` or `LMPVault`). It might also happen if users withdraw all their tokens from the vaults, leading to a `totalSupply()` of `0`, but this is very unlikely.

## Impact
Lost reward tokens. The amount depends on the time during which the `totalSupply()` is `0`, but could be significant.

## Code Snippet
The `rewardPerToken()` calculation:
```solidity
function rewardPerToken() public view returns (uint256) {
    uint256 total = totalSupply();
    if (total == 0) {
        return rewardPerTokenStored;
    }

    return rewardPerTokenStored + ((lastBlockRewardApplicable() - lastUpdateBlock) * rewardRate * 1e18 / total);
}
```
The `rewardPerTokenStored` does not increment when the `totalSupply()` is `0`.

## Tool used
Vscode
Foundry
Manual Review

## Recommendation
The `totalSupply()` should not realistically be `0` after the initial setup period (unless for some reason everyone decides to withdraw from the vaults, but this should be handled separately). It should be enough to only allow queueing rewards if the `totalSupply()` is bigger than `0`. For this, only a new check needs to be added:
```solidity
function queueNewRewards(uint256 newRewards) external onlyWhitelisted {
    if (totalSupply() == 0) revert ZeroTotalSupply();
    ...
}
```

# Issue M-5: `LMPVault._withdraw()` can revert due to an arithmetic underflow 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/519 

## Found by 
ArmedGoose, Ch\_301, Flora, Nyx, berndartmueller, shaka
`LMPVault._withdraw()` can revert due to an arithmetic underflow.

## Vulnerability Detail
Inside the `_withdraw()` function, the `maxAssetsToPull` argument value of `_calcUserWithdrawSharesToBurn()` is calculated to be equal to `info.totalAssetsToPull - Math.max(info.debtDecrease, info.totalAssetsPulled)`. 
However, the `_withdraw()` function only halts its loop when `info.totalAssetsPulled >= info.totalAssetsToPull`. 
This can lead to a situation where `info.debtDecrease >= info.totalAssetsToPull`. Consequently, when calculating `info.totalAssetsToPull - Math.max(info.debtDecrease, info.totalAssetsPulled)` for the next destination vault in the loop, an underflow occurs and triggers a contract revert.

To illustrate this vulnerability, consider the following scenario:

```solidity
    function test_revert_underflow() public {
        _accessController.grantRole(Roles.SOLVER_ROLE, address(this));
        _accessController.grantRole(Roles.LMP_FEE_SETTER_ROLE, address(this));

        // User is going to deposit 1500 asset
        _asset.mint(address(this), 1500);
        _asset.approve(address(_lmpVault), 1500);
        _lmpVault.deposit(1500, address(this));

        // Deployed 700 asset to DV1
        _underlyerOne.mint(address(this), 700);
        _underlyerOne.approve(address(_lmpVault), 700);
        _lmpVault.rebalance(
            address(_destVaultOne),
            address(_underlyerOne), // tokenIn
            700,
            address(0), // destinationOut, none when sending out baseAsset
            address(_asset), // baseAsset, tokenOut
            700
        );

        // Deploy 600 asset to DV2
        _underlyerTwo.mint(address(this), 600);
        _underlyerTwo.approve(address(_lmpVault), 600);
        _lmpVault.rebalance(
            address(_destVaultTwo),
            address(_underlyerTwo), // tokenIn
            600,
            address(0), // destinationOut, none when sending out baseAsset
            address(_asset), // baseAsset, tokenOut
            600
        );

        // Deployed 200 asset to DV3
        _underlyerThree.mint(address(this), 200);
        _underlyerThree.approve(address(_lmpVault), 200);
        _lmpVault.rebalance(
            address(_destVaultThree),
            address(_underlyerThree), // tokenIn
            200,
            address(0), // destinationOut, none when sending out baseAsset
            address(_asset), // baseAsset, tokenOut
            200
        );

        // Drop the price of DV2 to 70% of original, so that 600 we transferred out is now only worth 420
         _mockRootPrice(address(_underlyerTwo), 7e17);

        // Revert because of an arithmetic underflow
        vm.expectRevert();
        uint256 assets = _lmpVault.redeem(1000, address(this), address(this));
    }
```

## Impact

The vulnerability can result in the contract reverting due to an underflow, disrupting the functionality of the contract. 
Users who try to withdraw assets from the LMPVault may encounter transaction failures and be unable to withdraw their assets.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L475
https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L493-L504

## Tool used
Manual Review

## Recommendation
To mitigate this vulnerability, it is recommended to break the loop within the `_withdraw()` function if `Math.max(info.debtDecrease, info.totalAssetsPulled) >= info.totalAssetsToPull`

```solidity
                if (
                    Math.max(info.debtDecrease, info.totalAssetsPulled) >
                    info.totalAssetsToPull
                ) {
                    info.idleIncrease =
                        Math.max(info.debtDecrease, info.totalAssetsPulled) -
                        info.totalAssetsToPull;
                    if (info.totalAssetsPulled >= info.debtDecrease) {
                        info.totalAssetsPulled = info.totalAssetsToPull;
                    }
                    break;
                }

                // No need to keep going if we have the amount we're looking for
                // Any overage is accounted for above. Anything lower and we need to keep going
                // slither-disable-next-line incorrect-equality
                if (
                    Math.max(info.debtDecrease, info.totalAssetsPulled) ==
                    info.totalAssetsToPull
                ) {
                    break;
                }
```

# Issue M-6: Unable to withdraw extra rewards 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/565 

## Found by 
0xGoodess, 0xdeadbeef, Ch\_301, berndartmueller, xiaoming90

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

# Issue M-7: Malicious or compromised admin of certain LSTs could manipulate the price 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/570 

## Found by 
ctf\_sec, xiaoming90

Malicious or compromised admin of certain LSTs could manipulate the price of the LSTs.

## Vulnerability Detail

> **Important**
> Per the [contest detail page](https://github.com/sherlock-audit/2023-06-tokemak-xiaoming9090/tree/main#q-are-the-admins-of-the-protocols-your-contracts-integrate-with-if-any-trusted-or-restricted), admins of the external protocols are marked as "Restricted" (Not Trusted). This means that any potential issues arising from the external protocol's admin actions (maliciously or accidentally) are considered valid in the context of this audit.
>
> **Q: Are the admins of the protocols your contracts integrate with (if any) TRUSTED or RESTRICTED?**
>
> RESTRICTED

> **Note**
> This issue also applies to other support Liquid Staking Tokens (LSTs) where the admin could upgrade the token contract code. Those examples are omitted for brevity, as the write-up and mitigation are the same and would duplicate this issue.

Per the [contest detail page](https://github.com/sherlock-audit/2023-06-tokemak-xiaoming9090/tree/main#q-which-erc20-tokens-do-you-expect-will-interact-with-the-smart-contracts), the protocol will hold and interact with the Swell ETH (swETH).

> Liquid Staking Tokens
>
> - swETH: 0xf951E335afb289353dc249e82926178EaC7DEd78

Upon inspection of the [swETH on-chain contract](https://etherscan.io/token/0xf951e335afb289353dc249e82926178eac7ded78#code), it was found that it is a Transparent Upgradeable Proxy. This means that the admin of Swell protocol could upgrade the contracts. 

Tokemak relies on the `swEth.swETHToETHRate()` function to determine the price of the swETH LST within the protocol. Thus, a malicious or compromised admin of Swell could upgrade the contract to have the `swETHToETHRate` function return an extremely high to manipulate the total values of the vaults, resulting in users being able to withdraw more assets than expected, thus draining the LMPVault.

```solidity
File: SwEthEthOracle.sol
26:     function getPriceInEth(address token) external view returns (uint256 price) {
27:         // Prevents incorrect config at root level.
28:         if (token != address(swEth)) revert Errors.InvalidToken(token);
29: 
30:         // Returns in 1e18 precision.
31:         price = swEth.swETHToETHRate();
32:     }
```

## Impact

Loss of assets in the scenario as described above.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/oracles/providers/SwEthEthOracle.sol#L26

## Tool used

Manual Review

## Recommendation

The protocol team should be aware of the above-mentioned risks and consider implementing additional controls to reduce the risks. 

Review each of the supported LSTs and determine how much power the Liquid staking protocol team/admin has over its tokens.

For LSTs that are more centralized (e.g., Liquid staking protocol team could update the token contracts or have the ability to update the exchange rate/price to an arbitrary value without any limit), those LSTs should be subjected to additional controls or monitoring, such as implementing some form of circuit breakers if the price deviates beyond a reasonable percentage to reduce the negative impact to Tokemak if it happens.

# Issue M-8: Losses are not distributed equally 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/591 

## Found by 
xiaoming90

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

# Issue M-9: Incorrect handling of Stash Tokens within the `ConvexRewardsAdapter._claimRewards()` 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/632 

## Found by 
duc, nobody2018
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

# Issue M-10: Vault cannot be added back into the vault registry 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/674 

## Found by 
0x70C9, AuditorPraise, Aymen0909, KingNFT, Phantasmagoria, ast3ros, carrotsmuggler, dipp, techOptimizor, xiaoming90

The vault registry does not clear the vault type mapping when removing a vault, which prevents the same vault from being added back later.

## Vulnerability Detail

When removing a vault from the registry, all states related to the vaults such as the `_vaults`, `_assets`, `_vaultsByAsset` are cleared except the `_vaultsByType` state.

        function removeVault(address vaultAddress) external onlyUpdater {
            Errors.verifyNotZero(vaultAddress, "vaultAddress");

            // remove from vaults list
            if (!_vaults.remove(vaultAddress)) revert VaultNotFound(vaultAddress);

            address asset = ILMPVault(vaultAddress).asset();

            // remove from assets list if this was the last vault for that asset
            if (_vaultsByAsset[asset].length() == 1) {
                //slither-disable-next-line unused-return
                _assets.remove(asset);
            }

            // remove from vaultsByAsset mapping
            if (!_vaultsByAsset[asset].remove(vaultAddress)) revert VaultNotFound(vaultAddress);

            emit VaultRemoved(asset, vaultAddress);
        }

https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/vault/LMPVaultRegistry.sol#L64-L82

The uncleared `_vaultsByType` state will cause the `addVault` function to revert when trying to add the vault back into the registry even though the vault does not exist in the registry anymore.

        if (!_vaultsByType[vaultType].add(vaultAddress)) revert VaultAlreadyExists(vaultAddress);

https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/vault/LMPVaultRegistry.sol#L59

## Impact

The `addVault` function is broken in the edge case when the updater tries to add the vault back into the registry after removing it. It affects all the operations of the protocol that rely on the vault registry.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/vault/LMPVaultRegistry.sol#L64-L82

## Tool used

Manual Review

## Recommendation

Clear the `_vaultsByType` state when removing the vault from the registry.

```diff

        function removeVault(address vaultAddress) external onlyUpdater {
            Errors.verifyNotZero(vaultAddress, "vaultAddress");
+            ILMPVault vault = ILMPVault(vaultAddress);
+            bytes32 vaultType = vault.vaultType();

            // remove from vaults list
            if (!_vaults.remove(vaultAddress)) revert VaultNotFound(vaultAddress);

            address asset = ILMPVault(vaultAddress).asset();

            // remove from assets list if this was the last vault for that asset
            if (_vaultsByAsset[asset].length() == 1) {
                //slither-disable-next-line unused-return
                _assets.remove(asset);
            }

            // remove from vaultsByAsset mapping
            if (!_vaultsByAsset[asset].remove(vaultAddress)) revert VaultNotFound(vaultAddress);
+           if (!_vaultsByType[vaultType].remove(vaultAddress)) revert VaultNotFound(vaultAddress);

            emit VaultRemoved(asset, vaultAddress);
        }

```

# Issue M-11: LMPVault: DoS when `feeSink` balance hits `perWalletLimit` 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/679 

## Found by 
Ch\_301, n33k, warRoom, xiaoming90

The LMPVault token share has a per-wallet limit. LMPVault collects fees as share tokens to the `feeSink` address. `_collectFees` will revert if it mints shares that make the `feeSink` balance hit the `perWalletLimit`.

## Vulnerability Detail

`_collectFees` mints shares to `feeSink`.

```solidity
function _collectFees(uint256 idle, uint256 debt, uint256 totalSupply) internal {
    address sink = feeSink;
    ....
    if (fees > 0 && sink != address(0)) {
        // Calculated separate from other mints as normal share mint is round down
        shares = _convertToShares(fees, Math.Rounding.Up);
        _mint(sink, shares);
        emit Deposit(address(this), sink, fees, shares);
    }
    ....
}
```

`_mint` calls `_beforeTokenTransfer` internally to check if the target wallet exceeds `perWalletLimit`.

```solidity
function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override whenNotPaused {
    ....
    if (balanceOf(to) + amount > perWalletLimit) {
        revert OverWalletLimit(to);
    }
}
```

`_collectFees` function will revert if `balanceOf(feeSink) + fee shares > perWalletLimit`. `updateDebtReporting`, `rebalance` and `flashRebalance` call `_collectFees` internally so they will be unfunctional.

## Impact

`updateDebtReporting`, `rebalance` and `flashRebalance` won't be working if `feeSink` balance hits `perWalletLimit`.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L823

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L849-L851

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L797

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L703

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/vault/LMPVault.sol#L727

## Tool used

Manual Review

## Recommendation

Allow `feeSink` to exceeds `perWalletLimit`.

# Issue M-12: Incorrect amount given as input to `_handleRebalanceIn` when `flashRebalance` is called 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/701 

## Found by 
Aymen0909, ck

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



## Discussion

**sherlock-admin2**

1 comment(s) were left on this issue during the judging contest.

**Trumpero** commented:
> 



# Issue M-13: Potential vulnerabilities with a 30-Minute Delay in TellorOracle 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/744 

## Found by 
0x73696d616f, 0xWeiss, Ch\_301, Qeew, ctf\_sec, inspecktor, lemonmon, xiaoming90

The protocol primarily uses Chainlink as its primary oracle service but falls back to Tellor in case Chainlink is down. However, the Tellor oracle is used with a 30-minute delay, which introduces a  potential risk.

## Vulnerability Detail
In the TellorOracle.sol contract, the following statement is used to retrieve data from the Tellor oracle:

(bytes memory data, uint256 timestamp) = getDataBefore(_queryId, block.timestamp - 30 minutes);

The vulnerability arises from the 30-minute delay in the getPriceInEth function of the TellorOracle contract. This delay means that, in the event of a fallback to Tellor, the system will be using a price that is at least 30 minutes old, which can lead to significant discrepancies in volatile markets.

There is a recent analysis by [Liquity ](https://www.liquity.org/blog/tellor-issue-and-fix) in which they are using 15 minutes for ETH after making some analysis of ETH volatility behaviour. 

Basically, there is a tradeoff between the volatility of an asset and the dispute time. More time is safer to have time to dispute but more likely to read an old value. 

## Impact

The 30-minute delay could lead to a larger differential between the price the system sees and the real market price. This is particularly important in the case of a fallback, as it increases the chances of the system using a stale price. Liquity chose 15 minute to give plenty of time for disputers to respond to fake prices while keeping any adverse impacts on the system to a minimum. Using a 30-minute delay could lead to adverse impacts that Liquity sought to minimize.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/5d8e902ce33981a6506b1b5fb979a084602c6c9a/v2-core-audit-2023-07-14/src/oracles/providers/TellorOracle.sol#L105

## Tool used

Manual Review

## Recommendation

Reduce the delay to a shorter period, such as 15 minutes, as used by Liquity.

# Issue M-14: OOG / unexpected reverts due to incorrect usage of staticcall. 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/822 

## Found by 
carrotsmuggler, ctf\_sec

OOG / unexpected reverts due to incorrect usage of staticcall.

## Vulnerability Detail

The function `checkReentrancy` in `BalancerUtilities.sol` is used to check if the balancer contract has been re-entered or not. It does this by doing a `staticcall` on the pool contract and checking the return value. According to the solidity docs, if a staticcall encounters a state change, it burns up all gas and returns. The `checkReentrancy` tries to call `manageUserBalance` on the vault contract, and returns if it finds a state change.

The issue is that this burns up all the gas sent with the call. According to EIP150, a call gets allocated 63/64 bits of the gas, and the entire 63/64 parts of the gas is burnt up after the staticcall, since the staticcall will always encounter a storage change. This is also highlighted in the balancer monorepo, which has guidelines on how to check re-entrancy [here](https://github.com/balancer/balancer-v2-monorepo/blob/227683919a7031615c0bc7f144666cdf3883d212/pkg/pool-utils/contracts/lib/VaultReentrancyLib.sol#L43-L55).

This can also be shown with a simple POC.

```solidity
unction testAttack() public {
        mockRootPrice(WSTETH, 1_123_300_000_000_000_000); //wstETH
        mockRootPrice(CBETH, 1_034_300_000_000_000_000); //cbETH

        IBalancerMetaStablePool pool = IBalancerMetaStablePool(WSTETH_CBETH_POOL);

        address[] memory assets = new address[](2);
        assets[0] = WSTETH;
        assets[1] = CBETH;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10_000 ether;
        amounts[1] = 0;

        IBalancerVault.JoinPoolRequest memory joinRequest = IBalancerVault.JoinPoolRequest({
            assets: assets,
            maxAmountsIn: amounts, // maxAmountsIn,
            userData: abi.encode(
                IBalancerVault.JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT,
                amounts, //maxAmountsIn,
                0
            ),
            fromInternalBalance: false
        });

        IBalancerVault.SingleSwap memory swapRequest = IBalancerVault.SingleSwap({
            poolId: 0x9c6d47ff73e0f5e51be5fd53236e3f595c5793f200020000000000000000042c,
            kind: IBalancerVault.SwapKind.GIVEN_IN,
            assetIn: WSTETH,
            assetOut: CBETH,
            amount: amounts[0],
            userData: abi.encode(
                IBalancerVault.JoinKind.EXACT_TOKENS_IN_FOR_BPT_OUT,
                amounts, //maxAmountsIn,
                0
            )
        });

        IBalancerVault.FundManagement memory funds = IBalancerVault.FundManagement({
            sender: address(this),
            fromInternalBalance: false,
            recipient: payable(address(this)),
            toInternalBalance: false
        });

        emit log_named_uint("Gas before price1", gasleft());
        uint256 price1 = oracle.getPriceInEth(WSTETH_CBETH_POOL);
        emit log_named_uint("price1", price1);
        emit log_named_uint("Gas after price1 ", gasleft());
    }
```

The oracle is called to get a price. This oracle calls the `checkReentrancy` function and burns up the gas. The gas left is checked before and after this call.

The output shows this:

```bash
[PASS] testAttack() (gas: 9203730962297323943)
Logs:
Gas before price1: 9223372036854745204
price1: 1006294352158612428
Gas after price1 : 425625349158468958
```

This shows that 96% of the gas sent is burnt up in the oracle call.

## Impact

This causes the contract to burn up 63/64 bits of gas in a single check. If there are lots of operations after this call, the call can revert due to running out of gas. This can lead to a DOS of the contract.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/libs/BalancerUtilities.sol#L19-L28

## Tool used

Foundry

## Recommendation

According to the monorepo [here](https://github.com/balancer/balancer-v2-monorepo/blob/227683919a7031615c0bc7f144666cdf3883d212/pkg/pool-utils/contracts/lib/VaultReentrancyLib.sol#L43-L55), the staticall must be allocated a fixed amount of gas. Change the reentrancy check to the following.

```solidity
(, bytes memory revertData) = address(vault).staticcall{ gas: 10_000 }(
            abi.encodeWithSelector(vault.manageUserBalance.selector, 0)
        );
```

This ensures gas isn't burnt up without reason.

# Issue M-15: Slashing during `LSTCalculatorBase.sol` deployment can show bad apr for months 

Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/824 

## Found by 
carrotsmuggler, saidam017, xiaoming90

Slashing during `LSTCalculatorBase.sol` deployment can show bad apr for months

## Vulnerability Detail

The contract `LSTCalculatorBase.sol` has some functions to calculate the rough APR expected from a liquid staking token. The contract is first deployed, and the first snapshot is taken after `APR_FILTER_INIT_INTERVAL_IN_SEC`, which is 9 days. It then calculates the APR between the deployment and this first snapshot, and uses that to initialize the APR value. It uses the function `calculateAnnualizedChangeMinZero` to do this calculation.

The issue is that the function `calculateAnnualizedChangeMinZero` has a floor of 0. So if the backing of the LST decreases over that 9 days due to a slashing event in that interval, this function will return 0, and the initial APR and `baseApr` will be set to 0.

The calculator is designed to update the APR at regular intervals of 3 days. However, the new apr is given a weight of 10% and the older apr is given a weight of 90% as seen below.

```solidity
return ((priorValue * (1e18 - alpha)) + (currentValue * alpha)) / 1e18;
```

And alpha is hardcoded to 0.1. So if the initial APR starts at 0 due to a slashing event in the initial 9 day period, a large number of updates will be required to bring the APR up to the correct value.

Assuming the correct APR of 6%, and an initial APR of 0%, we can calculate that it takes upto 28 updates to reflect close the correct APR. This transaltes to 84 days. So the wrong APR cann be shown for upto 3 months. Tha protocol uses these APR values to justify the allocation to the various protocols. Thus a wrong APR for months would mean the protocol would sub optimally allocate funds for months, losing potential yield.

## Impact

The protocol can underperform for months due to slashing events messing up APR calculations close to deployment date.

## Code Snippet

https://github.com/sherlock-audit/2023-06-tokemak/blob/main/v2-core-audit-2023-07-14/src/stats/calculators/base/LSTCalculatorBase.sol#L108-L110

## Tool used

Manual Review

## Recommendation

It is recommended to initialize the APR with a specified value, rather than calculate it over the initial 9 days. 9 day window is not good enough to get an accurate APR, and can be easily manipulated by a slashing event.

