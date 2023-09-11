Helpful Amber Llama

high

# Curve rentrancy check does not work
## Summary
curve re entrancy check does not work

## Vulnerability Detail

Curve protocol is a protocol that is prone to read only reentrancy attacks. Because of this protocols that wish to use curve must establish a re entrancy guard or re entrancy check. The problem with the reentrancy check in tokemak is that it does not work.

```solidity
 for (uint256 i = 0; i < nTokens;) {
            address iToken = tokens[i];

            // We're in a V1 ETH pool and we'll be reading the virtual price later
            // make sure we're not in a read-only reentrancy scenario
            if (iToken == LibAdapter.CURVE_REGISTRY_ETH_ADDRESS_POINTER) {
                // @audit
                if (poolInfo.checkReentrancy == 1) {
                    // This will fail in reentrancy
                    ICurveOwner(pool.owner()).withdraw_admin_fees(address(pool));
                }
            }
```

Here is the logic for the reentrancy check.

The problem comes up in this line of code `ICurveOwner(pool.owner()).withdraw_admin_fees(address(pool))`.

Some of the in scope curve pool does not expose the `owner()` function, so this call will always revert.

This will cause the reentrancy check to revert and make withdraw revert 

Also You can observe the owner() function is not exposed when reading contract

https://etherscan.io/address/0x21E27a5E5513D6e65C4f830167390997aA84843a#readContract

also the [withdraw_admin_fee](https://etherscan.io/address/0x21E27a5E5513D6e65C4f830167390997aA84843a#code#L1116) does not check if pool is in re-entered state
(does not have @nonreentrant('lock') modifier)

so calling withdraw_admin_fee to check read-only reentrancy does not really work

## Impact

Reentrancy check will always revert, the protocol is prone to reentrancy attacks.

## Code Snippet
https://github.com/Tokemak/v2-core-audit-2023-07-14/blob/62445b8ee3365611534c96aef189642b721693bf/src/oracles/providers/CurveV1StableEthOracle.sol#L112-L156



## Tool used

Manual Review

## Recommendation

N/A