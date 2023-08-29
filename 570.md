Clean Mulberry Gecko

medium

# Malicious or compromised admin of certain LSTs could manipulate the price
## Summary

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