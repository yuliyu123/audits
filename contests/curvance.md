# Curvance 


## Findings Summary


| ID  | Description | Severity |
|-----|-------------|----------|
| [H-01](#h-01-incorrect-stablepool-bpt-price-calculation) | Incorrect StablePool BPT price calculation | High |(#h-01-incorrect-stablepool-bpt-price-calculation) |
| [M-01](#m-01-dtoken-debt-cant-be-repaidliquidated-due-to-overflow) | DToken debt can't be repaid/liquidated due to overflow | Medium |
| [M-02](#m-02-utilization-ratio-can-be-manipulated-above-100) | Utilization ratio can be manipulated above 100% | Medium |
| [M-03](#m-03-cve-bridge-will-be-replayed-when-chain-hard-fork) | CVE bridge will be replayed when chain hard fork | Medium |
| [M-04](#m-04-malicious-users-can-open-many-small-positions-and-borrow-debt-liquidators-have-no-profit-to-liquidate-such-positions) | Malicious users can open many small positions and borrow debt, liquidators have no profit to liquidate such positions | Medium |





### <a name="h-01-incorrect-stablepool-bpt-price-calculation"></a> [H-01] Incorrect StablePool BPT price calculation

**Description**:

Incorrect StablePool BPT price calculation as `RateProvider's` rate are not considered

According to balancer [doc](https://github.com/balancer/docs/blob/663e2f4f2c3eee6f85805e102434629633af92a2/docs/concepts/advanced/valuing-bpt/bpt-as-collateral.md#metastablepools-eg-wsteth-weth), the current stable pool price calculation as following(e.g. wstETH-WETH):

1. Get market price for each constituent token

Get market price of wstETH and WETH in terms of USD, using chainlink oracles.

2. Get RateProvider price for each constituent token

Since wstETH - WETH pool is a MetaStablePool and not a ComposableStablePool, it does not have getTokenRate() function. Therefore, it's needed to get the `RateProvider` price manually for wstETH, using the rate providers of the pool. The rate provider will return the wstETH token in terms of stETH.

Note that WETH does not have a rate provider for this pool. In that case, assume a value of 1e18 (it means, market price of WETH won't be divided by any value, and it's used purely in the minPrice formula).

3. Get minimum price

`minPrice = min(marketPriceOfWstETH/WstETHRateProvider.getRate(), marketPriceOfWETH)`

4. Calculates the BPT price

return `minPrice * IRateProvider(poolAddress).getRate()`

So incorrect stable pool BPT price calculation can cause users borrow/repay/liquidated more/less tokens than actually.

**Recommendation**:

For pools having rate providers, divide prices by rate then choosing the minimum, finally calculate the price by `minPrice * IRateProvider(poolAddress).getRate()`. Protocol should refactor such function from Balancer [doc](https://github.com/balancer/docs/blob/663e2f4f2c3eee6f85805e102434629633af92a2/docs/concepts/advanced/valuing-bpt/bpt-as-collateral.md#metastablepools-eg-wsteth-weth).

### <a name="m-01-dtoken-debt-cant-be-repaidliquidated-due-to-overflow"></a> M-01: DToken debt can't be repaid/liquidated due to overflow

**Description**:

When borrowers [borrow](https://github.com/curvance/Curvance-CantinaCompetition/blob/76669e36572d9c6803a0e706214a9149d5247586/contracts/market/collateral/DToken.sol#L1244-L1255) from DToken, the borrow position `principal` will increase, the code `_debtOf[account].principal = debtBalanceCached(account) + amount` calculate the borrower's debt principal based on `debtBalanceCached(account)` and borrow `amount`.

Inside `debtBalanceCached()` function:

```solidity
function debtBalanceCached(address account) public view returns (uint256) {
    // Cache borrow data to save gas.
    DebtData storage accountDebt = _debtOf[account];

    // If theres no principal owed, can return immediately.
    if (accountDebt.principal == 0) {
        return 0;
    }

    // Calculate debt balance using the interest index:
    // debtBalanceCached calculation:
    // ((Account's principal * DToken's exchange rate) /
    // Account's exchange rate).
    return
        (accountDebt.principal * marketData.exchangeRate) /
        accountDebt.accountExchangeRate;
}
```


As we can see, first borrowers's debt principal will be `_debtOf[account].principal = totalBorrows = amount`. After some time goes by, when `repay` or `_liquidate` all the borrower's full debt, the calculation steps as following:

```solidity
function _repay(
    address payer,
    address account,
    uint256 amount
) internal returns (uint256) {
  // Validate that the payer is allowed to repay the loan.
  marketManager.canRepay(address(this), account);

  // Cache how much the account has to save gas.
  uint256 accountDebt = debtBalanceCached(account);

  // Validate repayment amount is not excessive.
  if (amount > accountDebt) {
      revert DToken__ExcessiveValue();
  }

  // If amount == 0, repay max; amount = accountDebt.
  amount = amount == 0 ? accountDebt : amount;

  SafeTransferLib.safeTransferFrom(
      underlying,
      payer,
      address(this),
      amount
  );

  // We calculate the new account and total borrow balances,
  // we check that amount is <= accountDebt so we can skip
  // underflow check here.
  unchecked {
      _debtOf[account].principal = accountDebt - amount;
  }
  _debtOf[account].accountExchangeRate = marketData.exchangeRate;
  totalBorrows -= amount;
  ...
}
```

we can see if the borrowers call `repay(0)` function to repay all debt, the debt is equal to `debtBalanceCached(account)` equal to `(accountDebt.principal * marketData.exchangeRate) / accountDebt.accountExchangeRate`, the `marketData.exchangeRate` and `totalBorrows` will update when call `DToken#accrueInterest` every time, the function be called by `DToken#repay/liquidate` functions.

```solidity
function accrueInterest() public {
  ...
  // Calculate the interest compound cycles to update,
  // in `interestCompounds`. Rounds down natively.
  // @audit - here `interestCompounds` can round down.
>>>  uint256 interestCompounds = (block.timestamp -
      cachedData.lastTimestampUpdated) / cachedData.compoundRate;
  // Calculate the interest and debt accumulated.
  uint256 interestAccumulated = borrowRate * interestCompounds;
  // @audit - here `debtAccumulated` can round down again.
>>>  uint256 debtAccumulated = (interestAccumulated * borrowsPrior) / WAD;
  // Calculate new borrows, and the new exchange rate, based on
  // accumulation values above.
  uint256 totalBorrowsNew = debtAccumulated + borrowsPrior;
  // @audit - here `exchangeRateNew` only round down once.
>>>  uint256 exchangeRateNew = ((interestAccumulated * exchangeRatePrior) /
      WAD) + exchangeRatePrior;
  // Update update timestamp, exchange rate, and total outstanding
  // borrows.
  marketData.lastTimestampUpdated = uint40(
      cachedData.lastTimestampUpdated +
          (interestCompounds * cachedData.compoundRate)
  );
  marketData.exchangeRate = uint216(exchangeRateNew);
  totalBorrows = totalBorrowsNew;
  ...
}
```

Because round issue here, the `totalBorrows` may a few less than `debtBalanceCached(account)` after first borrower borrow from DToken some time, accumulated debt will increase as time goes by, such that the borrower can't repay all his debt or can't be liquidated by others if no other borrowers borrow from DToken during this period time because [`totalBorrows -= amount`](https://github.com/curvance/Curvance-CantinaCompetition/blob/76669e36572d9c6803a0e706214a9149d5247586/contracts/market/collateral/DToken.sol#L1379) will overflow.

This cause two issues here:

- First borrower can't repay/liquidated all his debt if there is no other borrowers during this period time.
- The DToken's debt can't be repaid/liquidated all, the last borrower's repay/liquidation action can't be done if accumulate some debt there.



PoC:

issue 1 - first borrower can't repay/liquidated all his debt:
```solidity
function testFirstBorrowerRevertedAfterAccrueInterests() public {
    uint256 _BASE_UNDERLYING_RESERVE = 42069;
    uint256 initialUsdcReserves = 1000e6;
    _setCbalRETHCollateralCaps(100_000e18);

    uint256 addUsdcAmount = 1150e6;
    deal(_USDC_ADDRESS, address(dUSDC), _BASE_UNDERLYING_RESERVE + initialUsdcReserves + addUsdcAmount);

    // 1. post collateral and borrow 1e18 - 1
    marketManager.postCollateral(address(this), address(cBALRETH), 1e18 - 1);
    dUSDC.borrow(addUsdcAmount);

    // can be called by malicious users
    for (uint i; i < 2; ++i) {
        skip(1 days);
        dUSDC.accrueInterest();
    }

    // 2. repay all debt would revert because overflow
    // give address(this) enough usdc to repay their debt because accumulated interest
    deal(_USDC_ADDRESS, address(this), 10000e6);
    IERC20(_USDC_ADDRESS).approve(address(dUSDC), type(uint256).max);
    // vm.expectRevert();
    dUSDC.repay(0);
}
```

Result:

```json
[FAIL. Reason: panic: arithmetic underflow or overflow (0x11)] testFirstBorrowerRevertedAfterAccrueInterests() (gas: 1493803)
```

issue 2 - the last borrower can't repay/liquidated all his debt:
```solidity
function testBorrowersCannotRepayAllDebts() public {
    uint256 _BASE_UNDERLYING_RESERVE = 42069;
    uint256 initialUsdcReserves = 1000e6;
    _setCbalRETHCollateralCaps(100_000e18);

    uint256 addUsdcAmount = 1500e6;
    deal(_USDC_ADDRESS, address(dUSDC), _BASE_UNDERLYING_RESERVE + initialUsdcReserves + addUsdcAmount);

    address user101 = address(101);
    address user102 = address(102);
    address user103 = address(103);
    address[] memory users = new address[](3);
    users[0] = user101;
    users[1] = user102;
    users[2] = user103;

    // 1. users post collateral and borrow 100 usdc
    for (uint i; i < 3; ++i) {
        address user = users[i];
        deal(address(cBALRETH), user, 1e18);
        vm.startPrank(user);
        marketManager.postCollateral(user, address(cBALRETH), 1e18 - 1);
        dUSDC.borrow(100e6);
        vm.stopPrank();
    }

    // 2. repay user101 and user102 all debt after two days
    skip(2 days);
    for (uint i; i < 2; ++i) {
        address user = users[i];
        vm.startPrank(user);
        // give users enough usdc to repay their debt because accumulated interest
        deal(_USDC_ADDRESS, user, 1000e6);
        IERC20(_USDC_ADDRESS).approve(address(dUSDC), type(uint256).max);
        dUSDC.repay(0);
        vm.stopPrank();
    }

    // can be called by malicious users
    for (uint i; i < 2; ++i) {
        skip(1 days);
        dUSDC.accrueInterest();
    }

    deal(_USDC_ADDRESS, users[2], 1000e6);
    vm.startPrank(users[2]);
    IERC20(_USDC_ADDRESS).approve(address(dUSDC), type(uint256).max);
    // 3. user103 repay all his debt would revert because overflow
    // vm.expectRevert();
    dUSDC.repay(0);
    vm.stopPrank();
}
```


Result:

```json
[FAIL. Reason: panic: arithmetic underflow or overflow (0x11)] testBorrowersCannotRepayAllDebts() (gas: 3486652)
```

Insert the two cases into `tests/market/collateral/DToken/functions/Borrow.t.sol` file.

**Recommendation**:

1. Change `totalBorrows -= accountDebt` to:

```solidity
if (totalBorrows < accountDebt) {
    totalBorrows = 0;
}
```

2.  Fix round issue in `DToken#accrueInterest` function.

### <a name="m-02-utilization-ratio-can-be-manipulated-above-100"></a> M-02: Utilization ratio can be manipulated above 100%

**Description**:

In low liquidity market, `UtilizationRatio` can be manipulated above 100%.

When borrowing from DToken, the utilization rate [calculation](https://github.com/curvance/Curvance-CantinaCompetition/blob/76669e36572d9c6803a0e706214a9149d5247586/contracts/market/collateral/DToken.sol#L820-L827) based on `marketUnderlyingHeld`, `totalBorrows` and `totalReserves`, the later two parameters be updated when `DToken#accrueInterest` function be called:


```solidity
function accrueInterest() public {
  ...
  // Calculate the interest compound cycles to update,
  // in `interestCompounds`. Rounds down natively.
 uint256 interestCompounds = (block.timestamp -
      cachedData.lastTimestampUpdated) / cachedData.compoundRate;
  // Calculate the interest and debt accumulated.
  uint256 interestAccumulated = borrowRate * interestCompounds;
  uint256 debtAccumulated = (interestAccumulated * borrowsPrior) / WAD;
  // Calculate new borrows, and the new exchange rate, based on
  // accumulation values above.
  uint256 totalBorrowsNew = debtAccumulated + borrowsPrior;
  uint256 exchangeRateNew = ((interestAccumulated * exchangeRatePrior) /
      WAD) + exchangeRatePrior;
  // Update update timestamp, exchange rate, and total outstanding
  // borrows.
  marketData.lastTimestampUpdated = uint40(
      cachedData.lastTimestampUpdated +
          (interestCompounds * cachedData.compoundRate)
  );
  marketData.exchangeRate = uint216(exchangeRateNew);
  totalBorrows = totalBorrowsNew;
  ...
  uint256 newReserves = ((interestFactor * debtAccumulated) / WAD);
  if (newReserves > 0) {
      totalReserves = newReserves + reservesPrior;

      // Update gauge pool values for new reserves.
      _gaugePool().deposit(
          address(this),
          centralRegistry.daoAddress(),
          newReserves
      );
  }
}
```

As time goes by, `totalBorrowsNew` and `totalReserves` will be greater because accumulated debt.

So if `totalBorrowsNew` is nearly or equal to `marketUnderlyingHeld()` at first in low liquidity market, the utilization ratio can be manipulated above 100%.

The utilization rate is basically `assets_borrowed / assets_loaned`, the higher utilization ratio, the higher interest rate,
such that borrowers be discouraged from borrowing from DToken, it shouldn't exceed 100% in any markets.


PoC:


```solidity
function testUtilizationRateInLowLiquidity() public {
    uint256 _BASE_UNDERLYING_RESERVE = 42069;
    uint256 initialUsdcReserves = 1000e6;
    _setCbalRETHCollateralCaps(100_000e18);

    uint256 addUsdcAmount = 1150e6;
    deal(_USDC_ADDRESS, address(dUSDC), _BASE_UNDERLYING_RESERVE + initialUsdcReserves + addUsdcAmount);

    assertEq(dUSDC.interestRateModel().compoundRate(), 600);
    assertEq(dUSDC.utilizationRate(), 0);

    // 1. user post collateral and borrow 1150 usdc
    marketManager.postCollateral(address(this), address(cBALRETH), 1e18 - 1);
    dUSDC.borrow(addUsdcAmount);
    assertLt(dUSDC.utilizationRate(), 1 ether);
    assertEq(dUSDC.totalBorrows(), addUsdcAmount);
    assertEq(dUSDC.totalSupply(), _BASE_UNDERLYING_RESERVE);

    // 2. accure interest
    for (uint i; i < 300; ++i) {
        skip(1 days);
        dUSDC.accrueInterest();
    }

    // 3. dUSDC.utilizationRate will exceed 100%
    assertGt(dUSDC.totalBorrows(), addUsdcAmount);
    assertGt(dUSDC.utilizationRate(), 1 ether);
    console2.log("Final utilizationRate", dUSDC.utilizationRate());
}
```

Result:

```json
[PASS] testUtilizationRateInLowLiquidity() (gas: 9275139)
Logs:
  finnal utilizationRate 1009843285420908248
```


Insert the case into `tests/market/collateral/DToken/functions/Borrow.t.sol` file.


**Recommendation**:

Limit DToken utilization ratio can't exceed 100%, many lending protocol have such a limitation, you can see here: https://medium.com/immunefi/silo-finance-logic-error-bugfix-review-35de29bd934a


### <a name="m-03-cve-bridge-will-be-replayed-when-chain-hard-fork"></a> M-03: CVE bridge will be replayed when chain hard fork


**Description**:

When chain hard fork, CVE/VeCVE bridge functions like [`CVE#bridge`](https://github.com/curvance/Curvance-CantinaCompetition/blob/76669e36572d9c6803a0e706214a9149d5247586/contracts/token/CVE.sol#L234-L251), [`ChildCVE#bridge`](https://github.com/curvance/Curvance-CantinaCompetition/blob/76669e36572d9c6803a0e706214a9149d5247586/contracts/token/ChildCVE.sol#L98-L113) and [`VeCVE#bridgeVeCVELock`](https://github.com/curvance/Curvance-CantinaCompetition/blob/76669e36572d9c6803a0e706214a9149d5247586/contracts/token/VeCVE.sol#L759-L813) can be replayed in the hard fork chain because the functions doesn't consider chain id if changed or not.

Although the possibility is low, but the effect is enormous, malicious users can gain lots of profit due to this issue. See omni bridge [vulnerability](https://neptunemutual.com/blog/decoding-omni-bridges-call-data-replay-exploit/) when Ethereum’s transition to the PoS chain.

**Recommendation**:

Consider check the chain id is the same with src chain id or not, reverted the bridge tx if chain is is not the same, you can see wormhole NttManager solution [here](https://github.com/wormhole-foundation/example-native-token-transfers/blob/cb57ed240bc4e986a144c6bc7e6b7e6fb3823cb5/evm/src/NttManager/NttManager.sol#L190C9-L190C31).


### <a name="m-04-malicious-users-can-open-many-small-positions-and-borrow-debt-liquidators-has-no-profit-to-liquidate-such-positions"></a> M-04 Malicious users can open many small positions and borrow debt, liquidators have no profit to liquidate such positions

**Description**:

Protocol have no limitation to minimum borrowable token currently, so any users can open many small positions and borrow debt. This protocol can be deployed on multiple chains including Ethernum, means the gas fee for liquidating the position maybe higher than the liquidation incentive, such that the positions maybe never be liquidated because liquidators won't be able to gain profits from the liquidation.

Malicious users can open many small positions and borrow high violation debt as much as possible in one tx, if the borrow debt price become higher, may cause bad debt to protocol.

**Recommendation**:

Protocol should have minimum borrow debt amount limitation to make liquidators have enough incentive to liquidate any user's position.


