/**
 * Wardex Delegation Framework Example
 *
 * Demonstrates integrating MetaMask's Delegation Framework with Wardex
 * for defense-in-depth on-chain enforcement:
 *
 * 1. Create a delegation with scoped caveats (mapped from SessionKeyConfig)
 * 2. Owner signs the EIP-712 payload externally (Wardex never holds keys)
 * 3. Agent validates transactions through both Wardex SDK and delegation
 * 4. Prepare redemption calldata for on-chain execution
 * 5. Rotate delegations without disrupting operations
 *
 * The MetaMask Delegation Framework enforces constraints on-chain via
 * caveat enforcers. Even if the off-chain Wardex SDK is bypassed, the
 * smart contract layer rejects out-of-scope transactions.
 */

import { createWardex, defaultPolicy } from '@wardexai/core';
import type { TransactionRequest } from '@wardexai/core';
import { DelegationManager } from '@wardexai/signer';
import type { SessionKeyConfig } from '@wardexai/signer';

const UNISWAP_ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const AAVE_POOL = '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2';
const OWNER_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const CHAIN_ID = 8453; // Base

async function main() {
  // -----------------------------------------------------------------------
  // 1. Set up Wardex Shield
  // -----------------------------------------------------------------------

  const policy = defaultPolicy();
  policy.allowlists.contracts.push(UNISWAP_ROUTER, AAVE_POOL);
  policy.behavioral.enabled = true;

  const wardex = createWardex({
    policy,
    signer: { type: 'isolated-process', endpoint: '/tmp/delegation-agent.sock' },
    mode: 'adaptive',
    onBlock: (e) => console.log(`[WARDEX BLOCKED] ${e.verdict.reasons[0]?.message}`),
    onFreeze: (e) => console.log(`[WARDEX FREEZE] ${e.reason}`),
  });

  // -----------------------------------------------------------------------
  // 2. Create DelegationManager
  // -----------------------------------------------------------------------

  const delegationMgr = new DelegationManager({
    chainId: CHAIN_ID,
    // Uses canonical MetaMask v1.3.0 enforcer addresses by default
    // Uncomment for strict mode (blocks approve/setApprovalForAll at enforcer level):
    // strictInfiniteApprovalBlocking: true,
  });

  // -----------------------------------------------------------------------
  // 3. Create a delegation with scoped boundaries
  // -----------------------------------------------------------------------

  const sessionConfig: SessionKeyConfig = {
    allowedContracts: [UNISWAP_ROUTER, AAVE_POOL],
    maxValuePerTx: '1000000000000000000',   // 1 ETH
    maxDailyVolume: '5000000000000000000',   // 5 ETH
    durationSeconds: 3600,                    // 1 hour
    forbidInfiniteApprovals: true,
  };

  const delegation = delegationMgr.createDelegation(sessionConfig, OWNER_ADDRESS);
  console.log(`[DELEGATION] Created: ${delegation.id}`);
  console.log(`[DELEGATION] Delegate: ${delegation.delegate}`);
  console.log(`[DELEGATION] Caveats: ${delegation.caveats.length} enforcers`);
  console.log(`[DELEGATION] Expires: ${delegation.expiresAt}`);

  // -----------------------------------------------------------------------
  // 4. Get EIP-712 payload for owner to sign
  // -----------------------------------------------------------------------

  const signingPayload = delegationMgr.getSigningPayload(delegation.id);
  console.log(`\n[SIGNING] Domain: ${signingPayload!.domain.name} v${signingPayload!.domain.version}`);
  console.log(`[SIGNING] Chain: ${signingPayload!.domain.chainId}`);
  console.log(`[SIGNING] Contract: ${signingPayload!.domain.verifyingContract}`);

  // In production, the owner signs with their wallet:
  //   const signature = await ownerWallet.signTypedData(
  //     signingPayload.domain,
  //     signingPayload.types,
  //     signingPayload.value
  //   );

  // For this example, simulate a signature:
  const mockSignature = '0x' + 'ab'.repeat(65);
  delegationMgr.setSignature(delegation.id, mockSignature);
  console.log(`[SIGNING] Delegation signed successfully`);

  // -----------------------------------------------------------------------
  // 5. Double-check: Wardex + Delegation validation
  // -----------------------------------------------------------------------

  console.log(`\n--- Transaction Evaluation ---`);

  const tx: TransactionRequest = {
    to: UNISWAP_ROUTER,
    value: '500000000000000000', // 0.5 ETH
    chainId: CHAIN_ID,
  };

  // Layer 1: Wardex risk evaluation
  const verdict = await wardex.evaluate(tx);
  console.log(`[WARDEX] Decision: ${verdict.decision}`);
  console.log(`[WARDEX] Risk score: ${verdict.riskScore.composite}`);

  // Layer 2: Delegation boundary check (off-chain)
  const delegationCheck = delegationMgr.validateTransaction(
    delegation.id,
    tx.to,
    tx.value!,
  );
  console.log(`[DELEGATION] Valid: ${delegationCheck.valid}`);

  // Layer 3: On-chain enforcers (when tx is submitted, contracts verify caveats)
  if (verdict.decision === 'approve' && delegationCheck.valid) {
    console.log(`[RESULT] Transaction approved by all layers`);

    // Prepare on-chain redemption calldata
    const redemption = delegationMgr.prepareRedemption(delegation.id, [
      {
        target: tx.to,
        value: BigInt(tx.value!),
        callData: tx.data ?? '0x',
      },
    ]);

    console.log(`[ON-CHAIN] Redemption target: ${redemption!.target}`);
    console.log(`[ON-CHAIN] Calldata length: ${redemption!.calldata.length} chars`);

    // Record the transaction
    delegationMgr.recordTransaction(delegation.id, tx.value!);
  } else {
    console.log(`[RESULT] Transaction BLOCKED`);
    if (verdict.decision !== 'approve') {
      console.log(`  Wardex reasons: ${verdict.reasons.map(r => r.message).join('; ')}`);
    }
    if (!delegationCheck.valid) {
      console.log(`  Delegation reason: ${delegationCheck.reason}`);
    }
  }

  // -----------------------------------------------------------------------
  // 6. Attack simulation: out-of-scope target
  // -----------------------------------------------------------------------

  console.log(`\n--- Attack Simulation ---`);

  const attackTx: TransactionRequest = {
    to: '0xdead000000000000000000000000000000000001',
    value: '500000000000000000',
    chainId: CHAIN_ID,
  };

  const attackVerdict = await wardex.evaluate(attackTx);
  const attackDelegation = delegationMgr.validateTransaction(
    delegation.id,
    attackTx.to,
    attackTx.value!,
  );

  console.log(`[WARDEX] Decision: ${attackVerdict.decision}`);
  console.log(`[DELEGATION] Valid: ${attackDelegation.valid}`);
  console.log(`[DELEGATION] Reason: ${attackDelegation.reason}`);
  console.log(`[RESULT] Attack blocked by delegation scope enforcement`);

  // -----------------------------------------------------------------------
  // 7. Delegation rotation
  // -----------------------------------------------------------------------

  console.log(`\n--- Delegation Rotation ---`);

  const rotated = delegationMgr.rotateDelegation(delegation.id);
  console.log(`[ROTATION] Old delegation revoked: ${delegation.id}`);
  console.log(`[ROTATION] New delegation created: ${rotated!.id}`);
  console.log(`[ROTATION] Same config: ${rotated!.config.maxValuePerTx === sessionConfig.maxValuePerTx}`);

  // Sign the new delegation
  delegationMgr.setSignature(rotated!.id, '0x' + 'cd'.repeat(65));

  // Old delegation is now invalid
  const oldCheck = delegationMgr.validateTransaction(
    delegation.id,
    UNISWAP_ROUTER,
    '100000000000000000',
  );
  console.log(`[ROTATION] Old delegation valid: ${oldCheck.valid} (${oldCheck.reason})`);

  // New delegation works
  const newCheck = delegationMgr.validateTransaction(
    rotated!.id,
    UNISWAP_ROUTER,
    '100000000000000000',
  );
  console.log(`[ROTATION] New delegation valid: ${newCheck.valid}`);

  // -----------------------------------------------------------------------
  // 8. Enforcer addresses for reference
  // -----------------------------------------------------------------------

  console.log(`\n--- Enforcer Addresses ---`);
  const addresses = delegationMgr.getEnforcerAddresses();
  console.log(`  DelegationManager: ${addresses.delegationManager}`);
  console.log(`  AllowedTargets: ${addresses.allowedTargets}`);
  console.log(`  ValueLte: ${addresses.valueLte}`);
  console.log(`  NativeTokenPeriod: ${addresses.nativeTokenPeriodTransfer}`);
  console.log(`  Timestamp: ${addresses.timestamp}`);
  console.log(`  AllowedMethods: ${addresses.allowedMethods}`);

  // Cleanup
  const removed = delegationMgr.cleanup();
  console.log(`\n[CLEANUP] Removed ${removed} expired/revoked delegations`);

  const status = wardex.getStatus();
  console.log(`[STATUS] Evaluations: ${status.evaluationCount}, Blocks: ${status.blockCount}`);
}

main().catch(console.error);
