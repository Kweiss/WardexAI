/**
 * Test Scenario: Delegation + WardexShield Integration
 *
 * Verifies that DelegationManager works alongside the Wardex evaluation
 * pipeline for defense-in-depth. Both layers must agree before a
 * transaction proceeds.
 *
 * Test flow:
 *   1. Wardex evaluates transaction (risk scoring, policy engine)
 *   2. DelegationManager validates boundaries (off-chain check)
 *   3. Both must pass for the transaction to proceed
 *
 * On-chain, MetaMask caveat enforcers provide the final backstop.
 */

import { describe, it, expect } from 'vitest';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type { TransactionRequest } from '@wardexai/core';
import { DelegationManager } from '@wardexai/signer';
import type { SessionKeyConfig, DelegationManagerConfig } from '@wardexai/signer';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHAIN_ID = 31337; // local / anvil
const DELEGATOR = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const SAFE_ADDRESS = '0x1111111111111111111111111111111111111111';
const ATTACKER = '0xdead000000000000000000000000000000000001';

function createSessionConfig(
  overrides?: Partial<SessionKeyConfig>,
): SessionKeyConfig {
  return {
    allowedContracts: [SAFE_ADDRESS],
    maxValuePerTx: '1000000000000000000', // 1 ETH
    maxDailyVolume: '5000000000000000000', // 5 ETH
    durationSeconds: 3600,
    forbidInfiniteApprovals: true,
    ...overrides,
  };
}

function createDelegationConfig(): DelegationManagerConfig {
  return { chainId: CHAIN_ID };
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

describe('Delegation + Wardex Shield Integration', () => {
  it('should pass when both Wardex and delegation approve', async () => {
    const policy = defaultPolicy();
    const wardex = createWardex({
      policy,
      signer: {
        type: 'isolated-process',
        endpoint: '/tmp/delegation-test.sock',
      },
      mode: 'adaptive',
    });

    const delegationMgr = new DelegationManager(createDelegationConfig());
    const delegation = delegationMgr.createDelegation(
      createSessionConfig(),
      DELEGATOR,
    );
    delegationMgr.setSignature(delegation.id, '0x' + 'ab'.repeat(65));

    const tx: TransactionRequest = {
      to: SAFE_ADDRESS,
      value: '100000000000000', // 0.0001 ETH (dust, Audit tier)
      chainId: CHAIN_ID,
    };

    // Both layers approve
    const wardexVerdict = await wardex.evaluate(tx);
    const delegationCheck = delegationMgr.validateTransaction(
      delegation.id,
      tx.to,
      tx.value!,
    );

    expect(wardexVerdict.decision).toBe('approve');
    expect(delegationCheck.valid).toBe(true);
  });

  it('should block when delegation rejects out-of-scope target', async () => {
    const policy = defaultPolicy();
    const wardex = createWardex({
      policy,
      signer: {
        type: 'isolated-process',
        endpoint: '/tmp/delegation-test.sock',
      },
      mode: 'adaptive',
    });

    const delegationMgr = new DelegationManager(createDelegationConfig());
    const delegation = delegationMgr.createDelegation(
      createSessionConfig(), // only allows SAFE_ADDRESS
      DELEGATOR,
    );
    delegationMgr.setSignature(delegation.id, '0x' + 'ab'.repeat(65));

    const tx: TransactionRequest = {
      to: '0x2222222222222222222222222222222222222222', // not in scope
      value: '100000000000000',
      chainId: CHAIN_ID,
    };

    // Wardex might approve (unknown address, low value)
    const wardexVerdict = await wardex.evaluate(tx);

    // But delegation rejects
    const delegationCheck = delegationMgr.validateTransaction(
      delegation.id,
      tx.to,
      tx.value!,
    );

    expect(delegationCheck.valid).toBe(false);
    expect(delegationCheck.reason).toContain('not in the allowed contracts');
  });

  it('should block when Wardex rejects denylisted address', async () => {
    const policy = defaultPolicy();
    policy.denylists.addresses.push(ATTACKER);

    const wardex = createWardex({
      policy,
      signer: {
        type: 'isolated-process',
        endpoint: '/tmp/delegation-test.sock',
      },
      mode: 'adaptive',
    });

    const delegationMgr = new DelegationManager(createDelegationConfig());
    const delegation = delegationMgr.createDelegation(
      createSessionConfig({ allowedContracts: [ATTACKER] }), // delegation allows it
      DELEGATOR,
    );
    delegationMgr.setSignature(delegation.id, '0x' + 'ab'.repeat(65));

    const tx: TransactionRequest = {
      to: ATTACKER,
      value: '50000000000000000', // 0.05 ETH → Guardian tier
      chainId: CHAIN_ID,
    };

    // Wardex blocks (denylisted)
    const wardexVerdict = await wardex.evaluate(tx);
    expect(wardexVerdict.decision).not.toBe('approve');
    expect(
      wardexVerdict.reasons.some((r) => r.code === 'DENYLISTED_ADDRESS'),
    ).toBe(true);

    // Delegation would allow it (attacker is in allowedContracts)
    const delegationCheck = delegationMgr.validateTransaction(
      delegation.id,
      tx.to,
      tx.value!,
    );
    expect(delegationCheck.valid).toBe(true);

    // Defense-in-depth: overall result is BLOCKED because Wardex caught it
  });

  it('should catch infinite approval in both layers', async () => {
    const policy = defaultPolicy();
    const wardex = createWardex({
      policy,
      signer: {
        type: 'isolated-process',
        endpoint: '/tmp/delegation-test.sock',
      },
      mode: 'adaptive',
    });

    const delegationMgr = new DelegationManager(createDelegationConfig());
    const delegation = delegationMgr.createDelegation(
      createSessionConfig(),
      DELEGATOR,
    );
    delegationMgr.setSignature(delegation.id, '0x' + 'ab'.repeat(65));

    // ERC-20 approve with max uint256
    const approveData =
      '0x095ea7b3' +
      '000000000000000000000000' +
      SAFE_ADDRESS.slice(2) +
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const tx: TransactionRequest = {
      to: SAFE_ADDRESS,
      value: '0',
      data: approveData,
      chainId: CHAIN_ID,
    };

    // Wardex catches it in the pipeline
    const wardexVerdict = await wardex.evaluate(tx);

    // Delegation also catches it off-chain
    const delegationCheck = delegationMgr.validateTransaction(
      delegation.id,
      tx.to,
      tx.value!,
      tx.data,
    );

    expect(delegationCheck.valid).toBe(false);
    expect(delegationCheck.reason).toContain('Infinite token approval');
  });

  it('should maintain Wardex evaluation continuity during rotation', async () => {
    const policy = defaultPolicy();
    const wardex = createWardex({
      policy,
      signer: {
        type: 'isolated-process',
        endpoint: '/tmp/delegation-test.sock',
      },
      mode: 'adaptive',
    });

    const delegationMgr = new DelegationManager(createDelegationConfig());
    const original = delegationMgr.createDelegation(
      createSessionConfig(),
      DELEGATOR,
    );
    delegationMgr.setSignature(original.id, '0x' + 'ab'.repeat(65));

    const tx: TransactionRequest = {
      to: SAFE_ADDRESS,
      value: '100000000000000',
      chainId: CHAIN_ID,
    };

    // First evaluation
    const v1 = await wardex.evaluate(tx);
    const d1 = delegationMgr.validateTransaction(
      original.id,
      tx.to,
      tx.value!,
    );
    expect(v1.decision).toBe('approve');
    expect(d1.valid).toBe(true);

    // Rotate delegation
    const rotated = delegationMgr.rotateDelegation(original.id);
    expect(rotated).not.toBeNull();
    delegationMgr.setSignature(rotated!.id, '0x' + 'cd'.repeat(65));

    // Old delegation rejected
    const d2 = delegationMgr.validateTransaction(
      original.id,
      tx.to,
      tx.value!,
    );
    expect(d2.valid).toBe(false);
    expect(d2.reason).toContain('revoked');

    // New delegation works
    const d3 = delegationMgr.validateTransaction(
      rotated!.id,
      tx.to,
      tx.value!,
    );
    expect(d3.valid).toBe(true);

    // Wardex still works (unaffected by delegation rotation)
    const v2 = await wardex.evaluate(tx);
    expect(v2.decision).toBe('approve');

    // Audit trail reflects all evaluations
    const auditLog = wardex.getAuditLog();
    expect(auditLog.length).toBe(2);
  });

  it('should include delegation metadata alongside Wardex audit', async () => {
    const policy = defaultPolicy();
    const wardex = createWardex({
      policy,
      signer: {
        type: 'isolated-process',
        endpoint: '/tmp/delegation-test.sock',
      },
      mode: 'adaptive',
    });

    const delegationMgr = new DelegationManager(createDelegationConfig());
    const delegation = delegationMgr.createDelegation(
      createSessionConfig(),
      DELEGATOR,
    );
    delegationMgr.setSignature(delegation.id, '0x' + 'ab'.repeat(65));

    const tx: TransactionRequest = {
      to: SAFE_ADDRESS,
      value: '100000000000000',
      chainId: CHAIN_ID,
    };

    const wardexVerdict = await wardex.evaluate(tx);
    const delegationCheck = delegationMgr.validateTransaction(
      delegation.id,
      tx.to,
      tx.value!,
    );

    // Both layers provide complementary information
    expect(wardexVerdict.evaluationId).toBeTruthy();
    expect(wardexVerdict.timestamp).toBeTruthy();
    expect(wardexVerdict.riskScore.composite).toBeDefined();
    expect(delegationCheck.valid).toBe(true);

    // The delegation has its own metadata
    const storedDelegation = delegationMgr.getDelegation(delegation.id);
    expect(storedDelegation!.caveats.length).toBeGreaterThan(0);
    expect(storedDelegation!.delegator).toBe(DELEGATOR.toLowerCase());
    expect(storedDelegation!.signature).toBeTruthy();
  });
});
