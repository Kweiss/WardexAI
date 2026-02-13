import { describe, it, expect } from 'vitest';
import { Wallet } from 'ethers';
import {
  SessionManager,
  DelegationManager,
} from '@wardexai/signer';
import type { SessionKeyConfig } from '@wardexai/signer';

const CHAIN_ID = 8453;
const DELEGATOR = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const DELEGATOR_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const ALLOWED_A = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const ALLOWED_B = '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2';
const DENIED = '0xdead000000000000000000000000000000000099';

function baseConfig(overrides?: Partial<SessionKeyConfig>): SessionKeyConfig {
  return {
    allowedContracts: [ALLOWED_A, ALLOWED_B],
    maxValuePerTx: '1000000000000000000', // 1 ETH
    maxDailyVolume: '3000000000000000000', // 3 ETH
    durationSeconds: 3600,
    forbidInfiniteApprovals: true,
    ...overrides,
  };
}

async function signDelegation(
  manager: DelegationManager,
  delegationId: string,
): Promise<string> {
  const payload = manager.getSigningPayload(delegationId);
  if (!payload) throw new Error(`Delegation ${delegationId} not found`);
  const wallet = new Wallet(DELEGATOR_PRIVATE_KEY);
  return wallet.signTypedData(payload.domain, payload.types, payload.value);
}

async function createParityPair(config: SessionKeyConfig) {
  const sessionMgr = new SessionManager();
  const delegationMgr = new DelegationManager({ chainId: CHAIN_ID });

  const session = sessionMgr.createSession(config);
  const delegation = delegationMgr.createDelegation(config, DELEGATOR);
  delegationMgr.setSignature(delegation.id, await signDelegation(delegationMgr, delegation.id));

  return { sessionMgr, delegationMgr, session, delegation };
}

describe('Session vs Delegation Parity', () => {
  it('should allow the same in-scope transaction', async () => {
    const { sessionMgr, delegationMgr, session, delegation } =
      await createParityPair(baseConfig());

    const s = sessionMgr.validateTransaction(session.id, ALLOWED_A, '100000000000000000');
    const d = delegationMgr.validateTransaction(delegation.id, ALLOWED_A, '100000000000000000');

    expect(s.valid).toBe(true);
    expect(d.valid).toBe(true);
  });

  it('should reject out-of-scope targets in both managers', async () => {
    const { sessionMgr, delegationMgr, session, delegation } =
      await createParityPair(baseConfig());

    const s = sessionMgr.validateTransaction(session.id, DENIED, '100000000000000000');
    const d = delegationMgr.validateTransaction(delegation.id, DENIED, '100000000000000000');

    expect(s.valid).toBe(false);
    expect(d.valid).toBe(false);
    expect(s.reason).toContain('allowed contracts');
    expect(d.reason).toContain('allowed contracts');
  });

  it('should enforce per-transaction value limit equally', async () => {
    const { sessionMgr, delegationMgr, session, delegation } =
      await createParityPair(baseConfig());

    const s = sessionMgr.validateTransaction(session.id, ALLOWED_A, '2000000000000000000');
    const d = delegationMgr.validateTransaction(delegation.id, ALLOWED_A, '2000000000000000000');

    expect(s.valid).toBe(false);
    expect(d.valid).toBe(false);
    expect(s.reason).toContain('per-tx limit');
    expect(d.reason).toContain('per-tx limit');
  });

  it('should enforce daily volume limit equally after recording usage', async () => {
    const { sessionMgr, delegationMgr, session, delegation } =
      await createParityPair(baseConfig());

    sessionMgr.recordTransaction(session.id, '2500000000000000000', ALLOWED_A);
    delegationMgr.recordTransaction(delegation.id, '2500000000000000000');

    const s = sessionMgr.validateTransaction(session.id, ALLOWED_A, '600000000000000000');
    const d = delegationMgr.validateTransaction(delegation.id, ALLOWED_A, '600000000000000000');

    expect(s.valid).toBe(false);
    expect(d.valid).toBe(false);
    expect(s.reason).toContain('daily volume limit');
    expect(d.reason).toContain('daily volume limit');
  });

  it('should block infinite approvals in both managers', async () => {
    const { sessionMgr, delegationMgr, session, delegation } =
      await createParityPair(baseConfig());

    const approveData =
      '0x095ea7b3' +
      '000000000000000000000000' +
      ALLOWED_A.slice(2) +
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const s = sessionMgr.validateTransaction(session.id, ALLOWED_A, '0', approveData);
    const d = delegationMgr.validateTransaction(delegation.id, ALLOWED_A, '0', approveData);

    expect(s.valid).toBe(false);
    expect(d.valid).toBe(false);
    expect(s.reason).toContain('Infinite token approval');
    expect(d.reason).toContain('Infinite token approval');
  });
});

describe('Rotation / Revocation / Expiry Edge Cases', () => {
  it('should reject old credentials immediately after rotation and allow new ones', async () => {
    const config = baseConfig();
    const sessionMgr = new SessionManager();
    const delegationMgr = new DelegationManager({ chainId: CHAIN_ID });

    const session = sessionMgr.createSession(config);
    const delegation = delegationMgr.createDelegation(config, DELEGATOR);
    delegationMgr.setSignature(delegation.id, await signDelegation(delegationMgr, delegation.id));

    const rotatedSession = sessionMgr.rotateSession(session.id);
    const rotatedDelegation = delegationMgr.rotateDelegation(delegation.id);
    expect(rotatedSession).not.toBeNull();
    expect(rotatedDelegation).not.toBeNull();
    delegationMgr.setSignature(
      rotatedDelegation!.id,
      await signDelegation(delegationMgr, rotatedDelegation!.id),
    );

    const oldSessionCheck = sessionMgr.validateTransaction(session.id, ALLOWED_A, '1');
    const oldDelegationCheck = delegationMgr.validateTransaction(delegation.id, ALLOWED_A, '1');
    expect(oldSessionCheck.valid).toBe(false);
    expect(oldDelegationCheck.valid).toBe(false);
    expect(oldSessionCheck.reason).toContain('revoked');
    expect(oldDelegationCheck.reason).toContain('revoked');

    const newSessionCheck = sessionMgr.validateTransaction(rotatedSession!.id, ALLOWED_A, '1');
    const newDelegationCheck = delegationMgr.validateTransaction(rotatedDelegation!.id, ALLOWED_A, '1');
    expect(newSessionCheck.valid).toBe(true);
    expect(newDelegationCheck.valid).toBe(true);
  });

  it('should enforce immediate expiry consistently', async () => {
    const { sessionMgr, delegationMgr, session, delegation } =
      await createParityPair(baseConfig({ durationSeconds: 0 }));

    const s = sessionMgr.validateTransaction(session.id, ALLOWED_A, '1');
    const d = delegationMgr.validateTransaction(delegation.id, ALLOWED_A, '1');

    expect(s.valid).toBe(false);
    expect(d.valid).toBe(false);
    expect(s.reason).toContain('expired');
    expect(d.reason).toContain('expired');
  });
});
