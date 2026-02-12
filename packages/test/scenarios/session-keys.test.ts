/**
 * Test Scenario: ERC-7715 Session Key Management
 *
 * Verifies that session keys correctly enforce scoped boundaries:
 * - Allowed target contracts
 * - Per-transaction value limits
 * - Daily volume limits
 * - Session expiration
 * - Infinite approval blocking
 * - Session revocation and rotation
 */

import { describe, it, expect } from 'vitest';
import { SessionManager } from '@wardexai/signer';
import type { SessionKeyConfig } from '@wardexai/signer';

const UNISWAP_ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const AAVE_POOL = '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
const RANDOM_CONTRACT = '0xdead000000000000000000000000000000000099';

function createDefaultConfig(overrides?: Partial<SessionKeyConfig>): SessionKeyConfig {
  return {
    allowedContracts: [UNISWAP_ROUTER, AAVE_POOL],
    maxValuePerTx: '1000000000000000000', // 1 ETH
    maxDailyVolume: '5000000000000000000', // 5 ETH
    durationSeconds: 3600, // 1 hour
    forbidInfiniteApprovals: true,
    ...overrides,
  };
}

describe('Session Key - Creation & Basics', () => {
  it('should create a session key with correct config', () => {
    const manager = new SessionManager();
    const config = createDefaultConfig();
    const session = manager.createSession(config);

    expect(session.id).toBeTruthy();
    expect(session.address).toMatch(/^0x[0-9a-f]{40}$/);
    expect(session.revoked).toBe(false);
    expect(session.config.allowedContracts).toHaveLength(2);
    expect(new Date(session.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });

  it('should normalize contract addresses to lowercase', () => {
    const manager = new SessionManager();
    const config = createDefaultConfig({
      allowedContracts: ['0xABCD1234567890ABCDEF1234567890ABCDEF1234'],
    });
    const session = manager.createSession(config);

    expect(session.config.allowedContracts[0]).toBe(
      '0xabcd1234567890abcdef1234567890abcdef1234',
    );
  });

  it('should generate unique session IDs', () => {
    const manager = new SessionManager();
    const config = createDefaultConfig();
    const s1 = manager.createSession(config);
    const s2 = manager.createSession(config);

    expect(s1.id).not.toBe(s2.id);
    expect(s1.address).not.toBe(s2.address);
  });

  it('should retrieve session by ID', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());
    const retrieved = manager.getSession(session.id);

    expect(retrieved).toBeDefined();
    expect(retrieved!.id).toBe(session.id);
  });
});

describe('Session Key - Contract Allowlist', () => {
  it('should allow transactions to permitted contracts', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '100000000000000000', // 0.1 ETH
    );
    expect(result.valid).toBe(true);
  });

  it('should block transactions to non-allowed contracts', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    const result = manager.validateTransaction(
      session.id,
      RANDOM_CONTRACT,
      '100000000000000000',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not in the allowed contracts list');
  });

  it('should allow any contract when allowedContracts is empty', () => {
    const manager = new SessionManager();
    const session = manager.createSession(
      createDefaultConfig({ allowedContracts: [] }),
    );

    const result = manager.validateTransaction(
      session.id,
      RANDOM_CONTRACT,
      '100000000000000000',
    );
    expect(result.valid).toBe(true);
  });
});

describe('Session Key - Value Limits', () => {
  it('should allow transactions within per-tx limit', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '500000000000000000', // 0.5 ETH (under 1 ETH limit)
    );
    expect(result.valid).toBe(true);
  });

  it('should block transactions exceeding per-tx limit', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '2000000000000000000', // 2 ETH (over 1 ETH limit)
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('exceeds per-tx limit');
  });

  it('should track daily volume and block when exceeded', () => {
    const manager = new SessionManager();
    const session = manager.createSession(
      createDefaultConfig({
        maxValuePerTx: '3000000000000000000', // 3 ETH per tx
        maxDailyVolume: '5000000000000000000', // 5 ETH daily
      }),
    );

    // First tx: 2 ETH → allowed
    let result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '2000000000000000000',
    );
    expect(result.valid).toBe(true);
    manager.recordTransaction(session.id, '2000000000000000000', UNISWAP_ROUTER);

    // Second tx: 2 ETH → total 4 ETH → allowed
    result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '2000000000000000000',
    );
    expect(result.valid).toBe(true);
    manager.recordTransaction(session.id, '2000000000000000000', UNISWAP_ROUTER);

    // Third tx: 2 ETH → total would be 6 ETH → over 5 ETH limit
    result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '2000000000000000000',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('daily volume limit');
  });

  it('should handle zero-value transactions', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '0',
    );
    expect(result.valid).toBe(true);
  });
});

describe('Session Key - Infinite Approval Blocking', () => {
  it('should block infinite ERC-20 approvals when forbidden', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    // approve(address, type(uint256).max)
    const infiniteApprovalData =
      '0x095ea7b3' +
      '000000000000000000000000dead000000000000000000000000000000000001' +
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '0',
      infiniteApprovalData,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Infinite token approval');
  });

  it('should allow finite approvals', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    // approve(address, 1000 * 10^18)
    const finiteApprovalData =
      '0x095ea7b3' +
      '000000000000000000000000dead000000000000000000000000000000000001' +
      '00000000000000000000000000000000000000000000003635c9adc5dea00000'; // 1000e18

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '0',
      finiteApprovalData,
    );
    expect(result.valid).toBe(true);
  });

  it('should block setApprovalForAll when forbidden', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    // setApprovalForAll(address, true)
    const approvalForAllData =
      '0xa22cb465' +
      '000000000000000000000000dead000000000000000000000000000000000001' +
      '0000000000000000000000000000000000000000000000000000000000000001';

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '0',
      approvalForAllData,
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('setApprovalForAll');
  });

  it('should allow infinite approvals when not forbidden', () => {
    const manager = new SessionManager();
    const session = manager.createSession(
      createDefaultConfig({ forbidInfiniteApprovals: false }),
    );

    const infiniteApprovalData =
      '0x095ea7b3' +
      '000000000000000000000000dead000000000000000000000000000000000001' +
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '0',
      infiniteApprovalData,
    );
    expect(result.valid).toBe(true);
  });
});

describe('Session Key - Expiration', () => {
  it('should reject transactions on expired sessions', () => {
    const manager = new SessionManager();
    // Create a session that expires immediately (0 seconds)
    const session = manager.createSession(
      createDefaultConfig({ durationSeconds: 0 }),
    );

    // Tiny delay to ensure expiration
    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '100000000000000000',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  it('should list active sessions only', () => {
    const manager = new SessionManager();

    // Active session (1 hour)
    manager.createSession(createDefaultConfig({ durationSeconds: 3600 }));

    // Expired session (0 seconds)
    manager.createSession(createDefaultConfig({ durationSeconds: 0 }));

    const active = manager.getActiveSessions();
    expect(active).toHaveLength(1);
  });

  it('should find sessions expiring soon', () => {
    const manager = new SessionManager();

    // Expires in 30 seconds
    manager.createSession(createDefaultConfig({ durationSeconds: 30 }));

    // Expires in 2 hours
    manager.createSession(createDefaultConfig({ durationSeconds: 7200 }));

    const expiringSoon = manager.getExpiringSessionsSoon(60); // within 60 seconds
    expect(expiringSoon).toHaveLength(1);
  });
});

describe('Session Key - Revocation', () => {
  it('should revoke a session', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    expect(manager.revokeSession(session.id)).toBe(true);

    const retrieved = manager.getSession(session.id);
    expect(retrieved!.revoked).toBe(true);
  });

  it('should reject transactions on revoked sessions', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    manager.revokeSession(session.id);

    const result = manager.validateTransaction(
      session.id,
      UNISWAP_ROUTER,
      '100000000000000000',
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('revoked');
  });

  it('should return false when revoking non-existent session', () => {
    const manager = new SessionManager();
    expect(manager.revokeSession('non-existent-id')).toBe(false);
  });
});

describe('Session Key - Rotation', () => {
  it('should rotate a session (revoke old + create new with same config)', () => {
    const manager = new SessionManager();
    const original = manager.createSession(createDefaultConfig());
    const rotated = manager.rotateSession(original.id);

    expect(rotated).not.toBeNull();
    expect(rotated!.id).not.toBe(original.id);
    expect(rotated!.address).not.toBe(original.address);

    // Old session should be revoked
    const oldSession = manager.getSession(original.id);
    expect(oldSession!.revoked).toBe(true);

    // New session should have same config
    expect(rotated!.config.allowedContracts).toEqual(original.config.allowedContracts);
    expect(rotated!.config.maxValuePerTx).toBe(original.config.maxValuePerTx);
    expect(rotated!.config.maxDailyVolume).toBe(original.config.maxDailyVolume);
  });

  it('should return null when rotating non-existent session', () => {
    const manager = new SessionManager();
    expect(manager.rotateSession('non-existent')).toBeNull();
  });
});

describe('Session Key - Cleanup', () => {
  it('should clean up expired and revoked sessions', () => {
    const manager = new SessionManager();

    // Active session
    manager.createSession(createDefaultConfig({ durationSeconds: 3600 }));

    // Expired sessions
    manager.createSession(createDefaultConfig({ durationSeconds: 0 }));
    manager.createSession(createDefaultConfig({ durationSeconds: 0 }));

    // Revoked session
    const toRevoke = manager.createSession(createDefaultConfig());
    manager.revokeSession(toRevoke.id);

    const removed = manager.cleanup();

    // 2 expired + 1 revoked = 3 removed
    expect(removed).toBe(3);
    expect(manager.getActiveSessions()).toHaveLength(1);
  });
});

describe('Session Key - State Tracking', () => {
  it('should track transaction count and contracts used', () => {
    const manager = new SessionManager();
    const session = manager.createSession(createDefaultConfig());

    manager.recordTransaction(session.id, '100000000000000000', UNISWAP_ROUTER);
    manager.recordTransaction(session.id, '200000000000000000', AAVE_POOL);
    manager.recordTransaction(session.id, '50000000000000000', UNISWAP_ROUTER);

    const state = manager.getSessionState(session.id);
    expect(state).toBeDefined();
    expect(state!.transactionCount).toBe(3);
    expect(state!.contractsUsed.size).toBe(2);
    expect(state!.dailyVolumeWei).toBe(350000000000000000n);
  });
});
