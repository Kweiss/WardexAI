/**
 * Test Scenario: MetaMask Delegation Framework Integration
 *
 * Verifies that Wardex correctly maps SessionKeyConfig to MetaMask
 * Delegation Framework caveat enforcers, creates/validates delegations,
 * handles EIP-712 signing payloads, and manages delegation lifecycle.
 *
 * Test groups:
 * 1. Enforcer Mapping - ABI encoding of caveat terms
 * 2. Delegation Creation - struct generation, caveats, salt, expiration
 * 3. Transaction Validation - off-chain boundary checks (defense-in-depth)
 * 4. EIP-712 Signing Payload - domain, types, struct for external signing
 * 5. Revocation & Rotation - lifecycle management
 * 6. Edge Cases - zero values, empty arrays, strict mode
 */

import { describe, it, expect } from 'vitest';
import { AbiCoder } from 'ethers';
import {
  DelegationManager,
  mapSessionConfigToCaveats,
  getDefaultEnforcerAddresses,
  encodeAllowedTargets,
  encodeValueLte,
  encodeTimestamp,
  encodeNativeTokenPeriod,
  encodeBlockedApprovalMethods,
  decodeAllowedTargets,
  decodeValueLte,
  decodeTimestamp,
  decodeNativeTokenPeriod,
} from '@wardexai/signer';
import type {
  SessionKeyConfig,
  DelegationManagerConfig,
  EnforcerAddresses,
} from '@wardexai/signer';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const UNISWAP_ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const AAVE_POOL = '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2';
const RANDOM_CONTRACT = '0xdead000000000000000000000000000000000099';
const DELEGATOR = '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
const CHAIN_ID = 8453; // Base

const coder = new AbiCoder();

function createDefaultConfig(
  overrides?: Partial<SessionKeyConfig>,
): SessionKeyConfig {
  return {
    allowedContracts: [UNISWAP_ROUTER, AAVE_POOL],
    maxValuePerTx: '1000000000000000000', // 1 ETH
    maxDailyVolume: '5000000000000000000', // 5 ETH
    durationSeconds: 3600, // 1 hour
    forbidInfiniteApprovals: true,
    ...overrides,
  };
}

function createDefaultManagerConfig(
  overrides?: Partial<DelegationManagerConfig>,
): DelegationManagerConfig {
  return {
    chainId: CHAIN_ID,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// 1. Enforcer Mapping
// ---------------------------------------------------------------------------

describe('Enforcer Mapping - ABI Encoding', () => {
  it('should encode AllowedTargets correctly', () => {
    const terms = encodeAllowedTargets([UNISWAP_ROUTER, AAVE_POOL]);
    const decoded = decodeAllowedTargets(terms);

    expect(decoded).toHaveLength(2);
    expect(decoded[0]).toBe(UNISWAP_ROUTER.toLowerCase());
    expect(decoded[1]).toBe(AAVE_POOL.toLowerCase());
  });

  it('should handle single contract in AllowedTargets', () => {
    const terms = encodeAllowedTargets([UNISWAP_ROUTER]);
    const decoded = decodeAllowedTargets(terms);

    expect(decoded).toHaveLength(1);
    expect(decoded[0]).toBe(UNISWAP_ROUTER.toLowerCase());
  });

  it('should encode ValueLte correctly', () => {
    const maxWei = '1000000000000000000'; // 1 ETH
    const terms = encodeValueLte(maxWei);
    const decoded = decodeValueLte(terms);

    expect(decoded).toBe(maxWei);
  });

  it('should encode ValueLte with large values', () => {
    const maxWei = '115792089237316195423570985008687907853269984665640564039457584007913129639935'; // max uint256
    const terms = encodeValueLte(maxWei);
    const decoded = decodeValueLte(terms);

    expect(decoded).toBe(maxWei);
  });

  it('should encode Timestamp with valid deadline', () => {
    const before = Math.floor(Date.now() / 1000);
    const terms = encodeTimestamp(3600); // 1 hour
    const decoded = decodeTimestamp(terms);
    const after = Math.floor(Date.now() / 1000);

    expect(decoded.afterTimestamp).toBe(0);
    // beforeTimestamp should be between now+3600 and now+3600+1
    expect(decoded.beforeTimestamp).toBeGreaterThanOrEqual(before + 3600);
    expect(decoded.beforeTimestamp).toBeLessThanOrEqual(after + 3600 + 1);
  });

  it('should encode NativeTokenPeriod correctly', () => {
    const maxWei = '5000000000000000000'; // 5 ETH
    const terms = encodeNativeTokenPeriod(maxWei, 86400);
    const decoded = decodeNativeTokenPeriod(terms);

    expect(decoded.allowance).toBe(maxWei);
    expect(decoded.periodSeconds).toBe(86400);
  });

  it('should encode NativeTokenPeriod with custom period', () => {
    const terms = encodeNativeTokenPeriod('1000000000000000000', 3600);
    const decoded = decodeNativeTokenPeriod(terms);

    expect(decoded.periodSeconds).toBe(3600);
  });

  it('should encode blocked approval methods for strict mode', () => {
    const terms = encodeBlockedApprovalMethods();
    // Should be valid ABI encoding of bytes4[]
    expect(terms).toBeTruthy();
    expect(terms.startsWith('0x')).toBe(true);

    // Decode and verify allowed selectors
    const [selectors] = coder.decode(['bytes4[]'], terms);
    expect((selectors as string[]).length).toBe(5);
    // approve (0x095ea7b3) should NOT be in the list
    const selectorHexes = (selectors as string[]).map((s: string) =>
      s.toLowerCase(),
    );
    expect(selectorHexes).not.toContain('0x095ea7b3');
    expect(selectorHexes).not.toContain('0xa22cb465');
  });

  it('should return canonical enforcer addresses', () => {
    const addresses = getDefaultEnforcerAddresses();

    expect(addresses.allowedTargets).toBe(
      '0x7F20f61b1f09b08D970938F6fa563634d65c4EeB',
    );
    expect(addresses.valueLte).toBe(
      '0x92Bf12322527cAA612fd31a0e810472BBB106A8F',
    );
    expect(addresses.timestamp).toBe(
      '0x1046bb45C8d673d4ea75321280DB34899413c069',
    );
    expect(addresses.nativeTokenPeriodTransfer).toBe(
      '0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9',
    );
    expect(addresses.delegationManager).toBe(
      '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3',
    );
  });

  it('should map full SessionKeyConfig to caveats', () => {
    const config = createDefaultConfig();
    const caveats = mapSessionConfigToCaveats(config);
    const addresses = getDefaultEnforcerAddresses();

    // Should have 4 caveats: AllowedTargets, ValueLte, NativeTokenPeriod, Timestamp
    // (forbidInfiniteApprovals is off-chain by default)
    expect(caveats).toHaveLength(4);

    const enforcers = caveats.map((c) => c.enforcer);
    expect(enforcers).toContain(addresses.allowedTargets);
    expect(enforcers).toContain(addresses.valueLte);
    expect(enforcers).toContain(addresses.nativeTokenPeriodTransfer);
    expect(enforcers).toContain(addresses.timestamp);
  });

  it('should add AllowedMethodsEnforcer in strict mode', () => {
    const config = createDefaultConfig({ forbidInfiniteApprovals: true });
    const caveats = mapSessionConfigToCaveats(config, undefined, {
      strictInfiniteApprovalBlocking: true,
    });
    const addresses = getDefaultEnforcerAddresses();

    // Should have 5 caveats (includes AllowedMethods)
    expect(caveats).toHaveLength(5);
    const enforcers = caveats.map((c) => c.enforcer);
    expect(enforcers).toContain(addresses.allowedMethods);
  });

  it('should skip AllowedTargets when no contracts specified', () => {
    const config = createDefaultConfig({ allowedContracts: [] });
    const caveats = mapSessionConfigToCaveats(config);
    const addresses = getDefaultEnforcerAddresses();

    const enforcers = caveats.map((c) => c.enforcer);
    expect(enforcers).not.toContain(addresses.allowedTargets);
  });
});

// ---------------------------------------------------------------------------
// 2. Delegation Creation
// ---------------------------------------------------------------------------

describe('Delegation Creation', () => {
  it('should create a delegation with correct metadata', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const config = createDefaultConfig();
    const delegation = manager.createDelegation(config, DELEGATOR);

    expect(delegation.id).toBeTruthy();
    expect(delegation.delegate).toMatch(/^0x[0-9a-f]{40}$/);
    expect(delegation.delegator).toBe(DELEGATOR.toLowerCase());
    expect(delegation.authority).toBe(
      '0x0000000000000000000000000000000000000000000000000000000000000000',
    );
    expect(delegation.revoked).toBe(false);
    expect(delegation.signature).toBe('');
  });

  it('should generate unique delegation IDs', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const config = createDefaultConfig();
    const d1 = manager.createDelegation(config, DELEGATOR);
    const d2 = manager.createDelegation(config, DELEGATOR);

    expect(d1.id).not.toBe(d2.id);
    expect(d1.delegate).not.toBe(d2.delegate);
    expect(d1.salt).not.toBe(d2.salt);
  });

  it('should set correct expiration', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const config = createDefaultConfig({ durationSeconds: 7200 }); // 2 hours
    const before = Date.now();
    const delegation = manager.createDelegation(config, DELEGATOR);
    const after = Date.now();

    const expiresAt = new Date(delegation.expiresAt).getTime();
    expect(expiresAt).toBeGreaterThanOrEqual(before + 7200 * 1000);
    expect(expiresAt).toBeLessThanOrEqual(after + 7200 * 1000 + 100);
  });

  it('should map caveats from SessionKeyConfig', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const config = createDefaultConfig();
    const delegation = manager.createDelegation(config, DELEGATOR);

    // 4 caveats: AllowedTargets, ValueLte, NativeTokenPeriod, Timestamp
    expect(delegation.caveats.length).toBe(4);
    delegation.caveats.forEach((caveat) => {
      expect(caveat.enforcer).toMatch(/^0x[0-9a-fA-F]{40}$/);
      expect(caveat.terms).toBeTruthy();
    });
  });

  it('should normalize contract addresses to lowercase', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const config = createDefaultConfig({
      allowedContracts: ['0xABCD1234567890ABCDEF1234567890ABCDEF1234'],
    });
    const delegation = manager.createDelegation(config, DELEGATOR);

    expect(delegation.config.allowedContracts[0]).toBe(
      '0xabcd1234567890abcdef1234567890abcdef1234',
    );
  });

  it('should store the original config for off-chain validation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const config = createDefaultConfig();
    const delegation = manager.createDelegation(config, DELEGATOR);

    expect(delegation.config.maxValuePerTx).toBe(config.maxValuePerTx);
    expect(delegation.config.maxDailyVolume).toBe(config.maxDailyVolume);
    expect(delegation.config.durationSeconds).toBe(config.durationSeconds);
    expect(delegation.config.forbidInfiniteApprovals).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 3. Transaction Validation
// ---------------------------------------------------------------------------

describe('Delegation Transaction Validation', () => {
  function createSignedDelegation(
    manager: DelegationManager,
    config?: SessionKeyConfig,
  ) {
    const delegation = manager.createDelegation(
      config ?? createDefaultConfig(),
      DELEGATOR,
    );
    // Simulate signing
    manager.setSignature(delegation.id, '0x' + 'ab'.repeat(65));
    return delegation;
  }

  it('should approve valid in-scope transaction', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);

    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '100000000000000000', // 0.1 ETH
    );

    expect(result.valid).toBe(true);
  });

  it('should reject unsigned delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );

    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '100000000000000000',
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not been signed');
  });

  it('should reject out-of-scope contract', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);

    const result = manager.validateTransaction(
      delegation.id,
      RANDOM_CONTRACT,
      '100000000000000000',
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not in the allowed contracts');
  });

  it('should reject over-limit value', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);

    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '2000000000000000000', // 2 ETH > 1 ETH limit
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('exceeds per-tx limit');
  });

  it('should reject when daily volume exceeded', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);

    // Record 4.5 ETH of prior transactions
    manager.recordTransaction(delegation.id, '4500000000000000000');

    // Try 0.6 ETH more (total 5.1 > 5 ETH limit)
    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '600000000000000000',
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('daily volume limit');
  });

  it('should reject revoked delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);
    manager.revokeDelegation(delegation.id);

    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '100000000000000000',
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('revoked');
  });

  it('should reject expired delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(
      manager,
      createDefaultConfig({ durationSeconds: 0 }),
    );

    // Wait a tick for expiration
    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '100000000000000000',
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  it('should reject infinite token approval', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);

    // ERC-20 approve with max uint256
    const data =
      '0x095ea7b3' +
      '000000000000000000000000' +
      UNISWAP_ROUTER.slice(2) +
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '0',
      data,
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('Infinite token approval');
  });

  it('should reject setApprovalForAll', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = createSignedDelegation(manager);

    // setApprovalForAll(address, true)
    const data =
      '0xa22cb465' +
      '000000000000000000000000' +
      UNISWAP_ROUTER.slice(2) +
      '0000000000000000000000000000000000000000000000000000000000000001';

    const result = manager.validateTransaction(
      delegation.id,
      UNISWAP_ROUTER,
      '0',
      data,
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('setApprovalForAll');
  });

  it('should return not found for unknown delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());

    const result = manager.validateTransaction(
      'nonexistent-id',
      UNISWAP_ROUTER,
      '100000000000000000',
    );

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not found');
  });
});

// ---------------------------------------------------------------------------
// 4. EIP-712 Signing Payload
// ---------------------------------------------------------------------------

describe('EIP-712 Signing Payload', () => {
  it('should generate correct domain separator', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    const payload = manager.getSigningPayload(delegation.id);

    expect(payload).not.toBeNull();
    expect(payload!.domain.name).toBe('DelegationManager');
    expect(payload!.domain.version).toBe('1');
    expect(payload!.domain.chainId).toBe(CHAIN_ID);
    expect(payload!.domain.verifyingContract).toBe(
      '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3',
    );
  });

  it('should include Delegation and Caveat types', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    const payload = manager.getSigningPayload(delegation.id);

    expect(payload!.types.Delegation).toBeDefined();
    expect(payload!.types.Caveat).toBeDefined();
    expect(payload!.types.Delegation).toHaveLength(5); // delegate, delegator, authority, caveats, salt
    expect(payload!.types.Caveat).toHaveLength(2); // enforcer, terms
  });

  it('should include correct struct values', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    const payload = manager.getSigningPayload(delegation.id);

    expect(payload!.value.delegate).toBe(delegation.delegate);
    expect(payload!.value.delegator).toBe(delegation.delegator);
    expect(payload!.value.authority).toBe(delegation.authority);
    expect(payload!.value.salt).toBe(delegation.salt.toString());
    expect(payload!.value.caveats).toHaveLength(4);
  });

  it('should complete signing flow', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );

    // Verify unsigned
    expect(delegation.signature).toBe('');

    // Simulate external signing
    const mockSignature = '0x' + 'ab'.repeat(65);
    manager.setSignature(delegation.id, mockSignature);

    // Verify signed
    const updated = manager.getDelegation(delegation.id);
    expect(updated!.signature).toBe(mockSignature);
  });

  it('should reject signing revoked delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    manager.revokeDelegation(delegation.id);

    expect(() => {
      manager.setSignature(delegation.id, '0x' + 'ab'.repeat(65));
    }).toThrow('revoked');
  });

  it('should return null for unknown delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const payload = manager.getSigningPayload('nonexistent');

    expect(payload).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 5. Revocation & Rotation
// ---------------------------------------------------------------------------

describe('Delegation Revocation & Rotation', () => {
  it('should revoke a delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );

    const result = manager.revokeDelegation(delegation.id);
    expect(result).toBe(true);

    const revoked = manager.getDelegation(delegation.id);
    expect(revoked!.revoked).toBe(true);
  });

  it('should return false for revoking nonexistent delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const result = manager.revokeDelegation('nonexistent');
    expect(result).toBe(false);
  });

  it('should rotate a delegation with same config', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const original = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );

    const rotated = manager.rotateDelegation(original.id);

    expect(rotated).not.toBeNull();
    expect(rotated!.id).not.toBe(original.id);
    expect(rotated!.delegate).not.toBe(original.delegate);
    expect(rotated!.config.maxValuePerTx).toBe(original.config.maxValuePerTx);
    expect(rotated!.config.maxDailyVolume).toBe(original.config.maxDailyVolume);

    // Old delegation should be revoked
    const old = manager.getDelegation(original.id);
    expect(old!.revoked).toBe(true);
  });

  it('should return null when rotating nonexistent delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const result = manager.rotateDelegation('nonexistent');
    expect(result).toBeNull();
  });

  it('should list active delegations only', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const d1 = manager.createDelegation(createDefaultConfig(), DELEGATOR);
    const d2 = manager.createDelegation(createDefaultConfig(), DELEGATOR);
    const d3 = manager.createDelegation(createDefaultConfig(), DELEGATOR);

    manager.revokeDelegation(d2.id);

    const active = manager.getActiveDelegations();
    expect(active).toHaveLength(2);
    const activeIds = active.map((d) => d.id);
    expect(activeIds).toContain(d1.id);
    expect(activeIds).toContain(d3.id);
    expect(activeIds).not.toContain(d2.id);
  });

  it('should clean up expired and revoked delegations', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());

    // Create one normal and one immediately-expiring delegation
    manager.createDelegation(createDefaultConfig(), DELEGATOR);
    const expired = manager.createDelegation(
      createDefaultConfig({ durationSeconds: 0 }),
      DELEGATOR,
    );
    const revoked = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    manager.revokeDelegation(revoked.id);

    const removed = manager.cleanup();
    expect(removed).toBe(2);

    // Only the normal one should remain
    const active = manager.getActiveDelegations();
    expect(active).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 6. Edge Cases & Configuration
// ---------------------------------------------------------------------------

describe('Delegation Edge Cases', () => {
  it('should use custom enforcer addresses', () => {
    const customAddress = '0x1234567890123456789012345678901234567890';
    const manager = new DelegationManager(
      createDefaultManagerConfig({
        enforcerAddresses: { allowedTargets: customAddress },
      }),
    );

    const addresses = manager.getEnforcerAddresses();
    expect(addresses.allowedTargets).toBe(customAddress);
    // Other addresses should still be canonical
    expect(addresses.valueLte).toBe(
      '0x92Bf12322527cAA612fd31a0e810472BBB106A8F',
    );
  });

  it('should use custom DelegationManager address', () => {
    const customDM = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const manager = new DelegationManager(
      createDefaultManagerConfig({
        delegationManagerAddress: customDM,
      }),
    );

    const addresses = manager.getEnforcerAddresses();
    expect(addresses.delegationManager).toBe(customDM);
  });

  it('should use custom DelegationManager address in EIP-712 domain', () => {
    const customDM = '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const manager = new DelegationManager(
      createDefaultManagerConfig({
        delegationManagerAddress: customDM,
      }),
    );

    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    const payload = manager.getSigningPayload(delegation.id);

    expect(payload!.domain.verifyingContract).toBe(customDM);
  });

  it('should handle zero maxValuePerTx (no value caveat)', () => {
    const config = createDefaultConfig({ maxValuePerTx: '0' });
    const caveats = mapSessionConfigToCaveats(config);
    const addresses = getDefaultEnforcerAddresses();

    // ValueLte should NOT be present (zero value = no constraint)
    const enforcers = caveats.map((c) => c.enforcer);
    expect(enforcers).not.toContain(addresses.valueLte);
  });

  it('should handle zero durationSeconds (no timestamp caveat)', () => {
    const config = createDefaultConfig({ durationSeconds: 0 });
    const caveats = mapSessionConfigToCaveats(config);
    const addresses = getDefaultEnforcerAddresses();

    // Timestamp should NOT be present
    const enforcers = caveats.map((c) => c.enforcer);
    expect(enforcers).not.toContain(addresses.timestamp);
  });

  it('should prepare redemption calldata for signed delegation', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );
    manager.setSignature(delegation.id, '0x' + 'ab'.repeat(65));

    const redemption = manager.prepareRedemption(delegation.id, [
      {
        target: UNISWAP_ROUTER,
        value: 100000000000000000n,
        callData: '0x',
      },
    ]);

    expect(redemption).not.toBeNull();
    expect(redemption!.target).toBe(
      '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3',
    );
    expect(redemption!.value).toBe(100000000000000000n);
    expect(redemption!.calldata).toBeTruthy();
  });

  it('should return null for unsigned delegation redemption', () => {
    const manager = new DelegationManager(createDefaultManagerConfig());
    const delegation = manager.createDelegation(
      createDefaultConfig(),
      DELEGATOR,
    );

    const redemption = manager.prepareRedemption(delegation.id, []);
    expect(redemption).toBeNull();
  });
});
