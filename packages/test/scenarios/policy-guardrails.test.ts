import { describe, it, expect } from 'vitest';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type { SecurityPolicy } from '@wardexai/core';

function createTestWardex(policyOverrides?: Partial<SecurityPolicy>) {
  const policy = defaultPolicy();
  if (policyOverrides) {
    Object.assign(policy, policyOverrides);
  }
  return createWardex({
    policy,
    signer: { type: 'isolated-process', endpoint: '/tmp/test-signer.sock' },
    mode: 'adaptive',
  });
}

describe('Policy Guardrails', () => {
  it('should reject empty tier override', () => {
    const wardex = createTestWardex();
    expect(() => wardex.updatePolicy({ tiers: [] })).toThrow(/at least one security tier/i);
  });

  it('should reject tier overrides without guardian/fortress blocking tiers', () => {
    const wardex = createTestWardex();
    const nonBlockingTiers = [
      {
        id: 'audit-only',
        name: 'Audit Only',
        triggers: { minValueAtRiskUsd: 0 },
        enforcement: {
          mode: 'audit' as const,
          blockThreshold: 100,
          requireHumanApproval: false,
          notifyOperator: false,
          requireOnChainProof: false,
        },
      },
    ];

    expect(() => wardex.updatePolicy({ tiers: nonBlockingTiers })).toThrow(/blocking tier/i);
  });
});
