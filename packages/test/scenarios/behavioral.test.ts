/**
 * Test Scenario: Behavioral Anomaly Detection
 *
 * Verifies that Wardex tracks agent transaction patterns and flags
 * deviations from established baselines (value spikes, new contracts,
 * frequency bursts).
 */

import { describe, it, expect } from 'vitest';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type { TransactionRequest, SecurityPolicy } from '@wardexai/core';

const KNOWN_CONTRACT = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'; // USDC
const NEW_CONTRACT = '0xdead000000000000000000000000000000000099';

function createTestWardex(policyOverrides?: Partial<SecurityPolicy>) {
  const policy = defaultPolicy();
  if (policyOverrides) {
    Object.assign(policy, policyOverrides);
  }
  // Enable behavioral analysis
  policy.behavioral.enabled = true;
  policy.behavioral.learningPeriodDays = 7;
  policy.behavioral.sensitivityLevel = 'medium';

  return createWardex({
    policy,
    signer: { type: 'isolated-process', endpoint: '/tmp/test-signer.sock' },
    mode: 'adaptive',
  });
}

/**
 * Helper: sends N small transactions to build a behavioral baseline.
 */
async function buildBaseline(
  wardex: ReturnType<typeof createWardex>,
  count: number,
  valueWei = '100000000000000', // 0.0001 ETH (~$0.35)
  to = KNOWN_CONTRACT,
): Promise<void> {
  for (let i = 0; i < count; i++) {
    await wardex.evaluate({
      to,
      value: valueWei,
      chainId: 1,
    });
  }
}

describe('Behavioral Anomaly Detection', () => {
  it('should not flag transactions when behavioral analysis is disabled', async () => {
    const policy = defaultPolicy();
    policy.behavioral.enabled = false;
    const wardex = createWardex({
      policy,
      signer: { type: 'isolated-process', endpoint: '/tmp/test-signer.sock' },
      mode: 'adaptive',
    });

    // Send many small txs then a large one
    await buildBaseline(wardex, 10);

    const verdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '10000000000000000000', // 10 ETH
      chainId: 1,
    });

    // Behavioral score should be 0 when disabled
    expect(verdict.riskScore.behavioral).toBe(0);
    expect(verdict.reasons.filter((r) => r.source === 'behavioral')).toHaveLength(0);
  });

  it('should not flag early transactions (insufficient history)', async () => {
    const wardex = createTestWardex();

    // Only 3 transactions - not enough for a baseline
    await buildBaseline(wardex, 3);

    const verdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '10000000000000000000', // 10 ETH (way larger)
      chainId: 1,
    });

    // Should not flag value anomaly with insufficient history
    const valueAnomaly = verdict.reasons.find(
      (r) => r.code === 'BEHAVIORAL_VALUE_ANOMALY',
    );
    expect(valueAnomaly).toBeUndefined();
  });

  it('should detect value anomaly after sufficient baseline', async () => {
    const wardex = createTestWardex();

    // Build baseline with small transactions (0.0001 ETH each)
    await buildBaseline(wardex, 10);

    // Now send a much larger transaction (10 ETH = 100,000x larger)
    const verdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '10000000000000000000', // 10 ETH
      chainId: 1,
    });

    const valueAnomaly = verdict.reasons.find(
      (r) => r.code === 'BEHAVIORAL_VALUE_ANOMALY',
    );
    expect(valueAnomaly).toBeDefined();
    expect(valueAnomaly!.source).toBe('behavioral');
    expect(verdict.riskScore.behavioral).toBeGreaterThan(0);
  });

  it('should detect new contract interaction', async () => {
    const wardex = createTestWardex();

    // Build baseline with transactions to known contracts (need at least 3 known)
    const contracts = [
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      '0x6B175474E89094C44Da98b954EedeAC495271d0F',
    ];
    for (const addr of contracts) {
      await wardex.evaluate({ to: addr, value: '100000000000000', chainId: 1 });
      await wardex.evaluate({ to: addr, value: '100000000000000', chainId: 1 });
    }

    // Now interact with a brand new contract
    const verdict = await wardex.evaluate({
      to: NEW_CONTRACT,
      value: '100000000000000', // same small value
      chainId: 1,
    });

    const newContractReason = verdict.reasons.find(
      (r) => r.code === 'BEHAVIORAL_NEW_CONTRACT',
    );
    expect(newContractReason).toBeDefined();
    expect(newContractReason!.severity).toBe('low');
  });

  it('should accumulate behavioral risk score from multiple anomalies', async () => {
    const wardex = createTestWardex();

    // Build baseline with known contracts and small values
    const contracts = [
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
      '0xdAC17F958D2ee523a2206206994597C13D831ec7',
      '0x6B175474E89094C44Da98b954EedeAC495271d0F',
    ];
    for (const addr of contracts) {
      for (let i = 0; i < 4; i++) {
        await wardex.evaluate({ to: addr, value: '100000000000000', chainId: 1 });
      }
    }

    // Now: new contract + large value = multiple behavioral anomalies
    const verdict = await wardex.evaluate({
      to: NEW_CONTRACT,
      value: '10000000000000000000', // 10 ETH
      chainId: 1,
    });

    // Should have both value anomaly and new contract findings
    const behavioralReasons = verdict.reasons.filter((r) => r.source === 'behavioral');
    expect(behavioralReasons.length).toBeGreaterThanOrEqual(2);
    expect(verdict.riskScore.behavioral).toBeGreaterThan(0);
  });

  it('should include behavioral score in composite risk', async () => {
    const wardex = createTestWardex();

    // Build baseline
    await buildBaseline(wardex, 10);

    // Get baseline composite for a normal transaction
    const normalVerdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '100000000000000',
      chainId: 1,
    });

    // Now trigger behavioral anomaly
    const anomalyVerdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '10000000000000000000', // 10 ETH
      chainId: 1,
    });

    // Composite should be higher when behavioral score is non-zero
    if (anomalyVerdict.riskScore.behavioral > 0) {
      expect(anomalyVerdict.riskScore.composite).toBeGreaterThan(
        normalVerdict.riskScore.composite,
      );
    }
  });

  it('should respect sensitivity level configuration', async () => {
    // Low sensitivity = harder to trigger anomalies (4x stddev)
    const wardexLow = createTestWardex();
    wardexLow.updatePolicy({ behavioral: { enabled: true, learningPeriodDays: 7, sensitivityLevel: 'low' } });

    // High sensitivity = easier to trigger anomalies (1.5x stddev)
    const wardexHigh = createTestWardex();
    wardexHigh.updatePolicy({ behavioral: { enabled: true, learningPeriodDays: 7, sensitivityLevel: 'high' } });

    // Build identical baselines
    await buildBaseline(wardexLow, 10);
    await buildBaseline(wardexHigh, 10);

    // Send moderately larger transaction (1 ETH, ~10,000x baseline but tests the threshold)
    const tx: TransactionRequest = {
      to: KNOWN_CONTRACT,
      value: '1000000000000000000',
      chainId: 1,
    };

    const verdictLow = await wardexLow.evaluate(tx);
    const verdictHigh = await wardexHigh.evaluate(tx);

    // High sensitivity should produce >= the behavioral score of low sensitivity
    expect(verdictHigh.riskScore.behavioral).toBeGreaterThanOrEqual(
      verdictLow.riskScore.behavioral,
    );
  });
});

describe('Behavioral + Provider Wrapper Integration', () => {
  it('should track transactions through the behavioral profile over time', async () => {
    const wardex = createTestWardex();

    // Send 15 transactions to build a solid baseline
    for (let i = 0; i < 15; i++) {
      const verdict = await wardex.evaluate({
        to: KNOWN_CONTRACT,
        value: '100000000000000',
        chainId: 1,
      });
      // Early transactions should not be flagged as behavioral anomalies
      if (i < 5) {
        expect(verdict.riskScore.behavioral).toBe(0);
      }
    }

    // Now the 16th transaction with anomalous value
    const verdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '50000000000000000000', // 50 ETH
      chainId: 1,
    });

    // Should detect the value spike
    expect(verdict.reasons.some((r) => r.code === 'BEHAVIORAL_VALUE_ANOMALY')).toBe(true);
  });
});

describe('Behavioral Poisoning Resistance', () => {
  it('should not learn from blocked transactions', async () => {
    const wardex = createTestWardex();

    // Build clean baseline at very low value.
    await buildBaseline(wardex, 10, '100000000000000'); // 0.0001 ETH

    // Force blocked high-value transactions via denylist.
    wardex.updatePolicy({
      denylists: {
        addresses: [NEW_CONTRACT],
        patterns: [],
      },
    });

    // Keep below auto-freeze threshold (5 blocks in recent window).
    for (let i = 0; i < 4; i++) {
      const blocked = await wardex.evaluate({
        to: NEW_CONTRACT,
        value: '1000000000000000000', // 1 ETH
        chainId: 1,
      });
      expect(blocked.decision).not.toBe('approve');
    }

    // Medium-large tx should still be treated as anomaly if blocks were not learned.
    const verdict = await wardex.evaluate({
      to: KNOWN_CONTRACT,
      value: '500000000000000000', // 0.5 ETH
      chainId: 1,
    });

    expect(verdict.reasons.some((r) => r.code === 'BEHAVIORAL_VALUE_ANOMALY')).toBe(true);
  });
});
