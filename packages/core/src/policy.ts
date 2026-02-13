/**
 * Default Security Policy
 *
 * Provides sensible defaults for the adaptive security tiers.
 * Operators can override any of these via WardexConfig.
 */

import type { SecurityPolicy, SecurityTierConfig } from './types.js';

const TIER_AUDIT: SecurityTierConfig = {
  id: 'tier-0-audit',
  name: 'Audit',
  triggers: {
    minValueAtRiskUsd: 0,
    maxValueAtRiskUsd: 1,
  },
  enforcement: {
    mode: 'audit',
    blockThreshold: 100, // never blocks
    requireHumanApproval: false,
    notifyOperator: false,
    requireOnChainProof: false,
  },
};

const TIER_COPILOT: SecurityTierConfig = {
  id: 'tier-1-copilot',
  name: 'Co-pilot',
  triggers: {
    minValueAtRiskUsd: 1,
    maxValueAtRiskUsd: 100,
  },
  enforcement: {
    mode: 'copilot',
    blockThreshold: 100, // advisory only
    requireHumanApproval: false,
    notifyOperator: false,
    requireOnChainProof: false,
  },
};

const TIER_GUARDIAN: SecurityTierConfig = {
  id: 'tier-2-guardian',
  name: 'Guardian',
  triggers: {
    minValueAtRiskUsd: 100,
    maxValueAtRiskUsd: 10_000,
  },
  enforcement: {
    mode: 'guardian',
    blockThreshold: 70,
    requireHumanApproval: false,
    notifyOperator: true,
    requireOnChainProof: false,
  },
};

const TIER_FORTRESS: SecurityTierConfig = {
  id: 'tier-3-fortress',
  name: 'Fortress',
  triggers: {
    minValueAtRiskUsd: 10_000,
  },
  enforcement: {
    mode: 'fortress',
    blockThreshold: 30,
    requireHumanApproval: true,
    timeLockSeconds: 900, // 15 minutes for > $10K
    notifyOperator: true,
    requireOnChainProof: true,
  },
};

/**
 * Creates a default security policy with sensible defaults.
 * This is the recommended starting point for most deployments.
 */
export function defaultPolicy(): SecurityPolicy {
  return {
    tiers: [TIER_AUDIT, TIER_COPILOT, TIER_GUARDIAN, TIER_FORTRESS],
    allowlists: {
      addresses: [],
      contracts: [],
      protocols: [],
    },
    denylists: {
      addresses: [],
      patterns: [],
    },
    limits: {
      // 10 ETH max per transaction (~$25K at typical prices)
      maxTransactionValueWei: '10000000000000000000',
      // 50 ETH max daily volume
      maxDailyVolumeWei: '50000000000000000000',
      // 1000 tokens max approval (never infinite by default)
      maxApprovalAmountWei: '1000000000000000000000',
      // 100 gwei max gas price
      maxGasPriceGwei: 100,
    },
    behavioral: {
      enabled: true,
      learningPeriodDays: 7,
      sensitivityLevel: 'medium',
    },
    contextAnalysis: {
      enablePromptInjectionDetection: true,
      enableCoherenceChecking: true,
      suspiciousPatterns: [],
      enableEscalationDetection: true,
      enableSourceVerification: true,
    },
  };
}

/**
 * Merges a partial policy override with the defaults.
 */
export function mergePolicy(
  base: SecurityPolicy,
  overrides: Partial<SecurityPolicy>
): SecurityPolicy {
  const mergedTiers = overrides.tiers ?? base.tiers;

  if (overrides.tiers) {
    if (mergedTiers.length === 0) {
      throw new Error('Policy must include at least one security tier');
    }

    const hasBlockingTier = mergedTiers.some(
      (tier) =>
        tier.enforcement.mode === 'guardian' ||
        tier.enforcement.mode === 'fortress'
    );
    if (!hasBlockingTier) {
      throw new Error(
        'Policy tiers must include at least one blocking tier (guardian or fortress)'
      );
    }
  }

  return {
    tiers: mergedTiers,
    allowlists: {
      addresses: [
        ...base.allowlists.addresses,
        ...(overrides.allowlists?.addresses ?? []),
      ],
      contracts: [
        ...base.allowlists.contracts,
        ...(overrides.allowlists?.contracts ?? []),
      ],
      protocols: [
        ...base.allowlists.protocols,
        ...(overrides.allowlists?.protocols ?? []),
      ],
    },
    denylists: {
      addresses: [
        ...base.denylists.addresses,
        ...(overrides.denylists?.addresses ?? []),
      ],
      patterns: [
        ...base.denylists.patterns,
        ...(overrides.denylists?.patterns ?? []),
      ],
    },
    limits: {
      ...base.limits,
      ...overrides.limits,
    },
    behavioral: {
      ...base.behavioral,
      ...overrides.behavioral,
    },
    contextAnalysis: {
      ...base.contextAnalysis,
      ...overrides.contextAnalysis,
    },
  };
}
