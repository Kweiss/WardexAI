/**
 * Behavioral Comparator Middleware
 *
 * Tracks agent transaction patterns and flags deviations from baseline behavior.
 * The "memory" component of the immune system - remembers what normal looks like
 * and raises alarms when behavior changes.
 *
 * Tracks:
 * - Typical transaction values (mean, stddev)
 * - Protocols/contracts interacted with
 * - Transaction frequency (txs per hour/day)
 * - Time-of-day patterns
 * - Gas usage patterns
 *
 * v1: Statistical baseline with configurable sensitivity
 * v2: Sliding window with exponential decay for adaptive baselines
 */

import type {
  Middleware,
  SecurityReason,
  BehavioralConfig,
  TransactionRequest,
} from '../types.js';

// ---------------------------------------------------------------------------
// Behavioral Profile
// ---------------------------------------------------------------------------

interface TransactionRecord {
  to: string;
  valuUsd: number;
  gasPrice: number;
  hourOfDay: number;
  timestamp: number;
  functionSelector?: string;
}

interface BehavioralProfile {
  /** All recorded transaction history within the learning window */
  history: TransactionRecord[];
  /** Set of known contract addresses this agent has interacted with */
  knownContracts: Set<string>;
  /** Running statistics for value */
  valueMean: number;
  valueStdDev: number;
  /** Running statistics for tx frequency (txs per hour) */
  txsPerHour: number;
  /** Typical active hours (0-23) */
  activeHours: Set<number>;
  /** Last update timestamp */
  lastUpdated: number;
}

/**
 * Creates a fresh behavioral profile.
 */
function createProfile(): BehavioralProfile {
  return {
    history: [],
    knownContracts: new Set(),
    valueMean: 0,
    valueStdDev: 0,
    txsPerHour: 0,
    activeHours: new Set(),
    lastUpdated: Date.now(),
  };
}

/**
 * Recomputes statistics from the transaction history.
 */
function recomputeStats(profile: BehavioralProfile): void {
  const { history } = profile;
  if (history.length === 0) return;

  // Value mean and stddev
  const values = history.map((r) => r.valuUsd);
  const sum = values.reduce((a, b) => a + b, 0);
  profile.valueMean = sum / values.length;

  if (values.length > 1) {
    const variance =
      values.reduce((acc, v) => acc + (v - profile.valueMean) ** 2, 0) /
      (values.length - 1);
    profile.valueStdDev = Math.sqrt(variance);
  } else {
    profile.valueStdDev = 0;
  }

  // Transaction frequency: txs per hour over the observation window
  const oldest = history[0].timestamp;
  const newest = history[history.length - 1].timestamp;
  const windowHours = Math.max(1, (newest - oldest) / (1000 * 60 * 60));
  profile.txsPerHour = history.length / windowHours;

  // Active hours
  profile.activeHours.clear();
  for (const record of history) {
    profile.activeHours.add(record.hourOfDay);
  }

  // Known contracts
  for (const record of history) {
    profile.knownContracts.add(record.to.toLowerCase());
  }

  profile.lastUpdated = Date.now();
}

// ---------------------------------------------------------------------------
// Anomaly Detection
// ---------------------------------------------------------------------------

/** Sensitivity multipliers for standard deviation thresholds */
const SENSITIVITY_MULTIPLIERS: Record<string, number> = {
  low: 4.0,
  medium: 2.5,
  high: 1.5,
};

/**
 * Detects value anomalies: transactions significantly larger than historical baseline.
 */
function detectValueAnomaly(
  profile: BehavioralProfile,
  currentValueUsd: number,
  sensitivity: string,
): SecurityReason | null {
  // Need enough history to have a meaningful baseline
  if (profile.history.length < 5) return null;

  const multiplier = SENSITIVITY_MULTIPLIERS[sensitivity] ?? 2.5;
  const threshold = profile.valueMean + multiplier * profile.valueStdDev;

  // Minimum threshold: don't flag small absolute values
  if (currentValueUsd < 10) return null;

  if (currentValueUsd > threshold && threshold > 0) {
    const ratio = currentValueUsd / profile.valueMean;
    return {
      code: 'BEHAVIORAL_VALUE_ANOMALY',
      message: `Transaction value ($${currentValueUsd.toFixed(0)}) is ${ratio.toFixed(1)}x the historical average ($${profile.valueMean.toFixed(0)})`,
      severity: ratio > 10 ? 'high' : 'medium',
      source: 'behavioral',
    };
  }

  return null;
}

/**
 * Detects new contract interactions: first-time interaction with an unknown contract.
 */
function detectNewContract(
  profile: BehavioralProfile,
  to: string,
): SecurityReason | null {
  // Need some history before we can flag new contracts
  if (profile.knownContracts.size < 3) return null;

  if (!profile.knownContracts.has(to.toLowerCase())) {
    return {
      code: 'BEHAVIORAL_NEW_CONTRACT',
      message: `First-time interaction with contract ${to.slice(0, 10)}... (${profile.knownContracts.size} known contracts)`,
      severity: 'low',
      source: 'behavioral',
    };
  }

  return null;
}

/**
 * Detects frequency anomalies: sudden burst of transactions.
 */
function detectFrequencyAnomaly(
  profile: BehavioralProfile,
  sensitivity: string,
): SecurityReason | null {
  if (profile.history.length < 10) return null;

  // Count transactions in the last hour
  const oneHourAgo = Date.now() - 60 * 60 * 1000;
  const recentCount = profile.history.filter(
    (r) => r.timestamp > oneHourAgo,
  ).length;

  const multiplier = SENSITIVITY_MULTIPLIERS[sensitivity] ?? 2.5;
  const threshold = Math.max(5, profile.txsPerHour * multiplier);

  if (recentCount > threshold) {
    return {
      code: 'BEHAVIORAL_FREQUENCY_ANOMALY',
      message: `${recentCount} transactions in the last hour (baseline: ${profile.txsPerHour.toFixed(1)}/hr)`,
      severity: recentCount > threshold * 2 ? 'high' : 'medium',
      source: 'behavioral',
    };
  }

  return null;
}

/**
 * Detects unusual timing: transactions outside the agent's normal active hours.
 */
function detectTimingAnomaly(
  profile: BehavioralProfile,
  currentHour: number,
): SecurityReason | null {
  // Need enough hourly diversity to have a pattern
  if (profile.activeHours.size < 4 || profile.history.length < 20) return null;

  if (!profile.activeHours.has(currentHour)) {
    return {
      code: 'BEHAVIORAL_TIMING_ANOMALY',
      message: `Transaction at unusual hour (${currentHour}:00) - not in typical active hours`,
      severity: 'low',
      source: 'behavioral',
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Middleware Export
// ---------------------------------------------------------------------------

/**
 * Creates the behavioral comparator middleware.
 * Maintains a behavioral profile across evaluations and flags deviations.
 *
 * The profile is held in memory (per WardexShield instance). In v2, it will
 * be persisted to disk for cross-session behavioral memory.
 */
export function createBehavioralComparator(): {
  middleware: Middleware;
  profile: BehavioralProfile;
} {
  const profile = createProfile();

  const middleware: Middleware = async (ctx, next) => {
    const config: BehavioralConfig = ctx.policy.behavioral;

    // Skip if behavioral analysis is disabled
    if (!config.enabled) {
      await next();
      return;
    }

    // Prune history outside the learning window
    const windowMs = config.learningPeriodDays * 24 * 60 * 60 * 1000;
    const cutoff = Date.now() - windowMs;
    profile.history = profile.history.filter((r) => r.timestamp > cutoff);

    // Recompute baseline statistics
    recomputeStats(profile);

    // Current transaction properties
    const currentValueUsd = ctx.decoded?.estimatedValueUsd ?? (ctx.metadata.estimatedValueUsd as number | undefined) ?? 0;
    const currentHour = new Date().getHours();
    const functionSelector = ctx.transaction.data?.slice(0, 10);
    const gasPrice = ctx.transaction.maxFeePerGas
      ? Number(BigInt(ctx.transaction.maxFeePerGas)) / 1e9
      : 0;

    // Run anomaly detectors
    const reasons: SecurityReason[] = [];

    const valueAnomaly = detectValueAnomaly(
      profile,
      currentValueUsd,
      config.sensitivityLevel,
    );
    if (valueAnomaly) reasons.push(valueAnomaly);

    const newContract = detectNewContract(profile, ctx.transaction.to);
    if (newContract) reasons.push(newContract);

    const frequencyAnomaly = detectFrequencyAnomaly(
      profile,
      config.sensitivityLevel,
    );
    if (frequencyAnomaly) reasons.push(frequencyAnomaly);

    const timingAnomaly = detectTimingAnomaly(profile, currentHour);
    if (timingAnomaly) reasons.push(timingAnomaly);

    // Add reasons to context
    ctx.reasons.push(...reasons);

    // Calculate behavioral risk score
    let behavioralScore = 0;
    for (const reason of reasons) {
      switch (reason.severity) {
        case 'critical':
          behavioralScore += 40;
          break;
        case 'high':
          behavioralScore += 25;
          break;
        case 'medium':
          behavioralScore += 15;
          break;
        case 'low':
          behavioralScore += 5;
          break;
        case 'info':
          break;
      }
    }
    ctx.riskScores.behavioral = Math.min(100, behavioralScore);

    await next();

    // H-01 FIX: Learn only from finalized non-blocked verdicts.
    // Recording blocked/frozen transactions allows baseline poisoning.
    const verdict = ctx.metadata.verdict as { decision?: string } | undefined;
    const shouldLearn =
      !verdict ||
      verdict.decision === 'approve' ||
      verdict.decision === 'advise';

    if (shouldLearn) {
      profile.history.push({
        to: ctx.transaction.to,
        valuUsd: currentValueUsd,
        gasPrice,
        hourOfDay: currentHour,
        timestamp: Date.now(),
        functionSelector,
      });
    }
  };

  return { middleware, profile };
}
