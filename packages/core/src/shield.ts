/**
 * WardexShield - Core Implementation
 *
 * The main Wardex interface. Orchestrates the middleware pipeline,
 * manages state, and produces security verdicts.
 */

import type {
  WardexConfig,
  WardexShield,
  SecurityVerdict,
  SecurityPolicy,
  SecurityStatus,
  TransactionRequest,
  ConversationContext,
  Middleware,
  OutputFilter,
  AuditEntry,
} from './types.js';
import { compose, createMiddlewareContext, validateTransactionRequest } from './pipeline.js';
import { createOutputFilter } from './output-filter.js';
import { createContextAnalyzer } from './middleware/context-analyzer.js';
import { transactionDecoder } from './middleware/transaction-decoder.js';
import { createAddressChecker } from './middleware/address-checker.js';
import { createValueAssessor } from './middleware/value-assessor.js';
import { createContractChecker } from './middleware/contract-checker.js';
import { createBehavioralComparator } from './middleware/behavioral-comparator.js';
import { riskAggregator } from './middleware/risk-aggregator.js';
import { policyEngine } from './middleware/policy-engine.js';
import { mergePolicy } from './policy.js';

export function createShield(config: WardexConfig): WardexShield {
  let policy = config.policy;
  let frozen = false;
  let freezeReason = '';
  let evaluationCount = 0;
  let blockCount = 0;
  let advisoryCount = 0;
  let dailyVolumeWei = 0n;
  let dailyVolumeResetDate = new Date().toDateString();
  let signerHealthy = true;
  let lastSignerCheck = 0;
  let intelligenceLastUpdated: string | undefined;

  const auditLog: AuditEntry[] = [];
  const filter = createOutputFilter();
  const customMiddlewares: Middleware[] = [];

  const { middleware: contextAnalyzer } = createContextAnalyzer();
  const valueAssessor = createValueAssessor();
  const { middleware: behavioralComparator } = createBehavioralComparator();

  // Wire intelligence provider into address and contract middleware when configured.
  // The intelligence package is an optional peer dependency - we use dynamic import
  // so that @wardexai/core works standalone without @wardexai/intelligence installed.
  let addressChecker: Middleware;
  let contractChecker: Middleware;

  if (config.intelligence) {
    // Lazy-load intelligence provider. If @wardexai/intelligence isn't installed,
    // fall back to stub middleware with no external reputation lookups.
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { createIntelligenceProvider } = require('@wardexai/intelligence') as {
        createIntelligenceProvider: (cfg: {
          rpcUrl: string;
          chainId: number;
          denylistPath?: string;
          explorerApiKey?: string;
          explorerApiUrl?: string;
        }) => {
          getAddressReputation: (address: string) => Promise<import('./types.js').AddressReputation>;
          getContractAnalysis: (address: string) => Promise<import('./types.js').ContractAnalysis>;
        };
      };

      const intel = createIntelligenceProvider({
        rpcUrl: config.intelligence.rpcUrl,
        chainId: config.intelligence.chainId,
        denylistPath: config.intelligence.denylistPath,
        explorerApiKey: config.intelligence.explorerApiKey,
        explorerApiUrl: `https://api.etherscan.io/api`,
      });

      addressChecker = createAddressChecker(
        async (address, _chainId) => intel.getAddressReputation(address),
      );
      contractChecker = createContractChecker(
        async (address, _chainId) => intel.getContractAnalysis(address),
      );
    } catch {
      // @wardexai/intelligence not installed - use stubs
      addressChecker = createAddressChecker();
      contractChecker = createContractChecker();
    }
  } else {
    addressChecker = createAddressChecker();
    contractChecker = createContractChecker();
  }

  /**
   * C-05 FIX: Wraps a custom middleware in a sandbox that prevents it from
   * corrupting the pipeline state accumulated by core middleware.
   *
   * Protections:
   * - Snapshots reasons[] and riskScores before the custom middleware runs
   * - Restores any removed core reasons (custom can add, but not delete)
   * - Restores any zeroed-out risk scores (custom can increase, but not decrease)
   * - Prevents custom middleware from setting metadata.verdict directly
   * - Freezes the policy object to prevent mutation
   * - Catches exceptions from custom middleware (fail-open for pipeline continuity)
   */
  function sandboxMiddleware(mw: Middleware): Middleware {
    return async (ctx, next) => {
      // Snapshot core state before custom middleware
      const reasonsSnapshot = [...ctx.reasons];
      const scoresSnapshot = { ...ctx.riskScores };
      const hadVerdict = 'verdict' in ctx.metadata;

      // Freeze the policy to prevent mutation by custom middleware
      const frozenPolicy = Object.freeze({ ...ctx.policy });
      const originalPolicy = ctx.policy;
      ctx.policy = frozenPolicy as typeof ctx.policy;

      try {
        await mw(ctx, next);
      } catch (err) {
        // C-05: Custom middleware threw — log but don't crash the pipeline.
        // Add a reason noting the failure for audit trail.
        ctx.reasons.push({
          code: 'CUSTOM_MIDDLEWARE_ERROR',
          message: `Custom middleware threw: ${err instanceof Error ? err.message : 'unknown error'}`,
          severity: 'medium',
          source: 'policy',
        });
      }

      // Restore the real policy object
      ctx.policy = originalPolicy;

      // Validate: custom middleware must not remove existing reasons
      // (it can add new ones, but core findings must be preserved)
      for (const coreReason of reasonsSnapshot) {
        if (!ctx.reasons.includes(coreReason)) {
          ctx.reasons.push(coreReason);
        }
      }

      // Validate: custom middleware must not decrease risk scores
      for (const key of Object.keys(scoresSnapshot) as Array<keyof typeof scoresSnapshot>) {
        const coreScore = scoresSnapshot[key];
        const currentScore = ctx.riskScores[key];
        if (coreScore !== undefined && (currentScore === undefined || currentScore < coreScore)) {
          ctx.riskScores[key] = coreScore;
        }
      }

      // Validate: custom middleware must not set verdict directly
      // (only policyEngine should produce the final verdict)
      if (!hadVerdict && ctx.metadata.verdict) {
        delete ctx.metadata.verdict;
        ctx.reasons.push({
          code: 'MIDDLEWARE_VERDICT_OVERRIDE_BLOCKED',
          message: 'Custom middleware attempted to set verdict directly — blocked',
          severity: 'high',
          source: 'policy',
        });
      }
    };
  }

  /**
   * Builds the full middleware pipeline.
   */
  function buildPipeline(): Middleware {
    // C-05 FIX: Wrap each custom middleware in a sandbox
    const sandboxedCustom = customMiddlewares.map(sandboxMiddleware);

    return compose([
      // Core pipeline in order:
      // 1. Analyze conversation context for prompt injection
      contextAnalyzer,
      // 2. Decode transaction calldata (function, params, type)
      transactionDecoder,
      // 3. Calculate USD value at risk (needed for tier determination)
      valueAssessor,
      // 4. Check target address against denylists and reputation
      addressChecker,
      // 5. Analyze contract bytecode for dangerous patterns
      contractChecker,
      // 6. Compare against behavioral baseline (anomaly detection)
      behavioralComparator,
      // 7. Insert any custom operator middlewares (sandboxed)
      ...sandboxedCustom,
      // 8. Aggregate all risk scores into composite
      riskAggregator,
      // 9. Apply policy rules and produce final verdict
      policyEngine,
    ]);
  }

  /**
   * Resets daily volume counter if the date has changed.
   */
  function checkDailyReset(): void {
    const today = new Date().toDateString();
    if (today !== dailyVolumeResetDate) {
      dailyVolumeWei = 0n;
      dailyVolumeResetDate = today;
    }
  }

  /**
   * Records an evaluation in the audit log.
   */
  function recordAudit(
    tx: TransactionRequest,
    verdict: SecurityVerdict,
    context?: ConversationContext,
    executed?: boolean
  ): void {
    auditLog.push({
      evaluationId: verdict.evaluationId,
      timestamp: verdict.timestamp,
      transaction: tx,
      verdict,
      contextSummary: context
        ? `${context.messages.length} messages, source: ${context.source.identifier}`
        : undefined,
      executed: executed ?? verdict.decision === 'approve',
    });

    // Keep audit log bounded (last 10,000 entries)
    if (auditLog.length > 10_000) {
      auditLog.splice(0, auditLog.length - 10_000);
    }
  }

  /**
   * Core evaluation logic.
   */
  async function evaluateInternal(
    tx: TransactionRequest,
    context?: ConversationContext
  ): Promise<SecurityVerdict> {
    // Check if frozen
    if (frozen) {
      const frozenVerdict: SecurityVerdict = {
        decision: 'freeze',
        riskScore: { context: 0, transaction: 0, behavioral: 0, composite: 100 },
        reasons: [{
          code: 'SYSTEM_FROZEN',
          message: `System is in emergency freeze: ${freezeReason}`,
          severity: 'critical',
          source: 'policy',
        }],
        suggestions: ['Contact operator to unfreeze the system'],
        requiredAction: 'human_approval',
        timestamp: new Date().toISOString(),
        evaluationId: crypto.randomUUID(),
        tierId: 'frozen',
      };
      recordAudit(tx, frozenVerdict, context, false);
      return frozenVerdict;
    }

    // C-03 FIX: Validate transaction request before entering the pipeline.
    // Reject malformed addresses early to prevent downstream confusion.
    const validationError = validateTransactionRequest(tx);
    if (validationError) {
      const invalidVerdict: SecurityVerdict = {
        decision: 'block',
        riskScore: { context: 0, transaction: 100, behavioral: 0, composite: 100 },
        reasons: [{
          code: 'INVALID_TRANSACTION',
          message: validationError,
          severity: 'critical',
          source: 'transaction',
        }],
        suggestions: ['Provide a valid Ethereum address (0x + 40 hex characters)'],
        timestamp: new Date().toISOString(),
        evaluationId: crypto.randomUUID(),
        tierId: 'validation',
      };
      blockCount++;
      recordAudit(tx, invalidVerdict, context, false);
      return invalidVerdict;
    }

    checkDailyReset();
    evaluationCount++;

    // Track intelligence activity timestamp
    if (config.intelligence) {
      intelligenceLastUpdated = new Date().toISOString();
    }

    // Build and run the middleware pipeline
    const pipeline = buildPipeline();
    const ctx = createMiddlewareContext({
      transaction: tx,
      conversationContext: context,
      policy,
    });

    await pipeline(ctx, async () => {});

    // Extract verdict from pipeline
    const verdict = ctx.metadata.verdict as SecurityVerdict | undefined;

    if (!verdict) {
      // Pipeline didn't produce a verdict (shouldn't happen with policyEngine)
      const fallbackVerdict: SecurityVerdict = {
        decision: 'block',
        riskScore: { context: 0, transaction: 0, behavioral: 0, composite: 50 },
        reasons: [{
          code: 'PIPELINE_ERROR',
          message: 'Evaluation pipeline did not produce a verdict',
          severity: 'high',
          source: 'policy',
        }],
        suggestions: ['Check Wardex configuration'],
        timestamp: new Date().toISOString(),
        evaluationId: crypto.randomUUID(),
        tierId: 'error',
      };
      recordAudit(tx, fallbackVerdict, context, false);
      return fallbackVerdict;
    }

    // Update counters
    if (verdict.decision === 'block' || verdict.decision === 'freeze') {
      blockCount++;
      config.onBlock?.({ verdict, transaction: tx, decoded: ctx.decoded });
    } else if (verdict.decision === 'advise') {
      advisoryCount++;
      config.onAdvisory?.({ verdict, transaction: tx });
    }

    // Track daily volume for approved transactions
    // C-01 FIX: Check projected volume BEFORE incrementing to prevent
    // TOCTOU race where blocked txs still inflate the volume counter.
    if (verdict.decision === 'approve') {
      const txValueWei = BigInt(tx.value ?? '0');
      const projectedVolume = dailyVolumeWei + txValueWei;

      if (projectedVolume > BigInt(policy.limits.maxDailyVolumeWei)) {
        // Block the transaction — do NOT increment dailyVolumeWei
        verdict.decision = 'block';
        verdict.requiredAction = 'human_approval';
        verdict.reasons.push({
          code: 'DAILY_VOLUME_EXCEEDED',
          message: `Daily transaction volume limit exceeded (projected: ${projectedVolume}, limit: ${policy.limits.maxDailyVolumeWei})`,
          severity: 'high',
          source: 'policy',
        });
        blockCount++;
      } else {
        // Only increment volume counter for actually approved transactions
        dailyVolumeWei = projectedVolume;
      }
    }

    // Record the audit entry BEFORE freeze check so it's included
    recordAudit(tx, verdict, context);

    // Auto-freeze on multiple consecutive blocks (possible active attack)
    if (verdict.decision === 'block' || verdict.decision === 'freeze') {
      const recentEntries = auditLog.slice(-10);
      const recentBlocks = recentEntries.filter(
        (e) => e.verdict.decision === 'block' || e.verdict.decision === 'freeze'
      );

      if (recentBlocks.length >= 5) {
        frozen = true;
        freezeReason = `Auto-freeze: ${recentBlocks.length} blocked transactions in last ${recentEntries.length} evaluations`;
        config.onFreeze?.({
          reason: freezeReason,
          details: `Blocked evaluations: ${recentBlocks.map((e) => e.evaluationId).join(', ')}`,
          timestamp: new Date().toISOString(),
        });
        config.onThreat?.({
          threatType: 'AUTO_FREEZE',
          severity: 'critical',
          details: freezeReason,
        });
      }
    }
    return verdict;
  }

  // Build the shield object
  const shield: WardexShield = {
    async evaluate(tx: TransactionRequest): Promise<SecurityVerdict> {
      return evaluateInternal(tx);
    },

    async evaluateWithContext(
      tx: TransactionRequest,
      context: ConversationContext
    ): Promise<SecurityVerdict> {
      return evaluateInternal(tx, context);
    },

    outputFilter: filter,

    getStatus(): SecurityStatus {
      return {
        mode: config.mode,
        frozen,
        evaluationCount,
        blockCount,
        advisoryCount,
        dailyVolumeWei: dailyVolumeWei.toString(),
        signerHealthy,
        intelligenceLastUpdated,
      };
    },

    updatePolicy(overrides: Partial<SecurityPolicy>, operatorSecret?: string): void {
      // C-04 FIX: Require operator authentication for policy changes.
      // An unauthenticated updatePolicy() could neutralize all security
      // (e.g., set blockThreshold to 100, clear denylists, disable detection).
      if (config.operatorSecret) {
        if (!operatorSecret || operatorSecret !== config.operatorSecret) {
          config.onThreat?.({
            threatType: 'UNAUTHORIZED_POLICY_CHANGE',
            severity: 'critical',
            details: 'Attempted policy update with invalid or missing operator secret',
          });
          throw new Error('Unauthorized: invalid operator secret for updatePolicy()');
        }
      }

      policy = mergePolicy(policy, overrides);

      // Emit audit event for all policy changes (even authenticated ones)
      config.onThreat?.({
        threatType: 'POLICY_UPDATED',
        severity: 'low',
        details: `Policy updated. Changed fields: ${Object.keys(overrides).join(', ')}`,
      });
    },

    getAuditLog(limit?: number): AuditEntry[] {
      if (limit) {
        return auditLog.slice(-limit);
      }
      return [...auditLog];
    },

    use(middleware: Middleware): void {
      customMiddlewares.push(middleware);
    },

    isFrozen(): boolean {
      return frozen;
    },

    freeze(reason: string): void {
      frozen = true;
      freezeReason = reason;
      config.onFreeze?.({
        reason,
        details: 'Manual freeze triggered',
        timestamp: new Date().toISOString(),
      });
    },

    unfreeze(operatorSecret?: string): void {
      // C-04 FIX: Require operator authentication to unfreeze.
      // Unfreezing is a privileged operation — an attacker who gains
      // code execution shouldn't be able to silently unfreeze the system.
      if (config.operatorSecret) {
        if (!operatorSecret || operatorSecret !== config.operatorSecret) {
          config.onThreat?.({
            threatType: 'UNAUTHORIZED_UNFREEZE',
            severity: 'critical',
            details: 'Attempted unfreeze with invalid or missing operator secret',
          });
          throw new Error('Unauthorized: invalid operator secret for unfreeze()');
        }
      }
      frozen = false;
      freezeReason = '';
    },
  };

  return shield;
}
