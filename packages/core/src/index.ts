/**
 * @wardexai/core
 *
 * Adaptive security for AI agent wallets.
 * An immune system that protects AI agents from prompt injection,
 * seed phrase leakage, malicious contracts, and social engineering.
 */

export { createWardex } from './wardex.js';
export { defaultPolicy, mergePolicy } from './policy.js';
export { createOutputFilter } from './output-filter.js';
export { createShield } from './shield.js';
export {
  compose,
  createMiddlewareContext,
  isValidEthereumAddress,
  validateTransactionRequest,
} from './pipeline.js';

// Middleware exports (for custom pipeline construction)
export { createContextAnalyzer } from './middleware/context-analyzer.js';
export { transactionDecoder } from './middleware/transaction-decoder.js';
export { createAddressChecker } from './middleware/address-checker.js';
export { createValueAssessor } from './middleware/value-assessor.js';
export { createContractChecker } from './middleware/contract-checker.js';
export { createBehavioralComparator } from './middleware/behavioral-comparator.js';
export { riskAggregator } from './middleware/risk-aggregator.js';
export { policyEngine } from './middleware/policy-engine.js';

// Provider wrappers (drop-in protection for ethers.js and viem)
export { wrapEthersSigner, WardexBlockedError } from './providers/ethers.js';
export { wrapViemWalletClient } from './providers/viem.js';

// Type exports
export type {
  WardexConfig,
  WardexShield,
  SecurityPolicy,
  SecurityTierConfig,
  SecurityVerdict,
  RiskScore,
  SecurityReason,
  TransactionRequest,
  DecodedTransaction,
  ConversationContext,
  ConversationMessage,
  InstructionSource,
  ToolCallRecord,
  EnforcementMode,
  SignerConfig,
  IsolatedProcessSignerConfig,
  TEESignerConfig,
  MPCSignerConfig,
  SmartAccountSignerConfig,
  SessionKeyConfig,
  IntelligenceConfig,
  AgentIdentityConfig,
  Allowlists,
  Denylists,
  ContractPattern,
  TransactionLimits,
  BehavioralConfig,
  ContextAnalysisConfig,
  TierTriggers,
  TierEnforcement,
  BlockEvent,
  AdvisoryEvent,
  ThreatEvent,
  FreezeEvent,
  OutputFilter,
  FilterResult,
  Redaction,
  AddressReputation,
  ContractAnalysis,
  WardexSigner,
  Middleware,
  MiddlewareContext,
  SecurityStatus,
  AuditEntry,
} from './types.js';
