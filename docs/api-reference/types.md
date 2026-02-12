# TypeScript Types Reference

Complete type definitions for the Wardex SDK. All types are exported from `@wardexai/core` and `@wardexai/signer`.

---

## Configuration Types

### `WardexConfig`

Top-level configuration for creating a Wardex shield.

```typescript
import type { WardexConfig } from '@wardexai/core';

interface WardexConfig {
  policy: SecurityPolicy;              // Operator-defined security policy
  signer: SignerConfig;                // Connection to isolated signer
  intelligence?: IntelligenceConfig;   // Threat intelligence sources
  mode: EnforcementMode;              // 'guardian' | 'copilot' | 'adaptive'
  agentIdentity?: AgentIdentityConfig; // ERC-8004 agent identity (optional)
  onBlock?: (event: BlockEvent) => void;
  onAdvisory?: (event: AdvisoryEvent) => void;
  onThreat?: (event: ThreatEvent) => void;
  onFreeze?: (event: FreezeEvent) => void;
}
```

### `EnforcementMode`

```typescript
type EnforcementMode = 'guardian' | 'copilot' | 'adaptive';
```

| Value | Behavior |
|---|---|
| `'guardian'` | Always applies Guardian-level checks regardless of value |
| `'copilot'` | Always applies Co-pilot-level checks (advisory only) |
| `'adaptive'` | Automatically selects tier based on value at risk (recommended) |

### `SignerConfig`

Union type for all supported signer backends.

```typescript
type SignerConfig =
  | IsolatedProcessSignerConfig
  | TEESignerConfig
  | MPCSignerConfig
  | SmartAccountSignerConfig
  | DelegationSignerConfig;
```

### `IsolatedProcessSignerConfig`

```typescript
interface IsolatedProcessSignerConfig {
  type: 'isolated-process';
  endpoint: string;    // Unix socket path or localhost URL for IPC
  timeout?: number;    // Timeout for signer responses in ms
}
```

### `TEESignerConfig`

```typescript
interface TEESignerConfig {
  type: 'tee';
  provider: string;              // TEE provider (e.g., 'aws-nitro', 'intel-sgx')
  endpoint: string;              // Connection endpoint
  expectedAttestation?: string;  // Expected attestation document hash
}
```

### `MPCSignerConfig`

```typescript
interface MPCSignerConfig {
  type: 'mpc';
  protocol: string;        // MPC protocol (e.g., 'gg20', 'cggmp')
  participants: string[];  // Endpoints for MPC participants
  threshold: number;       // Signing threshold
}
```

### `SmartAccountSignerConfig`

```typescript
interface SmartAccountSignerConfig {
  type: 'smart-account';
  accountAddress: string;         // ERC-4337 account address
  entryPoint: string;             // EntryPoint contract address
  bundlerUrl: string;             // Bundler URL
  session?: SessionKeyConfig;     // Session key configuration (ERC-7715)
}
```

### `DelegationSignerConfig`

```typescript
interface DelegationSignerConfig {
  type: 'delegation';
  chainId: number;                        // Chain ID for EIP-712 domain
  delegationManagerAddress?: string;      // DelegationManager contract (defaults to canonical)
  delegatorAddress: string;               // Owner address granting authority
  session: SessionKeyConfig;              // Mapped to caveat enforcers
  strictMode?: boolean;                   // Block approve/setApprovalForAll at enforcer level
}
```

### `SessionKeyConfig`

Shared by `SessionManager` and `DelegationManager`.

```typescript
interface SessionKeyConfig {
  allowedContracts: string[];        // Allowed target contract addresses
  maxValuePerTx: string;             // Maximum value per transaction (wei)
  maxDailyVolume: string;            // Maximum daily volume (wei)
  durationSeconds: number;           // Session duration in seconds
  forbidInfiniteApprovals: boolean;  // Whether infinite token approvals are forbidden
}
```

### `IntelligenceConfig`

```typescript
interface IntelligenceConfig {
  rpcUrl: string;                     // RPC endpoint for on-chain queries
  chainId: number;                    // Chain ID
  denylistPath?: string;              // Path to local denylist file
  explorerApiKey?: string;            // Etherscan/block explorer API key
  enableOnChainAnalysis?: boolean;    // Enable on-chain age/activity analysis
  threatFeeds?: string[];             // Custom threat feed URLs
}
```

### `AgentIdentityConfig`

```typescript
interface AgentIdentityConfig {
  registryAddress: string;  // Agent's ERC-8004 registry address
  agentId: string;          // Agent's registered identity ID
  chainId: number;          // Chain ID where identity is registered
}
```

---

## Security Policy Types

### `SecurityPolicy`

The complete operator-configurable security policy.

```typescript
interface SecurityPolicy {
  tiers: SecurityTierConfig[];            // Adaptive security tier configuration
  allowlists: Allowlists;                // Trusted addresses, contracts, protocols
  denylists: Denylists;                  // Known-bad addresses and patterns
  limits: TransactionLimits;             // Global transaction limits
  behavioral: BehavioralConfig;          // Behavioral anomaly detection settings
  contextAnalysis: ContextAnalysisConfig; // Prompt injection detection settings
}
```

### `SecurityTierConfig`

```typescript
interface SecurityTierConfig {
  id: string;                     // Unique tier identifier
  name: string;                   // Human-readable name
  triggers: TierTriggers;        // Conditions that activate this tier
  enforcement: TierEnforcement;  // Enforcement behavior at this tier
}
```

### `TierTriggers`

```typescript
interface TierTriggers {
  minValueAtRiskUsd?: number;       // Minimum value (USD) to activate
  maxValueAtRiskUsd?: number;       // Maximum value (USD) for this tier
  targetAddresses?: string[];       // Specific addresses that trigger this tier
  functionSignatures?: string[];    // Specific function signatures
  protocols?: string[];             // Protocol identifiers (e.g., 'uniswap-v3')
}
```

### `TierEnforcement`

```typescript
interface TierEnforcement {
  mode: 'audit' | 'copilot' | 'guardian' | 'fortress';
  blockThreshold: number;           // Risk score threshold (0-100) that triggers blocking
  requireHumanApproval: boolean;    // Require human approval for all transactions
  timeLockSeconds?: number;         // Time-lock delay before execution
  notifyOperator: boolean;          // Notify operator on block or all activity
  requireOnChainProof: boolean;     // Record evaluation proof on-chain
}
```

### `Allowlists`

```typescript
interface Allowlists {
  addresses: string[];   // Known-safe EOA and contract addresses
  contracts: string[];   // Known-safe contract addresses
  protocols: string[];   // Known-safe protocol identifiers (e.g., 'uniswap-v3')
}
```

### `Denylists`

```typescript
interface Denylists {
  addresses: string[];         // Known-malicious addresses
  patterns: ContractPattern[]; // Contract bytecode/pattern signatures to block
}
```

### `ContractPattern`

```typescript
interface ContractPattern {
  name: string;          // Human-readable name
  pattern: string;       // Bytecode pattern to match (hex string or regex)
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;   // Description of what this pattern indicates
}
```

### `TransactionLimits`

```typescript
interface TransactionLimits {
  maxTransactionValueWei: string;  // Max value per single transaction (wei)
  maxDailyVolumeWei: string;       // Max cumulative daily volume (wei)
  maxApprovalAmountWei: string;    // Max token approval amount (wei)
  maxGasPriceGwei: number;         // Max gas price (gwei)
}
```

**Default values** (from `defaultPolicy()`):

| Limit | Default | Meaning |
|---|---|---|
| `maxTransactionValueWei` | `'10000000000000000000'` | 10 ETH |
| `maxDailyVolumeWei` | `'50000000000000000000'` | 50 ETH |
| `maxApprovalAmountWei` | `'1000000000000000000000'` | 1000 tokens |
| `maxGasPriceGwei` | `100` | 100 gwei |

### `BehavioralConfig`

```typescript
interface BehavioralConfig {
  enabled: boolean;                               // Enable behavioral anomaly detection
  learningPeriodDays: number;                     // Days of history for baseline (default: 7)
  sensitivityLevel: 'low' | 'medium' | 'high';   // How sensitive anomaly detection is
}
```

### `ContextAnalysisConfig`

```typescript
interface ContextAnalysisConfig {
  enablePromptInjectionDetection: boolean;  // Enable prompt injection detection
  enableCoherenceChecking: boolean;         // Enable conversation coherence checking
  suspiciousPatterns: string[];             // Custom suspicious patterns (regex strings)
  enableEscalationDetection: boolean;       // Enable multi-turn escalation detection
  enableSourceVerification: boolean;        // Enable cross-MCP source verification
}
```

---

## Verdict Types

### `SecurityVerdict`

The output of every evaluation.

```typescript
interface SecurityVerdict {
  decision: 'approve' | 'advise' | 'block' | 'freeze';
  riskScore: RiskScore;
  reasons: SecurityReason[];
  suggestions: string[];
  requiredAction?: 'human_approval' | 'delay' | 'none';
  delaySeconds?: number;
  proofHash?: string;         // For on-chain proof submission
  timestamp: string;          // ISO timestamp
  evaluationId: string;       // Unique ID for audit trail
  tierId: string;             // Which security tier was applied
}
```

### `RiskScore`

Component risk scores, each from 0-100.

```typescript
interface RiskScore {
  context: number;      // Prompt injection / context manipulation likelihood
  transaction: number;  // On-chain threat signals
  behavioral: number;   // Deviation from agent's normal behavior
  composite: number;    // Weighted composite score
}
```

### `SecurityReason`

Individual finding from the evaluation pipeline.

```typescript
interface SecurityReason {
  code: string;       // Short code (e.g., 'INFINITE_APPROVAL', 'DENYLISTED_ADDRESS')
  message: string;    // Human-readable description
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  source: 'context' | 'transaction' | 'behavioral' | 'address' | 'contract' | 'policy';
}
```

**Common reason codes:**

| Code | Source | Meaning |
|---|---|---|
| `PROMPT_INJECTION` | context | Detected instruction override pattern |
| `JAILBREAK_PATTERN` | context | Detected jailbreak attempt |
| `URGENCY_MANIPULATION` | context | Urgency/pressure language detected |
| `SEED_PHRASE_EXTRACTION` | context | Attempt to extract seed phrase |
| `DENYLISTED_ADDRESS` | address | Target address is on denylist |
| `UNVERIFIED_CONTRACT` | address | Contract code not verified |
| `INFINITE_APPROVAL` | transaction | Unlimited token approval detected |
| `SELFDESTRUCT_DETECTED` | contract | Contract has self-destruct capability |
| `DELEGATECALL_DETECTED` | contract | Unsafe delegatecall to unknown target |
| `VALUE_ANOMALY` | behavioral | Transaction value is unusual for this agent |
| `FREQUENCY_ANOMALY` | behavioral | Unusually high transaction frequency |
| `DAILY_VOLUME_EXCEEDED` | policy | Daily volume limit exceeded |

---

## Transaction Types

### `TransactionRequest`

Input to every evaluation.

```typescript
interface TransactionRequest {
  to: string;                    // Target address
  value?: string;                // Value in wei (string for BigInt compatibility)
  data?: string;                 // Encoded calldata
  chainId: number;               // Chain ID
  gasLimit?: string;             // Gas limit
  maxFeePerGas?: string;         // Max fee per gas (EIP-1559)
  maxPriorityFeePerGas?: string; // Max priority fee per gas (EIP-1559)
  nonce?: number;                // Nonce (if specified)
}
```

### `DecodedTransaction`

Populated by the `transactionDecoder` middleware.

```typescript
interface DecodedTransaction {
  raw: TransactionRequest;                  // Original request
  functionName?: string;                    // Decoded function name
  parameters?: Record<string, unknown>;     // Decoded function parameters
  abi?: string;                             // ABI used for decoding
  contractName?: string;                    // Contract name (if known)
  isApproval: boolean;                      // Whether this is a token approval
  isTransfer: boolean;                      // Whether this is a token transfer
  involvesEth: boolean;                     // Whether this involves ETH value
  estimatedValueUsd: number;                // Total estimated USD value at risk
}
```

---

## Context Types

### `ConversationContext`

Conversation context for LLM-aware evaluation.

```typescript
interface ConversationContext {
  messages: ConversationMessage[];           // Recent conversation messages
  triggeringMessage?: ConversationMessage;   // Message that triggered this transaction
  source: InstructionSource;                 // Source identification
  toolCallChain?: ToolCallRecord[];          // Tool call chain leading to this tx
}
```

### `ConversationMessage`

```typescript
interface ConversationMessage {
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string;
  timestamp?: string;  // ISO timestamp
}
```

### `InstructionSource`

```typescript
interface InstructionSource {
  type: 'user' | 'mcp-server' | 'skill' | 'tool' | 'system' | 'unknown';
  identifier: string;                       // e.g., MCP server name
  trustLevel: 'high' | 'medium' | 'low' | 'untrusted';
}
```

### `ToolCallRecord`

```typescript
interface ToolCallRecord {
  tool: string;       // Tool name
  input: string;      // Tool input (sanitized)
  output?: string;    // Tool output (sanitized)
  timestamp?: string; // Timestamp
}
```

---

## Event Types

### `BlockEvent`

Fired when a transaction is blocked.

```typescript
interface BlockEvent {
  verdict: SecurityVerdict;
  transaction: TransactionRequest;
  decoded?: DecodedTransaction;
}
```

### `AdvisoryEvent`

Fired when an advisory is issued (transaction proceeds with warnings).

```typescript
interface AdvisoryEvent {
  verdict: SecurityVerdict;
  transaction: TransactionRequest;
}
```

### `ThreatEvent`

Fired when a threat is detected (may or may not block the transaction).

```typescript
interface ThreatEvent {
  threatType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  details: string;
  address?: string;
}
```

### `FreezeEvent`

Fired when the system enters emergency freeze.

```typescript
interface FreezeEvent {
  reason: string;
  details: string;
  timestamp: string;
}
```

---

## Filter Types

### `OutputFilter`

```typescript
interface OutputFilter {
  filterText(text: string): FilterResult;
  filterData(data: unknown): FilterResult;
}
```

### `FilterResult`

```typescript
interface FilterResult {
  filtered: string;        // Sanitized output
  redactions: Redaction[];  // What was redacted and why
  blocked: boolean;         // Whether entire output should be suppressed
}
```

### `Redaction`

```typescript
interface Redaction {
  type: 'private_key' | 'seed_phrase' | 'mnemonic' | 'keystore' | 'internal_config' | 'address_correlation';
  start: number;       // Position in original text (start index)
  end: number;         // Position in original text (end index)
  replacement: string; // What it was replaced with
}
```

---

## Signer Types

### `WardexSigner`

Interface for signer implementations.

```typescript
interface WardexSigner {
  signTransaction(tx: TransactionRequest, approvalToken: string): Promise<string>;
  getAddress(): Promise<string>;
  healthCheck(): Promise<boolean>;
  signMessage(message: string, approvalToken: string): Promise<string>;
}
```

### `SessionKey`

A session key with its metadata (from `@wardexai/signer`).

```typescript
interface SessionKey {
  id: string;                    // Unique session key identifier
  address: string;               // Session key's public address
  config: SessionKeyConfig;      // Session boundaries
  createdAt: string;             // ISO timestamp
  expiresAt: string;             // ISO timestamp
  revoked: boolean;              // Whether revoked
}
```

### `SessionState`

Runtime state tracking for a session.

```typescript
interface SessionState {
  dailyVolumeWei: bigint;          // Total value spent today
  dailyResetDate: string;          // Date string for current daily window
  transactionCount: number;        // Number of transactions executed
  contractsUsed: Set<string>;      // Contracts that have been interacted with
}
```

### `SessionValidationResult`

```typescript
interface SessionValidationResult {
  valid: boolean;
  reason?: string;  // Reason for rejection (if not valid)
}
```

---

## Delegation Types

From `@wardexai/signer`.

### `DelegationManagerConfig`

```typescript
interface DelegationManagerConfig {
  chainId: number;                                    // Chain ID for EIP-712
  delegationManagerAddress?: string;                  // Defaults to canonical v1.3.0
  enforcerAddresses?: Partial<EnforcerAddresses>;     // Custom enforcer addresses
  strictInfiniteApprovalBlocking?: boolean;           // Block approve at enforcer level
}
```

### `WardexDelegation`

```typescript
interface WardexDelegation {
  id: string;                  // Unique delegation ID (internal)
  delegate: string;            // Agent's session key address
  delegator: string;           // Owner address granting authority
  authority: string;           // Parent delegation hash (0x0...0 for root)
  caveats: CaveatTerm[];      // Mapped from SessionKeyConfig
  salt: bigint;                // Random salt for uniqueness
  signature: string;           // EIP-712 signature (empty until setSignature)
  config: SessionKeyConfig;    // Original config for off-chain validation
  createdAt: string;           // ISO timestamp
  expiresAt: string;           // ISO timestamp
  revoked: boolean;
}
```

### `CaveatTerm`

```typescript
interface CaveatTerm {
  enforcer: string;  // Enforcer contract address
  terms: string;     // ABI-encoded terms for this enforcer
}
```

### `EnforcerAddresses`

```typescript
interface EnforcerAddresses {
  allowedTargets: string;             // AllowedTargetsEnforcer
  valueLte: string;                   // ValueLteEnforcer
  nativeTokenPeriodTransfer: string;  // NativeTokenPeriodTransferEnforcer
  timestamp: string;                  // TimestampEnforcer
  allowedMethods: string;             // AllowedMethodsEnforcer
  limitedCalls: string;               // LimitedCallsEnforcer
  allowedCalldata: string;            // AllowedCalldataEnforcer
  delegationManager: string;          // DelegationManager contract
}
```

### `Execution`

```typescript
interface Execution {
  target: string;     // Target contract address
  value: bigint;      // Native value (wei)
  callData: string;   // Encoded calldata
}
```

### `EIP712Domain`

```typescript
interface EIP712Domain {
  name: string;              // 'DelegationManager'
  version: string;           // '1'
  chainId: number;
  verifyingContract: string; // DelegationManager contract address
}
```

---

## Middleware Types

### `Middleware`

```typescript
type Middleware = (
  ctx: MiddlewareContext,
  next: () => Promise<void>
) => Promise<void>;
```

### `MiddlewareContext`

The shared context passed through the pipeline.

```typescript
interface MiddlewareContext {
  transaction: TransactionRequest;               // Original transaction request
  decoded?: DecodedTransaction;                  // Populated by transactionDecoder
  conversationContext?: ConversationContext;      // Conversation context (if provided)
  riskScores: Partial<RiskScore>;                // Accumulated risk scores
  reasons: SecurityReason[];                     // Accumulated security reasons
  addressReputation?: AddressReputation;         // Populated by addressChecker
  contractAnalysis?: ContractAnalysis;           // Populated by contractChecker
  policy: SecurityPolicy;                        // The policy being applied
  tier?: SecurityTierConfig;                     // Determined tier
  metadata: Record<string, unknown>;             // Metadata for audit trail
}
```

---

## Status & Audit Types

### `SecurityStatus`

```typescript
interface SecurityStatus {
  mode: EnforcementMode;
  frozen: boolean;
  evaluationCount: number;
  blockCount: number;
  advisoryCount: number;
  dailyVolumeWei: string;
  signerHealthy: boolean;
  intelligenceLastUpdated?: string;
}
```

### `AuditEntry`

```typescript
interface AuditEntry {
  evaluationId: string;
  timestamp: string;
  transaction: TransactionRequest;
  verdict: SecurityVerdict;
  contextSummary?: string;    // Stored without sensitive data
  executed: boolean;          // Whether the transaction was ultimately executed
}
```

---

## Intelligence Types

### `AddressReputation`

```typescript
interface AddressReputation {
  address: string;
  score: number;                // 0-100, higher = safer
  isDenylisted: boolean;
  isAllowlisted: boolean;
  ageDays: number;              // Days since first on-chain activity
  transactionCount: number;
  labels: string[];             // e.g., 'Uniswap V3 Router'
  isVerified?: boolean;         // Contract code verified on block explorer
  riskFactors: string[];
}
```

### `ContractAnalysis`

```typescript
interface ContractAnalysis {
  address: string;
  isVerified: boolean;
  isProxy: boolean;
  implementationAddress?: string;
  dangerousPatterns: ContractPattern[];
  allowsInfiniteApproval: boolean;
  hasSelfDestruct: boolean;
  hasUnsafeDelegatecall: boolean;
  risk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}
```
