/**
 * @wardexai/core - Core type definitions
 *
 * These interfaces define the entire Wardex SDK contract.
 * Every other component builds against these types.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface WardexConfig {
  /** Operator-defined security policy */
  policy: SecurityPolicy;
  /** Connection to isolated signer */
  signer: SignerConfig;
  /** Threat intelligence sources */
  intelligence?: IntelligenceConfig;
  /** Enforcement mode */
  mode: EnforcementMode;
  /** Max evaluate() calls per second. Set <= 0 to disable. Default: 100 */
  evaluationRateLimitPerSecond?: number;
  /** Minimum cooldown after auto-freeze before unfreeze is allowed (seconds, default 900) */
  unfreezeCooldownSeconds?: number;
  /** ERC-8004 agent identity (optional, for on-chain trust signal) */
  agentIdentity?: AgentIdentityConfig;
  /**
   * C-04 FIX: Operator secret required for privileged operations
   * (updatePolicy, unfreeze). Must be at least 32 characters.
   * If not set, updatePolicy() and unfreeze() will throw.
   */
  operatorSecret?: string;
  /** Event handlers */
  onBlock?: (event: BlockEvent) => void;
  onAdvisory?: (event: AdvisoryEvent) => void;
  onThreat?: (event: ThreatEvent) => void;
  onFreeze?: (event: FreezeEvent) => void;
}

export type EnforcementMode = 'guardian' | 'copilot' | 'adaptive';

// ---------------------------------------------------------------------------
// Signer Configuration
// ---------------------------------------------------------------------------

export type SignerConfig =
  | IsolatedProcessSignerConfig
  | TEESignerConfig
  | MPCSignerConfig
  | SmartAccountSignerConfig
  | DelegationSignerConfig;

export interface IsolatedProcessSignerConfig {
  type: 'isolated-process';
  /** Unix socket path or localhost URL for IPC */
  endpoint: string;
  /** Timeout for signer responses in ms */
  timeout?: number;
}

export interface TEESignerConfig {
  type: 'tee';
  /** TEE provider (e.g., 'aws-nitro', 'intel-sgx') */
  provider: string;
  /** Connection endpoint */
  endpoint: string;
  /** Expected attestation document hash */
  expectedAttestation?: string;
}

export interface MPCSignerConfig {
  type: 'mpc';
  /** MPC protocol (e.g., 'gg20', 'cggmp') */
  protocol: string;
  /** Endpoints for MPC participants */
  participants: string[];
  /** Signing threshold */
  threshold: number;
}

export interface SmartAccountSignerConfig {
  type: 'smart-account';
  /** ERC-4337 account address */
  accountAddress: string;
  /** EntryPoint contract address */
  entryPoint: string;
  /** Bundler URL */
  bundlerUrl: string;
  /** Session key configuration (ERC-7715) */
  session?: SessionKeyConfig;
}

export interface DelegationSignerConfig {
  type: 'delegation';
  /** Chain ID for EIP-712 domain */
  chainId: number;
  /** DelegationManager contract address (defaults to canonical v1.3.0) */
  delegationManagerAddress?: string;
  /** Delegator (owner) address granting authority */
  delegatorAddress: string;
  /** Session key configuration (mapped to caveat enforcers) */
  session: SessionKeyConfig;
  /** Block approve/setApprovalForAll at enforcer level (not just off-chain) */
  strictMode?: boolean;
}

export interface SessionKeyConfig {
  /** Allowed target contracts */
  allowedContracts: string[];
  /** Maximum value per transaction (wei) */
  maxValuePerTx: string;
  /** Maximum daily volume (wei) */
  maxDailyVolume: string;
  /** Session duration in seconds */
  durationSeconds: number;
  /** Whether infinite token approvals are forbidden */
  forbidInfiniteApprovals: boolean;
}

// ---------------------------------------------------------------------------
// Intelligence Configuration
// ---------------------------------------------------------------------------

export interface IntelligenceConfig {
  /** RPC endpoint for on-chain queries */
  rpcUrl: string;
  /** Chain ID */
  chainId: number;
  /** Path to local denylist file */
  denylistPath?: string;
  /** Etherscan/block explorer API key for contract verification */
  explorerApiKey?: string;
  /** Enable on-chain age/activity analysis */
  enableOnChainAnalysis?: boolean;
  /** Timeout for RPC/explorer requests in milliseconds (default: 5000) */
  requestTimeoutMs?: number;
  /** Custom threat feed URLs */
  threatFeeds?: string[];
}

// ---------------------------------------------------------------------------
// ERC-8004 Agent Identity
// ---------------------------------------------------------------------------

export interface AgentIdentityConfig {
  /** Agent's ERC-8004 registry address */
  registryAddress: string;
  /** Agent's registered identity ID */
  agentId: string;
  /** Chain ID where identity is registered */
  chainId: number;
}

// ---------------------------------------------------------------------------
// Security Policy (Operator Configurable)
// ---------------------------------------------------------------------------

export interface SecurityPolicy {
  /** Adaptive security tier configuration */
  tiers: SecurityTierConfig[];
  /** Trusted addresses, contracts, and protocols */
  allowlists: Allowlists;
  /** Known-bad addresses and patterns */
  denylists: Denylists;
  /** Global transaction limits */
  limits: TransactionLimits;
  /** Behavioral anomaly detection settings */
  behavioral: BehavioralConfig;
  /** Context integrity / prompt injection detection settings */
  contextAnalysis: ContextAnalysisConfig;
}

export interface SecurityTierConfig {
  id: string;
  name: string;
  /** Conditions that trigger this tier */
  triggers: TierTriggers;
  /** Enforcement behavior at this tier */
  enforcement: TierEnforcement;
}

export interface TierTriggers {
  /** Minimum value at risk (USD) to activate this tier */
  minValueAtRiskUsd?: number;
  /** Maximum value at risk (USD) for this tier */
  maxValueAtRiskUsd?: number;
  /** Specific addresses that trigger this tier */
  targetAddresses?: string[];
  /** Specific function signatures that trigger this tier */
  functionSignatures?: string[];
  /** Protocol identifiers (e.g., 'uniswap-v3') */
  protocols?: string[];
}

export interface TierEnforcement {
  mode: 'audit' | 'copilot' | 'guardian' | 'fortress';
  /** Risk score threshold that triggers blocking (0-100) */
  blockThreshold: number;
  /** Require human approval for all transactions in this tier */
  requireHumanApproval: boolean;
  /** Time-lock delay in seconds before execution */
  timeLockSeconds?: number;
  /** Notify operator on block or all activity */
  notifyOperator: boolean;
  /** Record evaluation proof on-chain */
  requireOnChainProof: boolean;
}

export interface Allowlists {
  /** Known-safe EOA and contract addresses */
  addresses: string[];
  /** Known-safe contract addresses (specifically for interaction) */
  contracts: string[];
  /** Known-safe protocol identifiers (e.g., 'uniswap-v3', 'aave-v3') */
  protocols: string[];
}

export interface Denylists {
  /** Known-malicious addresses */
  addresses: string[];
  /** Contract bytecode/pattern signatures to block */
  patterns: ContractPattern[];
}

export interface ContractPattern {
  /** Human-readable name for this pattern */
  name: string;
  /** Bytecode pattern to match (hex string or regex) */
  pattern: string;
  /** Severity: how dangerous is this pattern */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description of what this pattern indicates */
  description: string;
}

export interface TransactionLimits {
  /** Max value per single transaction (wei string) */
  maxTransactionValueWei: string;
  /** Max cumulative daily volume (wei string) */
  maxDailyVolumeWei: string;
  /** Max token approval amount (wei string). Default: never allow infinite */
  maxApprovalAmountWei: string;
  /** Max gas price (gwei). Prevents gas price manipulation */
  maxGasPriceGwei: number;
}

export interface BehavioralConfig {
  /** Enable behavioral anomaly detection */
  enabled: boolean;
  /** Days of history to use for baseline (default: 7) */
  learningPeriodDays: number;
  /** How sensitive anomaly detection is */
  sensitivityLevel: 'low' | 'medium' | 'high';
}

export interface ContextAnalysisConfig {
  /** Enable prompt injection detection */
  enablePromptInjectionDetection: boolean;
  /** Enable conversation coherence checking */
  enableCoherenceChecking: boolean;
  /** Custom suspicious patterns (regex strings) */
  suspiciousPatterns: string[];
  /** Enable multi-turn escalation detection */
  enableEscalationDetection: boolean;
  /** Enable cross-MCP source verification */
  enableSourceVerification: boolean;
}

// ---------------------------------------------------------------------------
// Security Verdict (Output of evaluation)
// ---------------------------------------------------------------------------

export interface SecurityVerdict {
  /** Final decision */
  decision: 'approve' | 'advise' | 'block' | 'freeze';
  /** Component risk scores */
  riskScore: RiskScore;
  /** Human-readable reasons for this verdict */
  reasons: SecurityReason[];
  /** Suggested safer alternatives */
  suggestions: string[];
  /** Required action before transaction can proceed */
  requiredAction?: 'human_approval' | 'delay' | 'none';
  /** Delay in seconds if requiredAction is 'delay' */
  delaySeconds?: number;
  /** Cryptographic hash of this evaluation (for on-chain proof) */
  proofHash?: string;
  /** ISO timestamp of evaluation */
  timestamp: string;
  /** Unique evaluation ID for audit trail */
  evaluationId: string;
  /** Which security tier was applied */
  tierId: string;
}

export interface RiskScore {
  /** Prompt injection / context manipulation likelihood (0-100) */
  context: number;
  /** On-chain threat signals (0-100) */
  transaction: number;
  /** Deviation from agent's normal behavior (0-100) */
  behavioral: number;
  /** Weighted composite score (0-100) */
  composite: number;
}

export interface SecurityReason {
  /** Short reason code (e.g., 'INFINITE_APPROVAL', 'UNVERIFIED_CONTRACT') */
  code: string;
  /** Human-readable description */
  message: string;
  /** Severity of this finding */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Which analysis component produced this reason */
  source: 'context' | 'transaction' | 'behavioral' | 'address' | 'contract' | 'policy';
}

// ---------------------------------------------------------------------------
// Transaction Types
// ---------------------------------------------------------------------------

export interface TransactionRequest {
  /** Target address */
  to: string;
  /** Value in wei (as string for BigInt compatibility) */
  value?: string;
  /** Encoded calldata */
  data?: string;
  /** Chain ID */
  chainId: number;
  /** Gas limit */
  gasLimit?: string;
  /** Max fee per gas (EIP-1559) */
  maxFeePerGas?: string;
  /** Max priority fee per gas (EIP-1559) */
  maxPriorityFeePerGas?: string;
  /** Nonce (if specified) */
  nonce?: number;
}

export interface DecodedTransaction {
  /** Original request */
  raw: TransactionRequest;
  /** Decoded function name (if ABI available) */
  functionName?: string;
  /** Decoded function parameters */
  parameters?: Record<string, unknown>;
  /** ABI used for decoding */
  abi?: string;
  /** Contract name (if known) */
  contractName?: string;
  /** Whether this is a token approval */
  isApproval: boolean;
  /** Whether this is a token transfer */
  isTransfer: boolean;
  /** Whether this involves ETH value */
  involvesEth: boolean;
  /** Total estimated USD value at risk */
  estimatedValueUsd: number;
}

// ---------------------------------------------------------------------------
// Conversation Context (for LLM-aware evaluation)
// ---------------------------------------------------------------------------

export interface ConversationContext {
  /** Recent conversation messages */
  messages: ConversationMessage[];
  /** The specific message/instruction that triggered this transaction */
  triggeringMessage?: ConversationMessage;
  /** Source identification */
  source: InstructionSource;
  /** Tool call chain that led to this transaction */
  toolCallChain?: ToolCallRecord[];
}

export interface ConversationMessage {
  /** Role of the message sender */
  role: 'user' | 'assistant' | 'system' | 'tool';
  /** Message content */
  content: string;
  /** ISO timestamp */
  timestamp?: string;
}

export interface InstructionSource {
  /** What type of source issued this instruction */
  type: 'user' | 'mcp-server' | 'skill' | 'tool' | 'system' | 'unknown';
  /** Identifier for the source (e.g., MCP server name) */
  identifier: string;
  /** Trust level assigned to this source */
  trustLevel: 'high' | 'medium' | 'low' | 'untrusted';
}

export interface ToolCallRecord {
  /** Tool name */
  tool: string;
  /** Tool input (sanitized) */
  input: string;
  /** Tool output (sanitized) */
  output?: string;
  /** Timestamp */
  timestamp?: string;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export interface BlockEvent {
  /** The verdict that caused the block */
  verdict: SecurityVerdict;
  /** The transaction that was blocked */
  transaction: TransactionRequest;
  /** Decoded transaction details */
  decoded?: DecodedTransaction;
}

export interface AdvisoryEvent {
  /** The verdict with advisory findings */
  verdict: SecurityVerdict;
  /** The transaction being evaluated */
  transaction: TransactionRequest;
}

export interface ThreatEvent {
  /** Type of threat detected */
  threatType: string;
  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Details */
  details: string;
  /** Address involved (if applicable) */
  address?: string;
}

export interface FreezeEvent {
  /** Reason for emergency freeze */
  reason: string;
  /** Details of what triggered the freeze */
  details: string;
  /** Timestamp */
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Output Filter
// ---------------------------------------------------------------------------

export interface OutputFilter {
  /** Filter text output before it reaches any destination */
  filterText(text: string): FilterResult;
  /** Filter structured data (tool outputs, API responses) */
  filterData(data: unknown): FilterResult;
}

export interface FilterResult {
  /** Sanitized output */
  filtered: string;
  /** What was redacted and why */
  redactions: Redaction[];
  /** Whether the entire output should be suppressed */
  blocked: boolean;
}

export interface Redaction {
  /** What type of sensitive data was found */
  type: 'private_key' | 'seed_phrase' | 'mnemonic' | 'keystore' | 'internal_config' | 'address_correlation';
  /** Position in original text (start index) */
  start: number;
  /** Position in original text (end index) */
  end: number;
  /** What it was replaced with */
  replacement: string;
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

export interface AuditEntry {
  /** Unique evaluation ID */
  evaluationId: string;
  /** ISO timestamp */
  timestamp: string;
  /** Transaction that was evaluated */
  transaction: TransactionRequest;
  /** Verdict produced */
  verdict: SecurityVerdict;
  /** Context provided (if any) - stored without sensitive data */
  contextSummary?: string;
  /** Whether the transaction was ultimately executed */
  executed: boolean;
}

// ---------------------------------------------------------------------------
// Address & Contract Intelligence
// ---------------------------------------------------------------------------

export interface AddressReputation {
  /** The address analyzed */
  address: string;
  /** Overall reputation score (0-100, higher = safer) */
  score: number;
  /** Whether this address is on a known denylist */
  isDenylisted: boolean;
  /** Whether this address is on the operator's allowlist */
  isAllowlisted: boolean;
  /** Address age in days (from first on-chain activity) */
  ageDays: number;
  /** Total transaction count */
  transactionCount: number;
  /** Known labels (e.g., 'Uniswap V3 Router', 'Aave Lending Pool') */
  labels: string[];
  /** Whether the contract code is verified on block explorer */
  isVerified?: boolean;
  /** Risk factors identified */
  riskFactors: string[];
}

export interface ContractAnalysis {
  /** The contract address analyzed */
  address: string;
  /** Whether the contract is verified */
  isVerified: boolean;
  /** Whether it's a proxy contract */
  isProxy: boolean;
  /** Implementation address (if proxy) */
  implementationAddress?: string;
  /** Dangerous patterns detected */
  dangerousPatterns: ContractPattern[];
  /** Whether infinite approval is possible via this contract */
  allowsInfiniteApproval: boolean;
  /** Whether the contract has self-destruct capability */
  hasSelfDestruct: boolean;
  /** Whether the contract uses delegatecall to unknown targets */
  hasUnsafeDelegatecall: boolean;
  /** Overall risk assessment */
  risk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

// ---------------------------------------------------------------------------
// Signer Interface
// ---------------------------------------------------------------------------

export interface WardexSigner {
  /** Sign a transaction that has been approved by Wardex */
  signTransaction(
    tx: TransactionRequest,
    approvalToken: string
  ): Promise<string>;

  /** Get the signer's public address (never the private key) */
  getAddress(): Promise<string>;

  /** Check if the signer is available and healthy */
  healthCheck(): Promise<boolean>;

  /** Sign a message (with Wardex approval) */
  signMessage(
    message: string,
    approvalToken: string
  ): Promise<string>;
}

// ---------------------------------------------------------------------------
// Middleware Pipeline
// ---------------------------------------------------------------------------

export interface MiddlewareContext {
  /** The original transaction request */
  transaction: TransactionRequest;
  /** Decoded transaction (populated by decoder middleware) */
  decoded?: DecodedTransaction;
  /** Conversation context (if provided) */
  conversationContext?: ConversationContext;
  /** Accumulated risk scores from each middleware */
  riskScores: Partial<RiskScore>;
  /** Accumulated security reasons from each middleware */
  reasons: SecurityReason[];
  /** Address reputation (populated by address checker) */
  addressReputation?: AddressReputation;
  /** Contract analysis (populated by contract analyzer) */
  contractAnalysis?: ContractAnalysis;
  /** The policy being applied */
  policy: SecurityPolicy;
  /** Which tier was determined */
  tier?: SecurityTierConfig;
  /** Metadata for audit trail */
  metadata: Record<string, unknown>;
}

export type Middleware = (
  ctx: MiddlewareContext,
  next: () => Promise<void>
) => Promise<void>;

// ---------------------------------------------------------------------------
// WardexShield - Main Interface
// ---------------------------------------------------------------------------

export interface WardexShield {
  /** Evaluate a transaction before execution */
  evaluate(tx: TransactionRequest): Promise<SecurityVerdict>;

  /** Evaluate with full conversation context (for LLM integrations) */
  evaluateWithContext(
    tx: TransactionRequest,
    context: ConversationContext
  ): Promise<SecurityVerdict>;

  /** Get the output filter for LLM response sanitization */
  outputFilter: OutputFilter;

  /** Get current security status */
  getStatus(): SecurityStatus;

  /**
   * Update policy at runtime.
   * C-04 FIX: Requires operator secret for authentication.
   * If operatorSecret was set in WardexConfig, the same secret must be
   * provided here. Without it, policy changes are rejected.
   */
  updatePolicy(policy: Partial<SecurityPolicy>, operatorSecret?: string): void;

  /** Get the audit log */
  getAuditLog(limit?: number): AuditEntry[];

  /** Register a custom middleware */
  use(middleware: Middleware): void;

  /** Check if the system is in freeze mode */
  isFrozen(): boolean;

  /** Manually trigger emergency freeze */
  freeze(reason: string): void;

  /**
   * Resume from freeze.
   * C-04 FIX: Requires operator secret for authentication.
   */
  unfreeze(operatorSecret?: string): void;
}

export interface SecurityStatus {
  /** Current enforcement mode */
  mode: EnforcementMode;
  /** Whether the system is frozen */
  frozen: boolean;
  /** Number of evaluations performed */
  evaluationCount: number;
  /** Number of transactions blocked */
  blockCount: number;
  /** Number of advisories issued */
  advisoryCount: number;
  /** Current daily volume (wei string) */
  dailyVolumeWei: string;
  /** Signer health status */
  signerHealthy: boolean;
  /** Intelligence feed last updated */
  intelligenceLastUpdated?: string;
}
