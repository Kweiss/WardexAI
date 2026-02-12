# @wardexai/core API Reference

The core package provides the main Wardex security shield, policy management, output filtering, provider wrappers, and the middleware pipeline for evaluating AI agent transactions.

## Installation

```bash
npm install @wardexai/core
```

## Imports

```typescript
import {
  createWardex,
  createShield,
  defaultPolicy,
  mergePolicy,
  createOutputFilter,
  wrapEthersSigner,
  wrapViemWalletClient,
  WardexBlockedError,
  compose,
  createMiddlewareContext,
  // Middleware factories (for custom pipeline construction)
  createContextAnalyzer,
  transactionDecoder,
  createAddressChecker,
  createValueAssessor,
  createContractChecker,
  createBehavioralComparator,
  riskAggregator,
  policyEngine,
} from '@wardexai/core';
```

---

## createWardex

Creates a new Wardex security shield. This is the recommended entry point for initializing Wardex. Validates that all required configuration fields are present before delegating to `createShield`.

### Import

```typescript
import { createWardex } from '@wardexai/core';
```

### Usage

```typescript
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: 'unix:///tmp/wardex-signer.sock' },
  mode: 'adaptive',
});

const verdict = await wardex.evaluate({
  to: '0x1234567890abcdef1234567890abcdef12345678',
  value: '1000000000000000000', // 1 ETH in wei
  chainId: 1,
});

if (verdict.decision === 'approve') {
  // Safe to proceed
} else {
  console.log('Blocked:', verdict.reasons);
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | [`WardexConfig`](./types.md#wardexconfig) | Yes | Full configuration including policy, signer, and enforcement mode. |

#### config.policy

```typescript
const wardex = createWardex({
  policy: defaultPolicy(),
  // ...
});
```

Type: [`SecurityPolicy`](./types.md#securitypolicy) -- The operator-defined security policy. Use `defaultPolicy()` for sensible defaults.

#### config.signer

```typescript
const wardex = createWardex({
  signer: { type: 'isolated-process', endpoint: 'unix:///tmp/wardex-signer.sock' },
  // ...
});
```

Type: [`SignerConfig`](./types.md#signerconfig) -- Connection configuration for the isolated signer process. The AI agent must never have direct key access.

#### config.mode

```typescript
const wardex = createWardex({
  mode: 'adaptive',
  // ...
});
```

Type: `'guardian' | 'copilot' | 'adaptive'` -- The enforcement mode. `adaptive` adjusts enforcement based on the value-at-risk tier.

#### config.intelligence

```typescript
const wardex = createWardex({
  intelligence: {
    rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    chainId: 1,
    explorerApiKey: 'YOUR_ETHERSCAN_KEY',
  },
  // ...
});
```

Type: [`IntelligenceConfig`](./types.md#intelligenceconfig) (optional) -- Threat intelligence sources for on-chain address and contract analysis.

#### config.agentIdentity

```typescript
const wardex = createWardex({
  agentIdentity: {
    registryAddress: '0x...',
    agentId: 'agent-001',
    chainId: 1,
  },
  // ...
});
```

Type: [`AgentIdentityConfig`](./types.md#agentidentityconfig) (optional) -- ERC-8004 agent identity for on-chain trust signals.

#### config.onBlock

```typescript
const wardex = createWardex({
  onBlock: (event) => {
    console.log('Transaction blocked:', event.verdict.reasons);
  },
  // ...
});
```

Type: `(event: BlockEvent) => void` (optional) -- Callback invoked when a transaction is blocked.

#### config.onAdvisory

```typescript
const wardex = createWardex({
  onAdvisory: (event) => {
    console.log('Advisory:', event.verdict.reasons);
  },
  // ...
});
```

Type: `(event: AdvisoryEvent) => void` (optional) -- Callback invoked when an advisory finding is produced.

#### config.onThreat

```typescript
const wardex = createWardex({
  onThreat: (event) => {
    console.log('Threat detected:', event.threatType, event.details);
  },
  // ...
});
```

Type: `(event: ThreatEvent) => void` (optional) -- Callback invoked when a threat is detected (including auto-freeze triggers).

#### config.onFreeze

```typescript
const wardex = createWardex({
  onFreeze: (event) => {
    console.log('FROZEN:', event.reason);
    alertOperator(event);
  },
  // ...
});
```

Type: `(event: FreezeEvent) => void` (optional) -- Callback invoked when the system enters emergency freeze.

### Return Type

```typescript
function createWardex(config: WardexConfig): WardexShield
```

Returns a [`WardexShield`](#wardexshield-interface) instance.

### Errors

- Throws `Error` if `config.policy` is not provided.
- Throws `Error` if `config.signer` is not provided.
- Throws `Error` if `config.mode` is not provided.

---

## createShield

Lower-level factory that creates a `WardexShield` without input validation. Used internally by `createWardex`. Use this when you need to construct the shield with pre-validated configuration.

### Import

```typescript
import { createShield } from '@wardexai/core';
```

### Usage

```typescript
import { createShield, defaultPolicy } from '@wardexai/core';

const shield = createShield({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: 'unix:///tmp/signer.sock' },
  mode: 'adaptive',
});
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | [`WardexConfig`](./types.md#wardexconfig) | Yes | Full configuration. No validation is performed. |

### Return Type

```typescript
function createShield(config: WardexConfig): WardexShield
```

Returns a [`WardexShield`](#wardexshield-interface) instance.

---

## WardexShield Interface

The main interface returned by `createWardex` and `createShield`. Provides methods for transaction evaluation, output filtering, audit logging, and system state management.

### evaluate

Evaluates a transaction before execution. Runs the full 9-stage middleware pipeline (context analysis, transaction decoding, value assessment, address checking, contract checking, behavioral comparison, custom middleware, risk aggregation, policy engine).

```typescript
evaluate(tx: TransactionRequest): Promise<SecurityVerdict>
```

#### Usage

```typescript
const verdict = await shield.evaluate({
  to: '0xdead...beef',
  value: '500000000000000000', // 0.5 ETH
  chainId: 1,
});

switch (verdict.decision) {
  case 'approve':
    // Safe to sign and send
    break;
  case 'advise':
    // Proceed with caution, log advisory
    console.warn(verdict.reasons);
    break;
  case 'block':
    // Do not execute
    console.error('Blocked:', verdict.reasons);
    break;
  case 'freeze':
    // System frozen, contact operator
    break;
}
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tx` | [`TransactionRequest`](./types.md#transactionrequest) | Yes | The transaction to evaluate. |

#### Return Type

[`Promise<SecurityVerdict>`](./types.md#securityverdict) -- The security evaluation result.

---

### evaluateWithContext

Evaluates a transaction with full conversation context. Enables prompt injection detection, coherence checking, and source verification by providing the conversation history that led to the transaction.

```typescript
evaluateWithContext(
  tx: TransactionRequest,
  context: ConversationContext
): Promise<SecurityVerdict>
```

#### Usage

```typescript
const verdict = await shield.evaluateWithContext(
  {
    to: '0xdead...beef',
    value: '1000000000000000000',
    chainId: 1,
  },
  {
    messages: [
      { role: 'user', content: 'Swap 1 ETH for USDC on Uniswap' },
      { role: 'assistant', content: 'I will execute the swap...' },
    ],
    source: {
      type: 'user',
      identifier: 'chat-session-123',
      trustLevel: 'high',
    },
  }
);
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `tx` | [`TransactionRequest`](./types.md#transactionrequest) | Yes | The transaction to evaluate. |
| `context` | [`ConversationContext`](./types.md#conversationcontext) | Yes | Conversation history and source metadata. |

#### Return Type

[`Promise<SecurityVerdict>`](./types.md#securityverdict)

---

### outputFilter

The output filter instance for sanitizing AI model responses. Detects and redacts private keys, seed phrases, mnemonics, and keystore data before they reach any destination.

```typescript
outputFilter: OutputFilter
```

#### Usage

```typescript
const result = shield.outputFilter.filterText(modelResponse);

if (result.blocked) {
  console.error('Output blocked: contains keystore data');
} else if (result.redactions.length > 0) {
  console.warn('Sensitive data redacted:', result.redactions);
  sendToUser(result.filtered); // Safe to send
} else {
  sendToUser(result.filtered);
}
```

Type: [`OutputFilter`](./types.md#outputfilter)

---

### getStatus

Returns the current security status of the shield, including evaluation counts, freeze state, and daily volume tracking.

```typescript
getStatus(): SecurityStatus
```

#### Usage

```typescript
const status = shield.getStatus();
console.log('Mode:', status.mode);
console.log('Frozen:', status.frozen);
console.log('Evaluations:', status.evaluationCount);
console.log('Blocks:', status.blockCount);
console.log('Daily volume (wei):', status.dailyVolumeWei);
```

#### Return Type

[`SecurityStatus`](./types.md#securitystatus)

---

### getAuditLog

Returns the audit log of all evaluations. The log is bounded to the last 10,000 entries.

```typescript
getAuditLog(limit?: number): AuditEntry[]
```

#### Usage

```typescript
// Get all entries
const allEntries = shield.getAuditLog();

// Get last 50 entries
const recentEntries = shield.getAuditLog(50);
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `limit` | `number` | No | If provided, returns only the last `limit` entries. |

#### Return Type

[`AuditEntry[]`](./types.md#auditentry)

---

### use

Registers a custom middleware in the pipeline. Custom middleware runs after the built-in behavioral comparator and before the risk aggregator (stage 7 of 9).

```typescript
use(middleware: Middleware): void
```

#### Usage

```typescript
shield.use(async (ctx, next) => {
  // Custom check: block all transactions to a specific address
  if (ctx.transaction.to === '0xSuspiciousAddress') {
    ctx.reasons.push({
      code: 'CUSTOM_BLOCK',
      message: 'Transaction to suspicious address blocked by custom rule',
      severity: 'critical',
      source: 'policy',
    });
    ctx.riskScores.transaction = 100;
  }
  await next();
});
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `middleware` | [`Middleware`](./types.md#middleware) | Yes | A middleware function receiving `(ctx, next)`. |

---

### isFrozen

Returns whether the system is currently in emergency freeze mode.

```typescript
isFrozen(): boolean
```

#### Usage

```typescript
if (shield.isFrozen()) {
  console.error('System is frozen. All transactions are blocked.');
}
```

#### Return Type

`boolean`

---

### freeze

Manually triggers an emergency freeze. All subsequent evaluations will return a `freeze` verdict until `unfreeze()` is called. Fires the `onFreeze` callback.

```typescript
freeze(reason: string): void
```

#### Usage

```typescript
shield.freeze('Operator detected suspicious activity');
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reason` | `string` | Yes | Human-readable reason for the freeze. |

---

### unfreeze

Resumes normal operation after an emergency freeze.

```typescript
unfreeze(): void
```

#### Usage

```typescript
shield.unfreeze();
console.log('System resumed:', shield.isFrozen()); // false
```

---

### updatePolicy

Updates the security policy at runtime. Performs a deep merge of the provided overrides with the current policy (allowlists and denylists are appended, other fields are replaced).

```typescript
updatePolicy(policy: Partial<SecurityPolicy>): void
```

#### Usage

```typescript
shield.updatePolicy({
  allowlists: {
    addresses: ['0xNewTrustedAddress'],
    contracts: [],
    protocols: [],
  },
  limits: {
    maxTransactionValueWei: '5000000000000000000', // 5 ETH
    maxDailyVolumeWei: '25000000000000000000', // 25 ETH
    maxApprovalAmountWei: '1000000000000000000000',
    maxGasPriceGwei: 200,
  },
});
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `policy` | `Partial<SecurityPolicy>` | Yes | Partial policy overrides to merge. |

---

## defaultPolicy

Returns a default security policy with sensible defaults. This is the recommended starting point for most deployments.

### Import

```typescript
import { defaultPolicy } from '@wardexai/core';
```

### Usage

```typescript
const policy = defaultPolicy();
```

### Return Type

```typescript
function defaultPolicy(): SecurityPolicy
```

Returns a [`SecurityPolicy`](./types.md#securitypolicy) with the following defaults:

| Setting | Default |
|---------|---------|
| Tiers | Audit ($0-1), Co-pilot ($1-100), Guardian ($100-10K), Fortress ($10K+) |
| Max tx value | 10 ETH (`'10000000000000000000'` wei) |
| Max daily volume | 50 ETH (`'50000000000000000000'` wei) |
| Max approval | 1000 tokens (`'1000000000000000000000'` wei) |
| Max gas price | 100 gwei |
| Behavioral detection | Enabled, 7-day learning, medium sensitivity |
| Prompt injection detection | Enabled |
| Coherence checking | Enabled |
| Escalation detection | Enabled |
| Source verification | Enabled |

---

## mergePolicy

Deep merges a partial policy override with a base policy. Allowlists and denylists are appended (not replaced). All other fields use the override value if present, otherwise the base value.

### Import

```typescript
import { mergePolicy } from '@wardexai/core';
```

### Usage

```typescript
import { defaultPolicy, mergePolicy } from '@wardexai/core';

const base = defaultPolicy();
const merged = mergePolicy(base, {
  allowlists: {
    addresses: ['0xTrustedRouter'],
    contracts: ['0xUniswapRouter'],
    protocols: ['uniswap-v3'],
  },
  limits: {
    maxTransactionValueWei: '20000000000000000000', // 20 ETH
    maxDailyVolumeWei: '100000000000000000000', // 100 ETH
    maxApprovalAmountWei: '1000000000000000000000',
    maxGasPriceGwei: 150,
  },
});
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `base` | [`SecurityPolicy`](./types.md#securitypolicy) | Yes | The base policy to merge into. |
| `overrides` | `Partial<SecurityPolicy>` | Yes | Partial overrides. Allowlists/denylists are appended. |

### Return Type

```typescript
function mergePolicy(
  base: SecurityPolicy,
  overrides: Partial<SecurityPolicy>
): SecurityPolicy
```

---

## createOutputFilter

Creates a standalone output filter for sanitizing text and structured data. The filter detects and redacts private keys (secp256k1, 64 hex characters), BIP-39 seed phrases/mnemonics (12/15/18/21/24 words), and JSON keystore file patterns.

### Import

```typescript
import { createOutputFilter } from '@wardexai/core';
```

### Usage

```typescript
const filter = createOutputFilter();

// Filter text
const result = filter.filterText('Here is a key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
console.log(result.filtered); // 'Here is a key: [REDACTED BY WARDEX]'
console.log(result.redactions); // [{ type: 'private_key', start: 15, end: 81, replacement: '...' }]

// Filter structured data
const dataResult = filter.filterData({ key: '0xac09...ff80', safe: 'hello' });
console.log(dataResult.filtered); // JSON with key redacted
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `bip39Wordlist` | `Set<string>` | No | Custom BIP-39 wordlist for mnemonic detection. Falls back to built-in common English overlap set. |

### Return Type

```typescript
function createOutputFilter(bip39Wordlist?: Set<string>): OutputFilter
```

Returns an [`OutputFilter`](./types.md#outputfilter) with two methods:

- `filterText(text: string): FilterResult` -- Filters raw text.
- `filterData(data: unknown): FilterResult` -- Serializes to JSON then filters.

---

## wrapEthersSigner

Wraps an ethers.js v6 Signer with a Proxy so that all `sendTransaction` calls are evaluated by Wardex before execution. Uses structural typing -- no hard dependency on ethers.js.

### Import

```typescript
import { wrapEthersSigner } from '@wardexai/core';
```

### Usage

```typescript
import { ethers } from 'ethers';
import { createWardex, defaultPolicy, wrapEthersSigner } from '@wardexai/core';

const provider = new ethers.JsonRpcProvider('http://localhost:8545');
const signer = await provider.getSigner();

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: 'unix:///tmp/signer.sock' },
  mode: 'adaptive',
});

const protectedSigner = wrapEthersSigner(signer, wardex);

try {
  // This sendTransaction call is automatically evaluated by Wardex
  const tx = await protectedSigner.sendTransaction({
    to: '0xRecipient',
    value: ethers.parseEther('1.0'),
  });
  console.log('Transaction sent:', tx.hash);
} catch (err) {
  if (err instanceof WardexBlockedError) {
    console.error('Blocked by Wardex:', err.verdict.reasons);
  }
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `signer` | `T extends EthersSigner` | Yes | An ethers.js v6 Signer instance. |
| `shield` | [`WardexShield`](#wardexshield-interface) | Yes | A WardexShield instance. |

### Return Type

```typescript
function wrapEthersSigner<T extends EthersSigner>(signer: T, shield: WardexShield): T
```

Returns a Proxy of the signer with `sendTransaction` intercepted.

### Behavior

- If verdict is `'approve'`: transaction proceeds normally.
- If verdict is `'advise'`: transaction proceeds, advisory is logged.
- If verdict is `'block'` or `'freeze'`: throws [`WardexBlockedError`](#wardexblockederror).

---

## wrapViemWalletClient

Wraps a viem WalletClient with a Proxy so that all `sendTransaction` calls are evaluated by Wardex before execution. Uses structural typing -- no hard dependency on viem.

### Import

```typescript
import { wrapViemWalletClient } from '@wardexai/core';
```

### Usage

```typescript
import { createWalletClient, http } from 'viem';
import { mainnet } from 'viem/chains';
import { createWardex, defaultPolicy, wrapViemWalletClient } from '@wardexai/core';

const client = createWalletClient({
  chain: mainnet,
  transport: http(),
});

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: 'unix:///tmp/signer.sock' },
  mode: 'adaptive',
});

const protectedClient = wrapViemWalletClient(client, wardex);

try {
  const hash = await protectedClient.sendTransaction({
    to: '0xRecipient',
    value: 1000000000000000000n, // 1 ETH
  });
  console.log('Transaction hash:', hash);
} catch (err) {
  if (err instanceof WardexBlockedError) {
    console.error('Blocked by Wardex:', err.verdict.reasons);
  }
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `client` | `T extends ViemWalletClient` | Yes | A viem WalletClient instance. |
| `shield` | [`WardexShield`](#wardexshield-interface) | Yes | A WardexShield instance. |

### Return Type

```typescript
function wrapViemWalletClient<T extends ViemWalletClient>(client: T, shield: WardexShield): T
```

Returns a Proxy of the wallet client with `sendTransaction` intercepted.

### Behavior

Same as [`wrapEthersSigner`](#wrapetherssigner): approve/advise proceed, block/freeze throw `WardexBlockedError`.

---

## WardexBlockedError

Custom error class thrown by provider wrappers when Wardex blocks a transaction. Contains the full `SecurityVerdict` for inspection.

### Import

```typescript
import { WardexBlockedError } from '@wardexai/core';
```

### Usage

```typescript
try {
  await protectedSigner.sendTransaction(tx);
} catch (err) {
  if (err instanceof WardexBlockedError) {
    console.log('Decision:', err.verdict.decision);
    console.log('Risk score:', err.verdict.riskScore.composite);
    console.log('Reasons:', err.verdict.reasons);
    console.log('Suggestions:', err.verdict.suggestions);
  }
}
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Always `'WardexBlockedError'`. |
| `message` | `string` | Human-readable summary of all reasons. |
| `verdict` | [`SecurityVerdict`](./types.md#securityverdict) | The full verdict that caused the block. |

### Constructor

```typescript
constructor(verdict: SecurityVerdict)
```

---

## compose

Composes an array of middleware functions into a single middleware using a Koa-style cascade pattern. Each middleware calls `next()` to pass control to the next middleware in the chain.

### Import

```typescript
import { compose } from '@wardexai/core';
```

### Usage

```typescript
import { compose, createMiddlewareContext, createContextAnalyzer, riskAggregator, policyEngine } from '@wardexai/core';

const pipeline = compose([
  createContextAnalyzer().middleware,
  riskAggregator,
  policyEngine,
]);

const ctx = createMiddlewareContext({
  transaction: { to: '0x...', chainId: 1 },
  policy: defaultPolicy(),
});

await pipeline(ctx, async () => {});
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `middlewares` | [`Middleware[]`](./types.md#middleware) | Yes | Array of middleware functions to compose. |

### Return Type

```typescript
function compose(middlewares: Middleware[]): Middleware
```

Returns a single `Middleware` function.

---

## createMiddlewareContext

Creates a fresh middleware context for a new evaluation. Provides default values for all required fields that are not specified in the overrides.

### Import

```typescript
import { createMiddlewareContext } from '@wardexai/core';
```

### Usage

```typescript
const ctx = createMiddlewareContext({
  transaction: { to: '0xTarget', value: '1000000000000000000', chainId: 1 },
  policy: defaultPolicy(),
});
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `overrides` | `Partial<MiddlewareContext>` | Yes | Partial context values. Missing fields get defaults. |

### Return Type

```typescript
function createMiddlewareContext(overrides: Partial<MiddlewareContext>): MiddlewareContext
```

Returns a [`MiddlewareContext`](./types.md#middlewarecontext).

---

## Middleware Factories

The following middleware factories are exported for custom pipeline construction. In normal usage, the built-in pipeline in `createShield` uses all of these in order.

### createContextAnalyzer

Creates the context analysis middleware for prompt injection detection.

```typescript
import { createContextAnalyzer } from '@wardexai/core';
const { middleware } = createContextAnalyzer();
```

### transactionDecoder

Stateless middleware that decodes transaction calldata.

```typescript
import { transactionDecoder } from '@wardexai/core';
```

### createAddressChecker

Creates the address checking middleware. Optionally accepts a reputation provider function.

```typescript
import { createAddressChecker } from '@wardexai/core';

// Without intelligence (denylist-only)
const checker = createAddressChecker();

// With intelligence provider
const checker = createAddressChecker(
  async (address, chainId) => getAddressReputation(address)
);
```

### createValueAssessor

Creates the value assessment middleware that calculates USD value at risk and determines the security tier.

```typescript
import { createValueAssessor } from '@wardexai/core';
const assessor = createValueAssessor();
```

### createContractChecker

Creates the contract bytecode analysis middleware. Optionally accepts an analysis provider function.

```typescript
import { createContractChecker } from '@wardexai/core';

// Without intelligence (bytecode pattern matching only)
const checker = createContractChecker();

// With intelligence provider
const checker = createContractChecker(
  async (address, chainId) => getContractAnalysis(address)
);
```

### createBehavioralComparator

Creates the behavioral anomaly detection middleware with four detectors: value anomaly, new contract interaction, transaction frequency, and timing patterns.

```typescript
import { createBehavioralComparator } from '@wardexai/core';
const { middleware } = createBehavioralComparator();
```

### riskAggregator

Stateless middleware that aggregates all individual risk scores into a weighted composite score.

```typescript
import { riskAggregator } from '@wardexai/core';
```

### policyEngine

Stateless middleware that applies policy rules and produces the final `SecurityVerdict` based on the aggregated risk score, tier enforcement settings, and critical findings.

```typescript
import { policyEngine } from '@wardexai/core';
```
