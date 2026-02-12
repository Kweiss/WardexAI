# Wardex Operator Quickstart

Get your AI agent protected in under 5 minutes.

## Prerequisites

- Node.js 20+
- An AI agent that signs Ethereum transactions (via ethers.js, viem, or MCP tools)

## Install

```bash
npm install @wardexai/core @wardexai/signer
# Optional: on-chain intelligence
npm install @wardexai/intelligence
```

## 1. Basic Setup (5 lines)

```typescript
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/agent-signer.sock' },
  mode: 'adaptive',
});
```

That's it. Your agent now has a full security evaluation pipeline.

## 2. Evaluate Transactions

Every transaction your agent wants to sign should go through Wardex first:

```typescript
const verdict = await wardex.evaluate({
  to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap V3
  value: '100000000000000000', // 0.1 ETH
  chainId: 1,
});

if (verdict.decision === 'approve') {
  // Safe to sign and send
} else if (verdict.decision === 'advise') {
  // Warn user, ask for confirmation
  console.log('Risks:', verdict.reasons.map(r => r.message));
} else {
  // Block or freeze - do NOT proceed
  console.log('BLOCKED:', verdict.reasons.map(r => r.message));
}
```

## 3. Detect Prompt Injection

If your agent gets instructions from LLM conversations or MCP tools, pass the context:

```typescript
const verdict = await wardex.evaluateWithContext(transaction, {
  messages: conversationHistory,
  source: {
    type: 'mcp-server',
    identifier: 'defi-skill',
    trustLevel: 'medium',
  },
  toolCallChain: recentToolCalls,
});
```

Wardex detects 10+ injection patterns including "ignore previous instructions", base64 encoded commands, role overrides, and cross-MCP manipulation.

## 4. Filter Agent Output

Prevent your agent from leaking keys or seed phrases in its responses:

```typescript
const filtered = wardex.outputFilter.filterText(agentResponse);
// Any private keys, seed phrases, or keystore data → [REDACTED BY WARDEX]
const safeResponse = filtered.filtered;
```

## 5. Drop-in Provider Wrappers

Wrap your existing ethers.js or viem provider — zero code changes required:

### ethers.js v6
```typescript
import { wrapEthersProvider } from '@wardexai/core/providers/ethers';

const protectedProvider = wrapEthersProvider(existingProvider, wardex);
// Use protectedProvider exactly like your original provider
// All sendTransaction calls are automatically evaluated
```

### viem
```typescript
import { wrapViemClient } from '@wardexai/core/providers/viem';

const protectedClient = wrapViemClient(existingClient, wardex);
// Use protectedClient exactly like your original client
```

## 6. Session Keys (ERC-7715)

Scope your agent's signing authority with time-bounded, contract-limited sessions:

```typescript
import { SessionManager } from '@wardexai/signer';

const sessions = new SessionManager();
const session = sessions.createSession({
  allowedContracts: ['0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'], // Uniswap only
  maxValuePerTx: '1000000000000000000',    // 1 ETH max per tx
  maxDailyVolume: '10000000000000000000',   // 10 ETH daily cap
  durationSeconds: 3600,                     // 1 hour session
  forbidInfiniteApprovals: true,             // Block unlimited approvals
});

// Validate every transaction against session limits
const check = sessions.validateTransaction(session.id, tx.to, tx.value);
if (!check.valid) {
  console.log('Session rejected:', check.reason);
}
```

## 7. Claude Code Integration

### As MCP Server
```bash
claude mcp add wardex npx @wardexai/mcp-server
```

### As Skill with PreToolUse Hooks
```bash
npm install @wardexai/claude-skill
# Merge settings-template.json into your .claude/settings.json
```

The hooks automatically intercept wallet MCP tool calls (`mcp__wallet__*`, `mcp__eth__*`, etc.) and evaluate them before execution.

## 8. On-Chain Defense (Smart Account)

Deploy the WardexValidationModule to your ERC-4337 smart account for defense in depth:

```bash
cd packages/contracts
forge build
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

Even if the SDK is bypassed, on-chain spending limits and approval verification hold.

---

## Customizing the Policy

### Add Trusted Contracts
```typescript
const policy = defaultPolicy();
policy.allowlists.contracts.push(
  '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D', // Uniswap V2
);
```

### Block Known Attackers
```typescript
policy.denylists.addresses.push(
  '0xdead000000000000000000000000000000000001',
);
```

### Adjust Security Tiers
```typescript
// Make the Guardian tier (default: $100-$10K) stricter
policy.tiers[2].enforcement.blockThreshold = 50; // Block at score 50 (default 70)
```

### Set Transaction Limits
```typescript
policy.limits.maxTransactionValueWei = '5000000000000000000'; // 5 ETH max per tx
policy.limits.maxDailyVolumeWei = '50000000000000000000';     // 50 ETH daily
```

### Enable Intelligence Feeds
```typescript
const wardex = createWardex({
  policy,
  signer: { type: 'isolated-process', endpoint: '/tmp/signer.sock' },
  mode: 'adaptive',
  intelligence: {
    rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    chainId: 1,
    denylistPath: './denylist.json',
    explorerApiKey: 'YOUR_ETHERSCAN_KEY',
  },
});
```

### Event Handlers
```typescript
const wardex = createWardex({
  // ...config
  onBlock: (event) => {
    // Alert your monitoring system
    alertSlack(`Transaction blocked: ${event.verdict.reasons[0].message}`);
  },
  onFreeze: (event) => {
    // Emergency: agent is under attack
    alertPagerDuty(`WARDEX FREEZE: ${event.reason}`);
  },
  onThreat: (event) => {
    // Threat intelligence signal
    logThreat(event.threatType, event.severity, event.details);
  },
});
```

---

## Security Tiers Reference

| Tier | Value at Risk | Mode | Blocks? | Human Required? |
|------|--------------|------|---------|-----------------|
| Audit | < $1 | Log only | Never | No |
| Co-pilot | $1 - $100 | Advisory | No | No |
| Guardian | $100 - $10K | Full eval | Score > 70 | On block only |
| Fortress | > $10K | Full eval + delay | Always | Always |
| Freeze | Active attack | Emergency halt | Everything | Required to resume |

**Critical override**: Prompt injection, denylisted addresses, and SELFDESTRUCT contracts are blocked at Guardian tier and above regardless of composite score.

## What Gets Caught

- Infinite token approvals (`type(uint256).max`)
- Transactions to known exploit addresses
- Prompt injection in MCP tool outputs
- Private key / seed phrase leakage in agent responses
- Behavioral anomalies (sudden value spikes, unusual contracts)
- Unverified proxy contracts with SELFDESTRUCT or unsafe delegatecall
- Cross-MCP source manipulation
- Social engineering escalation patterns
- Daily volume limit breaches
