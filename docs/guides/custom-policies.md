# Configure Custom Policies

The security policy controls every aspect of how Wardex evaluates transactions. Start with `defaultPolicy()` and customize from there.

---

## Step 1: Start with the Default Policy

```typescript
import { createWardex, defaultPolicy } from '@wardexai/core';

const policy = defaultPolicy();
// Returns a fully configured policy with sensible defaults
```

**Default settings:**

| Setting | Default | Description |
|---|---|---|
| Tiers | Audit / Co-pilot / Guardian / Fortress | 4-tier adaptive system |
| Max per-tx | 10 ETH | Single transaction limit |
| Max daily | 50 ETH | Daily cumulative limit |
| Max approval | 1000 tokens | Token approval limit |
| Max gas | 100 gwei | Gas price ceiling |
| Behavioral detection | Enabled, medium sensitivity | 7-day learning period |
| Prompt injection detection | Enabled | All 10+ patterns active |
| Coherence checking | Enabled | Cross-message analysis |

---

## Step 2: Customize Allowlists

Add trusted addresses, contracts, and protocols that reduce risk scoring.

```typescript
// Trust specific DeFi protocols
policy.allowlists.contracts.push(
  '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap V3 Router
  '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2', // Aave V3 Pool
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
);

// Trust specific EOAs
policy.allowlists.addresses.push(
  '0x...treasury',   // Your treasury wallet
  '0x...operator',   // Your operator account
);

// Trust protocol identifiers (used by address checker labels)
policy.allowlists.protocols.push('uniswap-v3', 'aave-v3', 'compound-v3');
```

> **Note**: Allowlisted addresses still go through the full evaluation pipeline. Allowlisting reduces the risk score but does not bypass checks.

---

## Step 3: Customize Denylists

Add known-bad addresses and contract patterns.

```typescript
// Block specific malicious addresses
policy.denylists.addresses.push(
  '0xdead000000000000000000000000000000000001', // Known scammer
  '0xbad0000000000000000000000000000000000002',  // Phishing contract
);

// Block bytecode patterns
policy.denylists.patterns.push({
  name: 'Hidden fee extractor',
  pattern: 'ff.*selfdestruct.*transfer', // regex pattern
  severity: 'critical',
  description: 'Contract that self-destructs after extracting fees',
});
```

---

## Step 4: Adjust Transaction Limits

```typescript
// For a high-value DeFi bot
policy.limits.maxTransactionValueWei = '50000000000000000000';  // 50 ETH
policy.limits.maxDailyVolumeWei = '200000000000000000000';      // 200 ETH
policy.limits.maxApprovalAmountWei = '10000000000000000000000';  // 10K tokens
policy.limits.maxGasPriceGwei = 200; // Higher gas tolerance for time-sensitive trades
```

```typescript
// For a conservative custody bot
policy.limits.maxTransactionValueWei = '1000000000000000000';   // 1 ETH
policy.limits.maxDailyVolumeWei = '5000000000000000000';        // 5 ETH
policy.limits.maxApprovalAmountWei = '0';                        // No approvals at all
policy.limits.maxGasPriceGwei = 50;
```

---

## Step 5: Adjust Security Tiers

```typescript
// Move Fortress tier to start at $5K instead of $10K
policy.tiers[3].triggers.minValueAtRiskUsd = 5000;

// Make Guardian tier stricter (block at score 50 instead of 70)
policy.tiers[2].enforcement.blockThreshold = 50;

// Require human approval for all Guardian+ transactions
policy.tiers[2].enforcement.requireHumanApproval = true;

// Add a time-lock for Guardian tier (5 minutes)
policy.tiers[2].enforcement.timeLockSeconds = 300;
```

### Custom Tier Example: Protocol-Specific

```typescript
import type { SecurityTierConfig } from '@wardexai/core';

// Create a custom tier for Uniswap operations up to $50K
const uniswapTier: SecurityTierConfig = {
  id: 'uniswap-trading',
  name: 'Uniswap Trading',
  triggers: {
    targetAddresses: ['0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45'],
    minValueAtRiskUsd: 0,
    maxValueAtRiskUsd: 50_000,
  },
  enforcement: {
    mode: 'guardian',
    blockThreshold: 80,          // More permissive for known protocol
    requireHumanApproval: false,
    notifyOperator: true,
    requireOnChainProof: false,
  },
};

// Insert before the default Fortress tier
policy.tiers.splice(3, 0, uniswapTier);
```

---

## Step 6: Configure Behavioral Detection

```typescript
// High-sensitivity for custody applications
policy.behavioral.enabled = true;
policy.behavioral.sensitivityLevel = 'high';
policy.behavioral.learningPeriodDays = 14; // 2 weeks of baseline

// Disable for testing/development
policy.behavioral.enabled = false;
```

| Sensitivity | Value Anomaly Threshold | Frequency Threshold | Best For |
|---|---|---|---|
| `'low'` | 5x baseline | 10x baseline | High-frequency trading bots |
| `'medium'` | 3x baseline | 5x baseline | General-purpose agents |
| `'high'` | 2x baseline | 3x baseline | Custody, treasury management |

---

## Step 7: Configure Context Analysis

```typescript
// Add custom suspicious patterns
policy.contextAnalysis.suspiciousPatterns.push(
  'send all',           // "send all ETH to..."
  'drain',              // "drain the wallet"
  'emergency transfer', // social engineering
);

// Disable coherence checking (for non-conversational agents)
policy.contextAnalysis.enableCoherenceChecking = false;

// Disable escalation detection (for batch processing)
policy.contextAnalysis.enableEscalationDetection = false;
```

---

## Step 8: Apply the Policy

```typescript
const wardex = createWardex({
  policy,
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex.sock' },
  mode: 'adaptive',
});
```

### Update Policy at Runtime

```typescript
// Tighten limits without restarting
wardex.updatePolicy({
  limits: {
    maxTransactionValueWei: '500000000000000000', // Reduce to 0.5 ETH
    maxDailyVolumeWei: '2000000000000000000',     // Reduce to 2 ETH
    maxApprovalAmountWei: '0',                     // Block all approvals
    maxGasPriceGwei: 30,
  },
});
```

> **Note**: `updatePolicy()` uses `mergePolicy()` internally — arrays (allowlists, denylists) are concatenated, objects are shallow-merged, and tiers are replaced entirely if provided.

---

## Policy Templates

### DeFi Trading Bot

```typescript
const policy = defaultPolicy();
policy.allowlists.contracts.push(UNISWAP, AAVE, COMPOUND);
policy.limits.maxTransactionValueWei = '50000000000000000000'; // 50 ETH
policy.limits.maxDailyVolumeWei = '200000000000000000000';     // 200 ETH
policy.behavioral.sensitivityLevel = 'low'; // Frequent trades are normal
```

### NFT Marketplace Agent

```typescript
const policy = defaultPolicy();
policy.allowlists.contracts.push(OPENSEA, BLUR, RESERVOIR);
policy.limits.maxApprovalAmountWei = '1'; // Minimal approvals
policy.behavioral.sensitivityLevel = 'medium';
policy.contextAnalysis.enableEscalationDetection = true;
```

### Treasury Management

```typescript
const policy = defaultPolicy();
policy.tiers[2].enforcement.requireHumanApproval = true; // Human for Guardian+
policy.tiers[3].triggers.minValueAtRiskUsd = 1000;       // Fortress at $1K
policy.limits.maxApprovalAmountWei = '0';                 // No approvals
policy.behavioral.sensitivityLevel = 'high';
```

---

## What's Next?

- **[Custom Middleware](./custom-middleware.md)** — Add domain-specific security checks
- **[Security Tiers Reference](../security/security-tiers.md)** — Full tier documentation
- **[API Reference](../api-reference/types.md)** — Complete type definitions
