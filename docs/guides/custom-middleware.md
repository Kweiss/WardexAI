# Write Custom Middleware

Wardex's middleware pipeline is extensible. You can insert custom checks between the built-in stages to add domain-specific security logic.

---

## How Middleware Works

Each middleware is an async function that receives a shared context and a `next()` function. Call `next()` to continue to the next stage. Don't call `next()` to short-circuit the pipeline.

```typescript
import type { Middleware, MiddlewareContext } from '@wardexai/core';

const myMiddleware: Middleware = async (ctx, next) => {
  // 1. Read from ctx (transaction, decoded, addressReputation, etc.)
  // 2. Add findings to ctx.reasons
  // 3. Update ctx.riskScores
  // 4. Call next() to continue the pipeline
  await next();
  // 5. Optionally inspect the verdict after downstream stages
};
```

### Pipeline Position

Custom middleware runs **after** all built-in checkers and **before** the risk aggregator:

```
contextAnalyzer → transactionDecoder → valueAssessor → addressChecker →
contractChecker → behavioralComparator → [YOUR MIDDLEWARE] → riskAggregator → policyEngine
```

This means your middleware has access to:
- `ctx.decoded` — decoded function name, parameters, isApproval, isTransfer
- `ctx.addressReputation` — address age, denylist status, labels
- `ctx.contractAnalysis` — bytecode patterns, proxy detection, risk level
- `ctx.riskScores` — context, transaction, behavioral scores so far
- `ctx.reasons` — all findings from upstream stages
- `ctx.tier` — which security tier was determined

---

## Step 1: Register Custom Middleware

```typescript
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex.sock' },
  mode: 'adaptive',
});

wardex.use(async (ctx, next) => {
  // Your custom logic here
  await next();
});
```

---

## Example: Block New Contracts

Block any interaction with contracts deployed less than 24 hours ago.

```typescript
wardex.use(async (ctx, next) => {
  if (ctx.addressReputation && ctx.addressReputation.ageDays < 1) {
    ctx.reasons.push({
      code: 'CONTRACT_TOO_NEW',
      message: `Contract ${ctx.transaction.to} was deployed less than 24 hours ago`,
      severity: 'high',
      source: 'contract',
    });
    ctx.riskScores.transaction = Math.max(ctx.riskScores.transaction ?? 0, 80);
  }
  await next();
});
```

---

## Example: Protocol-Specific Validation

Validate that Uniswap swaps have reasonable slippage.

```typescript
const UNISWAP_ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const SWAP_SELECTOR = '0x38ed1739'; // swapExactTokensForTokens

wardex.use(async (ctx, next) => {
  const to = ctx.transaction.to?.toLowerCase();
  const data = ctx.transaction.data?.toLowerCase();

  if (to === UNISWAP_ROUTER && data?.startsWith(SWAP_SELECTOR)) {
    // Check if decoded parameters indicate high slippage
    if (ctx.decoded?.parameters) {
      const amountOutMin = ctx.decoded.parameters['amountOutMin'];
      const amountIn = ctx.decoded.parameters['amountIn'];

      if (amountIn && amountOutMin) {
        const slippage = 1 - Number(amountOutMin) / Number(amountIn);
        if (slippage > 0.05) { // > 5% slippage
          ctx.reasons.push({
            code: 'HIGH_SLIPPAGE',
            message: `Swap has ${(slippage * 100).toFixed(1)}% slippage (>5% threshold)`,
            severity: 'medium',
            source: 'transaction',
          });
          ctx.riskScores.transaction = Math.max(ctx.riskScores.transaction ?? 0, 40);
        }
      }
    }
  }
  await next();
});
```

---

## Example: Time-Based Restrictions

Block transactions outside business hours.

```typescript
wardex.use(async (ctx, next) => {
  const hour = new Date().getUTCHours();
  const isBusinessHours = hour >= 8 && hour < 20; // 8 AM - 8 PM UTC

  if (!isBusinessHours && (ctx.decoded?.estimatedValueUsd ?? 0) > 1000) {
    ctx.reasons.push({
      code: 'OUTSIDE_BUSINESS_HOURS',
      message: 'High-value transaction attempted outside business hours (08:00-20:00 UTC)',
      severity: 'medium',
      source: 'policy',
    });
    ctx.riskScores.behavioral = Math.max(ctx.riskScores.behavioral ?? 0, 50);
  }
  await next();
});
```

---

## Example: Rate Limiting

Limit the number of transactions per minute.

```typescript
const recentTxTimestamps: number[] = [];
const MAX_TX_PER_MINUTE = 10;

wardex.use(async (ctx, next) => {
  const now = Date.now();
  // Clean old timestamps
  while (recentTxTimestamps.length > 0 && recentTxTimestamps[0] < now - 60_000) {
    recentTxTimestamps.shift();
  }

  if (recentTxTimestamps.length >= MAX_TX_PER_MINUTE) {
    ctx.reasons.push({
      code: 'RATE_LIMIT_EXCEEDED',
      message: `More than ${MAX_TX_PER_MINUTE} transactions in the last minute`,
      severity: 'high',
      source: 'behavioral',
    });
    ctx.riskScores.behavioral = Math.max(ctx.riskScores.behavioral ?? 0, 90);
  }

  recentTxTimestamps.push(now);
  await next();
});
```

---

## Example: External API Check

Call an external threat intelligence API.

```typescript
wardex.use(async (ctx, next) => {
  const address = ctx.transaction.to;
  if (!address) {
    await next();
    return;
  }

  try {
    const response = await fetch(`https://api.threatfeed.example/check/${address}`, {
      signal: AbortSignal.timeout(2000), // 2s timeout
    });

    if (response.ok) {
      const result = await response.json();
      if (result.isMalicious) {
        ctx.reasons.push({
          code: 'EXTERNAL_THREAT_FEED',
          message: `Address flagged by threat feed: ${result.reason}`,
          severity: 'critical',
          source: 'address',
        });
        ctx.riskScores.transaction = 95;
      }
    }
  } catch {
    // External API failure should not block the pipeline
    // The built-in checks still run
  }

  await next();
});
```

> **Important**: Always set a timeout on external calls. The pipeline should not hang if an external service is down.

---

## MiddlewareContext Reference

| Field | Type | Available After | Description |
|---|---|---|---|
| `ctx.transaction` | `TransactionRequest` | Always | The original transaction |
| `ctx.decoded` | `DecodedTransaction` | `transactionDecoder` | Decoded function name, params |
| `ctx.conversationContext` | `ConversationContext` | Always (if provided) | Conversation context |
| `ctx.riskScores` | `Partial<RiskScore>` | Varies | Accumulated scores |
| `ctx.reasons` | `SecurityReason[]` | Varies | Accumulated findings |
| `ctx.addressReputation` | `AddressReputation` | `addressChecker` | Address age, labels |
| `ctx.contractAnalysis` | `ContractAnalysis` | `contractChecker` | Bytecode analysis |
| `ctx.policy` | `SecurityPolicy` | Always | Current policy |
| `ctx.tier` | `SecurityTierConfig` | `valueAssessor` | Selected security tier |
| `ctx.metadata` | `Record<string, unknown>` | Always | Metadata bag |

---

## Best Practices

1. **Always call `next()`** unless you intentionally want to short-circuit the pipeline
2. **Set timeouts on external calls** — the pipeline should fail open, not hang
3. **Use appropriate severity levels** — `critical` findings override tier enforcement
4. **Add both a reason AND a risk score** — the aggregator needs scores, the verdict needs reasons
5. **Don't mutate `ctx.transaction`** — it's the original request and should stay unchanged
6. **Use `ctx.metadata`** for passing data between custom middlewares

---

## What's Next?

- **[Core Concepts: Pipeline](../core-concepts.md#middleware-pipeline)** — Pipeline architecture details
- **[Custom Policies](./custom-policies.md)** — Policy configuration without custom code
- **[API Reference: Types](../api-reference/types.md)** — Full MiddlewareContext type reference
