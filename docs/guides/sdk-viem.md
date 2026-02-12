# Protect a viem Agent

Add Wardex security to a viem wallet client in 5 minutes. Every `sendTransaction` call will pass through the Wardex evaluation pipeline before reaching the network -- no changes to your existing code required.

> **How it works:** `wrapViemWalletClient` returns a [Proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy) that intercepts `sendTransaction`. The return type is the same `WalletClient` you passed in, so TypeScript and all downstream code stay unchanged.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Node.js | 20+ |
| viem | 2.x |
| `@wardexai/core` | latest |

---

## Step 1: Install Packages

```bash
npm install @wardexai/core viem
```

If you want on-chain intelligence (address reputation, contract bytecode analysis), also install the intelligence package:

```bash
npm install @wardexai/intelligence
```

---

## Step 2: Create a Wardex Shield

```typescript
// wardex-setup.ts
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: {
    type: 'isolated-process',
    endpoint: '/tmp/wardex-signer.sock',
  },
  mode: 'adaptive', // security scales with value at risk
});
```

`defaultPolicy()` provides sensible defaults for all four adaptive tiers:

| Tier | Value Range | Behavior |
|---|---|---|
| Audit | $0 -- $1 | Log only, never blocks |
| Co-pilot | $1 -- $100 | Advisory warnings |
| Guardian | $100 -- $10K | Blocks when risk score >= 70 |
| Fortress | $10K+ | Blocks at >= 30, requires human approval, 15-min time lock |

> **Good to know:** `mode: 'adaptive'` is the recommended setting. It automatically applies the appropriate tier based on the USD value at risk in each transaction.

---

## Step 3: Wrap Your viem Wallet Client

```typescript
// agent.ts
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import { wrapViemWalletClient } from '@wardexai/core';

const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);

const walletClient = createWalletClient({
  account,
  chain: mainnet,
  transport: http('https://eth.llamarpc.com'),
});

// One line to add Wardex protection
const protectedClient = wrapViemWalletClient(walletClient, wardex);
```

`protectedClient` has the exact same type as `walletClient`. You can pass it anywhere a `WalletClient` is expected -- libraries like wagmi actions, Uniswap SDK, and custom contracts all work without changes.

---

## Step 4: Use the Wrapped Client Normally

```typescript
import { parseEther } from 'viem';

// Wardex evaluates every transaction automatically
const hash = await protectedClient.sendTransaction({
  to: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap Router
  value: parseEther('0.1'),
});

console.log(`Transaction sent: ${hash}`);
```

Behind the scenes, Wardex runs the full 9-stage middleware pipeline before the transaction reaches the network:

1. **Context Analyzer** -- prompt injection detection
2. **Transaction Decoder** -- decodes calldata (function name, parameters)
3. **Value Assessor** -- calculates USD value at risk
4. **Address Checker** -- reputation and denylist lookup
5. **Contract Checker** -- bytecode pattern analysis
6. **Behavioral Comparator** -- anomaly detection against historical baseline
7. **Custom Middleware** -- your operator-defined checks (if any)
8. **Risk Aggregator** -- weighted composite score
9. **Policy Engine** -- applies tier rules, produces final verdict

If the verdict is `approve` or `advise`, the transaction proceeds. If the verdict is `block` or `freeze`, a `WardexBlockedError` is thrown.

> **Good to know:** The chain ID is automatically read from `args.chain?.id` or `walletClient.chain.id`. If neither is available, it defaults to `1` (Ethereum mainnet).

---

## Step 5: Handle Blocked Transactions

```typescript
// agent.ts
import { parseEther } from 'viem';
import { wrapViemWalletClient, WardexBlockedError } from '@wardexai/core';

const protectedClient = wrapViemWalletClient(walletClient, wardex);

try {
  await protectedClient.sendTransaction({
    to: '0xdead000000000000000000000000000000000001',
    value: parseEther('5.0'),
  });
} catch (error) {
  if (error instanceof WardexBlockedError) {
    console.log('Transaction blocked by Wardex');
    console.log(`Decision: ${error.verdict.decision}`);
    console.log(`Risk score: ${error.verdict.riskScore.composite}`);
    console.log(`Tier: ${error.verdict.tierId}`);

    for (const reason of error.verdict.reasons) {
      console.log(`  [${reason.severity}] ${reason.code}: ${reason.message}`);
    }

    // Access the full verdict for programmatic handling
    if (error.verdict.suggestions.length > 0) {
      console.log('Suggestions:', error.verdict.suggestions);
    }
  }
}
```

**Expected output for a blocked transaction:**

```
Transaction blocked by Wardex
Decision: block
Risk score: 52
Tier: tier-2-guardian
  [critical] PROMPT_INJECTION: Detected instruction override pattern
  [medium] LOW_TRUST_SOURCE: Transaction originated from low-trust source
Suggestions: [ 'Verify the instruction source before proceeding' ]
```

The `WardexBlockedError.verdict` object contains the full `SecurityVerdict`:

| Field | Type | Description |
|---|---|---|
| `decision` | `'approve' \| 'advise' \| 'block' \| 'freeze'` | Final decision |
| `riskScore` | `RiskScore` | Component scores (context, transaction, behavioral, composite) |
| `reasons` | `SecurityReason[]` | Every finding with severity and source |
| `suggestions` | `string[]` | Recommended safer alternatives |
| `tierId` | `string` | Which adaptive tier was applied |
| `evaluationId` | `string` | Unique ID for audit trail |
| `timestamp` | `string` | ISO timestamp of evaluation |

> **Good to know:** `WardexBlockedError` is re-exported from the ethers provider module. Both the ethers.js and viem wrappers throw the same error class, so your error handling logic works identically for both.

---

## Step 6: Add Event Handlers

```typescript
// wardex-setup.ts
const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex-signer.sock' },
  mode: 'adaptive',

  // Called when a transaction is blocked
  onBlock: (event) => {
    console.log(`[BLOCKED] Transaction to ${event.transaction.to}`);
    console.log(`  Reasons: ${event.verdict.reasons.map((r) => r.message).join('; ')}`);
    // Send alert to your monitoring system
  },

  // Called when findings are detected but not severe enough to block
  onAdvisory: (event) => {
    console.log(`[WARNING] Risk score ${event.verdict.riskScore.composite} for tx to ${event.transaction.to}`);
  },

  // Called when a specific threat is detected (address reputation, contract risk)
  onThreat: (event) => {
    console.log(`[THREAT] ${event.threatType}: ${event.details}`);
  },

  // Called when the system enters emergency freeze (5+ blocks in last 10 evals)
  onFreeze: (event) => {
    console.log(`[FREEZE] ${event.reason}`);
    // Page your on-call team
  },
});
```

> **Good to know:** Auto-freeze triggers when 5 or more transactions are blocked within the last 10 evaluations. This signals a likely active attack. Call `wardex.unfreeze()` to resume after investigating.

---

## Step 7: Enable Intelligence (Optional)

Add on-chain intelligence for address reputation lookups and contract bytecode analysis.

```typescript
// wardex-setup.ts
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex-signer.sock' },
  mode: 'adaptive',
  intelligence: {
    rpcUrl: 'https://eth.llamarpc.com',
    chainId: 1,
    // Optional: Etherscan API key for contract verification checks
    explorerApiKey: process.env.ETHERSCAN_API_KEY,
    // Optional: path to a local address denylist file
    denylistPath: './denylists/addresses.json',
  },
});
```

With intelligence enabled, the address checker and contract checker middleware use live on-chain data:

| Check | What It Does |
|---|---|
| Address age | Flags addresses with < 7 days of on-chain activity |
| Transaction count | Flags low-activity addresses as potentially risky |
| Contract verification | Checks if contract source is verified on Etherscan |
| Bytecode patterns | Detects SELFDESTRUCT, unsafe DELEGATECALL, proxy patterns |
| Denylist | Matches against known-malicious addresses |

---

## Customize the Policy for DeFi

For a DeFi trading agent, you will want to allowlist the protocols your agent interacts with and tighten the limits:

```typescript
// defi-agent-setup.ts
import { createWardex, defaultPolicy, mergePolicy } from '@wardexai/core';

const basePolicy = defaultPolicy();

const defiPolicy = mergePolicy(basePolicy, {
  allowlists: {
    contracts: [
      '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap V3 SwapRouter02
      '0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2', // Aave V3 Pool
      '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC
    ],
    protocols: ['uniswap-v3', 'aave-v3'],
    addresses: [],
  },
  limits: {
    maxTransactionValueWei: '2000000000000000000',  // 2 ETH per tx
    maxDailyVolumeWei: '20000000000000000000',       // 20 ETH daily cap
    maxApprovalAmountWei: '1000000000000000000000',  // 1000 tokens max approval
    maxGasPriceGwei: 50,
  },
  behavioral: {
    enabled: true,
    learningPeriodDays: 7,
    sensitivityLevel: 'high', // Tighter anomaly detection for DeFi
  },
});

const wardex = createWardex({
  policy: defiPolicy,
  signer: { type: 'isolated-process', endpoint: '/tmp/defi-agent.sock' },
  mode: 'adaptive',
});
```

> **Good to know:** `mergePolicy` merges allowlists and denylists additively (arrays are concatenated), while limits and behavioral settings are overwritten. This lets you extend the defaults without losing the base configuration.

---

## Full Working Example

```typescript
// full-viem-agent.ts
import { createWalletClient, http, parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';
import {
  createWardex,
  defaultPolicy,
  wrapViemWalletClient,
  WardexBlockedError,
} from '@wardexai/core';

async function main() {
  // 1. Set up Wardex
  const wardex = createWardex({
    policy: defaultPolicy(),
    signer: { type: 'isolated-process', endpoint: '/tmp/wardex-signer.sock' },
    mode: 'adaptive',
    onBlock: (e) => console.log(`[BLOCKED] ${e.verdict.reasons[0]?.message}`),
    onFreeze: (e) => console.log(`[FREEZE] ${e.reason}`),
  });

  // 2. Wrap your wallet client
  const account = privateKeyToAccount(process.env.PRIVATE_KEY as `0x${string}`);
  const walletClient = createWalletClient({
    account,
    chain: mainnet,
    transport: http(process.env.RPC_URL),
  });
  const agent = wrapViemWalletClient(walletClient, wardex);

  // 3. Transact normally -- Wardex protects automatically
  try {
    const hash = await agent.sendTransaction({
      to: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
      value: parseEther('0.1'),
    });
    console.log(`Sent: ${hash}`);
  } catch (error) {
    if (error instanceof WardexBlockedError) {
      console.log(`Blocked: ${error.verdict.reasons.map((r) => r.code).join(', ')}`);
    } else {
      throw error;
    }
  }

  // 4. Check the audit trail
  const log = wardex.getAuditLog(5);
  for (const entry of log) {
    console.log(`${entry.timestamp} | ${entry.verdict.decision} | ${entry.transaction.to}`);
  }
}

main().catch(console.error);
```

---

## What's Next?

| Goal | Guide |
|---|---|
| Use ethers.js instead of viem | [Protect an ethers.js Agent](./sdk-ethers.md) |
| Add session keys with spending limits | [Set Up Session Keys](./session-keys.md) |
| Understand the security tiers | [Core Concepts](../core-concepts.md) |
| See the full API surface | [API Reference](../api-reference/core.md) |
| Add on-chain enforcement | [Delegation Framework](./delegation-framework.md) |
