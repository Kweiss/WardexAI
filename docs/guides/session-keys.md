# Set Up Session Keys (ERC-7715)

Session keys give an AI agent scoped permission to transact within strict, pre-defined boundaries -- without needing the owner's full private key for every operation. If the agent is compromised, the blast radius is limited to the session's constraints.

> **Why session keys matter:** An unrestricted private key gives an agent unlimited power over a wallet. A session key restricts the agent to specific contracts, spending limits, and time windows. Even if the Wardex SDK is bypassed entirely, session key limits are enforced on-chain by the `WardexValidationModule`.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Node.js | 20+ |
| `@wardexai/signer` | latest |
| `@wardexai/core` | latest (for double-check with shield) |

---

## Step 1: Install Packages

```bash
npm install @wardexai/signer @wardexai/core
```

---

## Step 2: Create a SessionManager

```typescript
// session-setup.ts
import { SessionManager } from '@wardexai/signer';

const sessions = new SessionManager();
```

The `SessionManager` handles key generation, validation, daily volume tracking, rotation, and cleanup. Private keys for session keys are held in memory and never exposed through the public API.

---

## Step 3: Create a Session

```typescript
// session-setup.ts
const session = sessions.createSession({
  allowedContracts: [
    '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap V3 Router
    '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2', // Aave V3 Pool
    '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
  ],
  maxValuePerTx: '2000000000000000000',    // 2 ETH per transaction
  maxDailyVolume: '20000000000000000000',   // 20 ETH daily cap
  durationSeconds: 3600,                     // 1-hour session
  forbidInfiniteApprovals: true,             // Block unlimited token approvals
});

console.log(`Session created: ${session.id}`);
console.log(`  Address: ${session.address}`);
console.log(`  Expires: ${session.expiresAt}`);
```

**Expected output:**

```
Session created: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Address: 0x3a9f...b2c1
  Expires: 2025-06-15T15:30:00.000Z
```

### SessionKeyConfig Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `allowedContracts` | `string[]` | Yes | Contract addresses the session key can interact with. Transactions to any other address are rejected. |
| `maxValuePerTx` | `string` | Yes | Maximum ETH value (in wei) for a single transaction. |
| `maxDailyVolume` | `string` | Yes | Maximum cumulative ETH value (in wei) across all transactions in a calendar day. Resets at midnight. |
| `durationSeconds` | `number` | Yes | How long the session is valid, in seconds from creation. |
| `forbidInfiniteApprovals` | `boolean` | Yes | When `true`, blocks ERC-20 `approve` calls with amounts >= 2^128 and all `setApprovalForAll` calls. |

> **Good to know:** Contract addresses are normalized to lowercase internally. You can pass checksummed or lowercase addresses -- both work.

---

## Step 4: Validate Transactions Against the Session

Before executing a transaction, validate it against the session boundaries:

```typescript
// agent-loop.ts
const tx = {
  to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap Router
  value: '500000000000000000', // 0.5 ETH
  data: '0x5ae401dc',          // multicall selector
};

const result = sessions.validateTransaction(
  session.id,
  tx.to,
  tx.value,
  tx.data,
);

if (result.valid) {
  console.log('Session check passed -- safe to execute');
} else {
  console.log(`Session check failed: ${result.reason}`);
}
```

The validation checks run in this order:

1. **Session exists** -- returns `'Session not found'` if the ID is invalid
2. **Not revoked** -- returns `'Session has been revoked'` if previously revoked
3. **Not expired** -- returns `'Session has expired'` if past `expiresAt`
4. **Allowed contract** -- returns `'Target ... is not in the allowed contracts list'` if the `to` address is not in `allowedContracts`
5. **Per-tx value limit** -- returns `'Transaction value ... exceeds per-tx limit'` if value exceeds `maxValuePerTx`
6. **Daily volume limit** -- returns `'Transaction would exceed daily volume limit'` if cumulative daily spend plus this transaction exceeds `maxDailyVolume`
7. **Infinite approval check** -- returns `'Infinite token approval detected'` or `'setApprovalForAll detected'` if `forbidInfiniteApprovals` is `true` and the calldata contains a forbidden approval pattern

---

## Step 5: Record Transactions After Execution

After a transaction is confirmed on-chain, record it so the daily volume tracker stays accurate:

```typescript
// agent-loop.ts
if (result.valid) {
  // Execute the transaction through your signer...
  // const txHash = await signer.sendTransaction(tx);

  // Record the spend against the session
  sessions.recordTransaction(session.id, tx.value, tx.to);

  const state = sessions.getSessionState(session.id);
  console.log(`Transactions executed: ${state!.transactionCount}`);
  console.log(`Daily volume used: ${state!.dailyVolumeWei} wei`);
  console.log(`Contracts used: ${[...state!.contractsUsed].join(', ')}`);
}
```

**Expected output after recording:**

```
Transactions executed: 1
Daily volume used: 500000000000000000 wei
Contracts used: 0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45
```

> **Good to know:** The daily volume counter resets automatically at midnight (based on the server's local date). You do not need to reset it manually.

---

## Step 6: Handle Session Expiration and Rotation

### Check for Sessions Nearing Expiry

Use `getExpiringSessionsSoon` to proactively rotate sessions before they expire, preventing interruptions during active trading:

```typescript
// session-monitor.ts

// Find sessions expiring within the next 10 minutes (600 seconds)
const expiring = sessions.getExpiringSessionsSoon(600);

for (const s of expiring) {
  console.log(`Session ${s.id} expires at ${s.expiresAt} -- rotating`);

  // rotateSession revokes the old session and creates a new one
  // with the same config but a fresh key and expiration
  const rotated = sessions.rotateSession(s.id);

  if (rotated) {
    console.log(`New session: ${rotated.id}, expires: ${rotated.expiresAt}`);
  }
}
```

### Rotation Behavior

`rotateSession(id)` performs three actions atomically:

1. Revokes the old session (zeroes out the private key in memory)
2. Creates a new session with the same `SessionKeyConfig`
3. Returns the new `SessionKey` with a fresh ID, address, and expiration

The old session's `dailyVolumeWei` and `transactionCount` do not carry over to the new session.

### List Active Sessions

```typescript
const active = sessions.getActiveSessions();
console.log(`Active sessions: ${active.length}`);

for (const s of active) {
  console.log(`  ${s.id} | expires ${s.expiresAt} | contracts: ${s.config.allowedContracts.length}`);
}
```

### Revoke a Session Immediately

```typescript
const revoked = sessions.revokeSession(session.id);
console.log(`Revoked: ${revoked}`); // true

// The session key's private key is zeroed out in memory
// Any subsequent validateTransaction calls will return { valid: false, reason: 'Session has been revoked' }
```

---

## Step 7: Combine with Wardex Shield (Defense in Depth)

For maximum protection, validate transactions against **both** the Wardex Shield and the session key. Both must approve before the transaction proceeds:

```typescript
// defi-agent.ts
import { createWardex, defaultPolicy } from '@wardexai/core';
import { SessionManager } from '@wardexai/signer';

// Layer 1: Wardex Shield (risk evaluation pipeline)
const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex-signer.sock' },
  mode: 'adaptive',
  onBlock: (e) => console.log(`[BLOCKED] ${e.verdict.reasons[0]?.message}`),
});

// Layer 2: Session key (scoped permissions)
const sessions = new SessionManager();
const session = sessions.createSession({
  allowedContracts: ['0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45'],
  maxValuePerTx: '2000000000000000000',
  maxDailyVolume: '20000000000000000000',
  durationSeconds: 3600,
  forbidInfiniteApprovals: true,
});

// Evaluate a transaction through both layers
async function executeTransaction(to: string, value: string, data?: string) {
  const tx = { to, value, data, chainId: 1 };

  // Layer 1: Wardex risk evaluation
  const verdict = await wardex.evaluate(tx);
  if (verdict.decision === 'block' || verdict.decision === 'freeze') {
    console.log(`Wardex blocked: ${verdict.reasons.map((r) => r.code).join(', ')}`);
    return null;
  }

  // Layer 2: Session key validation
  const sessionCheck = sessions.validateTransaction(session.id, to, value, data);
  if (!sessionCheck.valid) {
    console.log(`Session rejected: ${sessionCheck.reason}`);
    return null;
  }

  // Both layers approve -- safe to sign and send
  console.log(`Approved by both layers (risk score: ${verdict.riskScore.composite})`);

  // ... sign and send the transaction ...

  // Record the spend
  sessions.recordTransaction(session.id, value, to);
  return verdict.evaluationId;
}
```

> **Good to know:** This double-check pattern provides defense in depth. Wardex catches threats like prompt injection, suspicious addresses, and behavioral anomalies. The session key enforces hard spending limits and contract allowlists. An attacker would need to bypass both layers simultaneously.

---

## Infinite Approval Blocking

When `forbidInfiniteApprovals` is `true`, the session manager inspects calldata for two patterns:

### ERC-20 `approve(address, uint256)`

Any `approve` call with an amount >= 2^128 is blocked. This catches the common DeFi pattern of approving `type(uint256).max` tokens.

```typescript
// This will be rejected by the session manager
const infiniteApproval = {
  to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', // USDC
  value: '0',
  data:
    '0x095ea7b3' + // approve(address,uint256)
    '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' + // spender
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',   // max uint256
};

const check = sessions.validateTransaction(
  session.id,
  infiniteApproval.to,
  infiniteApproval.value,
  infiniteApproval.data,
);

console.log(check.valid);  // false
console.log(check.reason); // 'Infinite token approval detected - session key forbids this'
```

### ERC-721/1155 `setApprovalForAll(address, bool)`

Any `setApprovalForAll` call with `approved = true` is blocked.

```typescript
const blanketApproval = {
  to: '0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d', // BAYC
  value: '0',
  data:
    '0xa22cb465' + // setApprovalForAll(address,bool)
    '0000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d' + // operator
    '0000000000000000000000000000000000000000000000000000000000000001',   // true
};

const check = sessions.validateTransaction(
  session.id,
  blanketApproval.to,
  blanketApproval.value,
  blanketApproval.data,
);

console.log(check.valid);  // false
console.log(check.reason); // 'setApprovalForAll detected - session key forbids blanket approvals'
```

---

## Session Cleanup

Remove expired and revoked sessions from memory to prevent leaks in long-running agents:

```typescript
// Run periodically (e.g., every 15 minutes)
const removed = sessions.cleanup();
console.log(`Cleaned up ${removed} expired/revoked sessions`);
```

`cleanup()` iterates all sessions and removes those that are either revoked or past their `expiresAt` timestamp. Private keys for removed sessions are zeroed out before deletion.

---

## Full Working Example

```typescript
// session-keys-agent.ts
import { createWardex, defaultPolicy } from '@wardexai/core';
import { SessionManager } from '@wardexai/signer';

const UNISWAP_ROUTER = '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45';
const AAVE_POOL = '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2';
const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

async function main() {
  // Set up both security layers
  const wardex = createWardex({
    policy: defaultPolicy(),
    signer: { type: 'isolated-process', endpoint: '/tmp/wardex-signer.sock' },
    mode: 'adaptive',
    onBlock: (e) => console.log(`[BLOCKED] ${e.verdict.reasons[0]?.message}`),
    onFreeze: (e) => console.log(`[FREEZE] ${e.reason}`),
  });

  const sessions = new SessionManager();
  const session = sessions.createSession({
    allowedContracts: [UNISWAP_ROUTER, AAVE_POOL, USDC],
    maxValuePerTx: '2000000000000000000',
    maxDailyVolume: '20000000000000000000',
    durationSeconds: 3600,
    forbidInfiniteApprovals: true,
  });

  console.log(`Session ${session.id} active until ${session.expiresAt}`);

  // Execute a swap through both layers
  const swapTx = {
    to: UNISWAP_ROUTER,
    value: '500000000000000000',
    data: '0x5ae401dc',
    chainId: 1,
  };

  const verdict = await wardex.evaluate(swapTx);
  const sessionCheck = sessions.validateTransaction(
    session.id, swapTx.to, swapTx.value, swapTx.data,
  );

  if (verdict.decision === 'approve' && sessionCheck.valid) {
    sessions.recordTransaction(session.id, swapTx.value, swapTx.to);
    console.log('Transaction approved by both layers');
  }

  // Monitor and rotate before expiry
  const expiring = sessions.getExpiringSessionsSoon(3600);
  for (const s of expiring) {
    const rotated = sessions.rotateSession(s.id);
    console.log(`Rotated ${s.id} -> ${rotated!.id}`);
  }

  // Periodic cleanup
  const removed = sessions.cleanup();
  console.log(`Cleaned up ${removed} sessions`);
}

main().catch(console.error);
```

---

## What's Next?

| Goal | Guide |
|---|---|
| Add Wardex shield to ethers.js | [Protect an ethers.js Agent](./sdk-ethers.md) |
| Add Wardex shield to viem | [Protect a viem Agent](./sdk-viem.md) |
| Enforce session limits on-chain | [Delegation Framework](./delegation-framework.md) |
| Understand adaptive security tiers | [Core Concepts](../core-concepts.md) |
| See the full API surface | [API Reference](../api-reference/core.md) |
| Deploy the validation module | [Contract Deployment](./contract-deployment.md) |
