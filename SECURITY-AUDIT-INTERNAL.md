# Wardex Internal Security Audit Report

**Date**: 2025-02-11
**Auditor**: Pre-audit internal review
**Scope**: All 7 packages — core, signer, intelligence, mcp-server, claude-skill, contracts, test
**Commit**: v1 + MetaMask Delegation Framework integration
**Test Coverage**: 168 TS tests (12 suites) + 16 Solidity tests

---

## Executive Summary

The Wardex codebase demonstrates strong security architecture with proper key isolation, defense-in-depth patterns, and comprehensive attack vector coverage. However, this pre-audit review identified **5 Critical**, **8 High**, **10 Medium**, and **9 Low** severity findings that should be addressed before external audit engagement to reduce audit costs and attack surface.

---

## CRITICAL Findings

### C-01: Verdict Object Mutation After Decision — TOCTOU Race in shield.ts

**File**: `packages/core/src/shield.ts` lines 244-258
**Severity**: CRITICAL

After the policy engine sets `verdict.decision = 'approve'`, the shield mutates it to `'block'` when daily volume is exceeded. However, the verdict object is the *same reference* stored in `ctx.metadata.verdict`. This means:

1. The policy engine produces a verdict with `decision: 'approve'`
2. Shield adds the tx value to `dailyVolumeWei`
3. Shield then mutates `verdict.decision = 'block'`

**The issue**: The daily volume is incremented *before* the block check. If the process crashes between lines 245 and 248, the volume has been added but the block never fires. On restart, the counter resets (in-memory), allowing the attacker to exceed the daily limit through crash-restart cycles.

**Recommendation**: Track daily volume in a durable store, or only increment after the verdict is finalized.

### C-02: Private Key Zeroing Is Ineffective in JavaScript

**File**: `packages/signer/src/isolated-process.ts` lines 247-249
**File**: `packages/signer/src/session-manager.ts` lines 221-225, 293-298

```typescript
this.privateKey = '0'.repeat(this.privateKey.length);
this.privateKey = '';
```

JavaScript strings are immutable. Assigning `'0'.repeat(...)` creates a *new* string — the original private key string remains in heap memory until garbage collection, which is non-deterministic. V8 may also intern or copy strings during JIT compilation.

**Impact**: Private key material persists in process memory long after "zeroing". Memory dump attacks, core dumps, or swap file access could recover keys.

**Recommendation**: Use `Buffer` or `Uint8Array` for key storage (these can be `.fill(0)` in-place). Consider `crypto.secureHeapUsed()` / secure heap allocation in Node.js 18+. Document that full memory protection requires a native module or TEE.

### C-03: No Address Validation on TransactionRequest.to

**File**: `packages/core/src/types.ts` line 312, used everywhere
**Severity**: CRITICAL

`TransactionRequest.to` is typed as `string` with no validation. The entire pipeline accepts arbitrary strings including:
- Empty strings
- Non-checksummed addresses
- Non-hex strings
- Addresses with wrong length

An attacker could pass `to: "ignore_all_previous_instructions"` and while this wouldn't succeed on-chain, it means address-checker comparisons against denylists/allowlists would never match, bypassing those checks.

**Impact**: Denylist/allowlist bypass when malformed addresses are used. Normalization via `toLowerCase()` doesn't validate length or hex format.

**Recommendation**: Add `isValidAddress()` validation at pipeline entry (in `createMiddlewareContext()` or the first middleware). Reject transactions with invalid `to` addresses before running the pipeline.

### C-04: updatePolicy() Has No Authentication

**File**: `packages/core/src/shield.ts` line 317-319
**Severity**: CRITICAL

```typescript
updatePolicy(overrides: Partial<SecurityPolicy>): void {
  policy = mergePolicy(policy, overrides);
}
```

The comment in `types.ts` says "(requires operator authentication)" but there is *no authentication*. Any code with a reference to the shield can call `updatePolicy()` to:
- Clear all denylists (`denylists: { addresses: [], patterns: [] }`)
- Set tier blockThreshold to 100 (never blocks)
- Disable all context analysis
- Add attacker addresses to allowlists

**Impact**: If the shield reference leaks to untrusted code (e.g., via a malicious middleware registered with `use()`), the entire security policy can be silently neutralized.

**Recommendation**: Add an operator authentication mechanism (API key, signed token, or capability-based access control). At minimum, emit a threat event when policy is changed so audit trail captures it.

### C-05: Custom Middleware Can Corrupt Pipeline State

**File**: `packages/core/src/shield.ts` line 328-330
**Severity**: CRITICAL

```typescript
use(middleware: Middleware): void {
  customMiddlewares.push(middleware);
}
```

Custom middleware registered via `use()` runs at position 7 in the pipeline (after behavioral comparator, before risk aggregator). A malicious middleware can:
- Clear `ctx.reasons` array (removing all findings)
- Reset `ctx.riskScores` to zeros
- Delete `ctx.decoded` (hiding infinite approvals)
- Mutate `ctx.policy` for downstream middleware
- Set `ctx.metadata.verdict` directly, bypassing the policy engine entirely

**Impact**: Complete bypass of all security checks.

**Recommendation**: Freeze `ctx.reasons` and `ctx.riskScores` before custom middleware runs (or use a snapshot/restore pattern). Run custom middleware on a shallow copy of the context. Alternatively, have the risk aggregator re-validate that reasons haven't been tampered with.

---

## HIGH Findings

### H-01: Behavioral Profile Poisoning via Approved Transactions

**File**: `packages/core/src/middleware/behavioral-comparator.ts` lines 315-323
**Severity**: HIGH

The behavioral comparator records every transaction into the profile at line 316, *including* transactions that will later be blocked by the policy engine. The recording happens inside the middleware's `next()` call chain before the policy engine runs.

**Attack**: An attacker can slowly escalate transaction values with approved dust-tier transactions ($0-1, which never block), gradually shifting `valueMean` and `valueStdDev` upward. After enough history poisoning, a large anomalous transaction won't be flagged because the baseline has been artificially inflated.

**Recommendation**: Only record transactions into the behavioral profile AFTER the verdict is finalized and is `approve` or `advise`. Move recording to the shield's post-evaluation logic.

### H-02: Regex State Persistence Across Invocations in Context Analyzer

**File**: `packages/core/src/middleware/context-analyzer.ts` line 258-260
**Severity**: HIGH

```typescript
pattern.pattern.lastIndex = 0;
if (pattern.pattern.test(message.content)) {
```

The regex patterns at lines 31-88 use flags like `/i` and `/is` but NOT the `/g` flag. The `lastIndex` reset on line 259 is therefore unnecessary (non-global regexes always search from index 0). However, the `HIDDEN_INSTRUCTION_MARKER` pattern on line 61 uses the `/is` flag with `.*?` — if this were ever changed to `/gis`, it would create intermittent detection failures. More critically:

The `KEYSTORE_PATTERN` in `output-filter.ts` line 125 DOES use the `/gi` flag and is declared at module scope. If `filterText()` is called concurrently (same shield, multiple evaluate calls in flight), `lastIndex` state will be shared and could cause missed detections.

**Recommendation**: Either create new RegExp instances per invocation, or ensure all module-scope regex patterns avoid the `/g` flag. Use non-global patterns and `String.prototype.match()` instead.

### H-03: Approval Token Replay Within 5-Minute Window

**File**: `packages/signer/src/isolated-process.ts` lines 86, 92-124
**Severity**: HIGH

The approval token includes an HMAC over `transactionHash + timestamp`, with a 5-minute validity window. However, there is **no nonce or one-time-use tracking**. The same approval token can be submitted multiple times within the 5-minute window to sign the same transaction repeatedly.

**Impact**: If an attacker intercepts an approval token (e.g., via process memory, log files, or socket sniffing), they can replay it within the 5-minute window.

**Recommendation**: Add a used-token set with expiration to the SignerServer. Reject tokens that have already been used. The set only needs to retain entries for 5 minutes.

### H-04: Signer Socket Lacks Peer Authentication

**File**: `packages/signer/src/isolated-process.ts` lines 229-240
**Severity**: HIGH

The Unix socket server sets `0o600` permissions on the socket file, which restricts access to the same user. However:
- There is no TLS or mutual authentication on the socket
- Any process running as the same user can connect
- The protocol accepts any JSON message from any connection
- No connection rate limiting

**Impact**: Any local process under the same user can send `sign_transaction` requests (still gated by approval tokens) or exhaust resources via rapid health_check/get_address calls.

**Recommendation**: Implement a challenge-response handshake on connection establishment using the shared secret. Add connection rate limiting. Consider using abstract Unix sockets or peer credential verification (`SO_PEERCRED`).

### H-05: Float Precision Loss in Value Assessment

**File**: `packages/core/src/middleware/value-assessor.ts` line 45
**Severity**: HIGH

```typescript
const ethValue = Number(weiValue) / 1e18;
```

`Number(weiValue)` loses precision for values > `2^53` (about 9007 ETH). While 9007 ETH ($31M+) may seem unlikely for a single transaction, precision loss could cause a Fortress-tier transaction to be miscalculated as Guardian-tier, applying weaker security controls.

More practically, for token approvals at line 65: `Number(amountBig) / 1e18` will lose precision for tokens with large supplies or non-18-decimal tokens (USDC has 6 decimals — dividing by 1e18 gives essentially 0 for any USDC amount).

**Recommendation**: Use BigInt arithmetic throughout value assessment. Create a `bigintDiv` helper that maintains precision. Handle non-18-decimal tokens explicitly.

### H-06: No Rate Limiting on shield.evaluate()

**File**: `packages/core/src/shield.ts` lines 291-293
**Severity**: HIGH

There is no rate limiting on the `evaluate()` function. A malicious or compromised agent could call evaluate millions of times per second to:
- Fill the audit log to the 10,000 entry limit (destroying historical evidence)
- Trigger auto-freeze via rapid block verdicts (DoS the shield)
- CPU-exhaust the process (intelligence RPC calls per evaluation)
- If intelligence is configured, flood the RPC endpoint

**Recommendation**: Add configurable rate limiting (e.g., max 100 evaluations per second). Separate rate limits for the intelligence provider RPC calls.

### H-07: Unfreeze Has No Authentication or Delay

**File**: `packages/core/src/shield.ts` lines 347-349
**Severity**: HIGH

```typescript
unfreeze(): void {
  frozen = false;
  freezeReason = '';
}
```

Any code with a shield reference can immediately unfreeze after an auto-freeze. The auto-freeze mechanism (5 blocks in 10 evaluations) is designed to stop active attacks, but if the attacker has access to the shield object, they can immediately unfreeze and continue.

**Recommendation**: Add a mandatory cooldown period after auto-freeze (e.g., 15 minutes minimum). Require operator authentication to unfreeze. Emit a threat event when unfreeze is called.

### H-08: Contract Bytecode Opcode Search Has False Positives

**File**: `packages/intelligence/src/contract-analyzer.ts` lines 83-93
**Severity**: HIGH

```typescript
if (code.includes(OPCODES.SELFDESTRUCT)) {  // 'ff'
```

Searching for the hex byte `'ff'` in the full bytecode string will match any occurrence of `ff` in the bytecode — including as part of PUSH data, constructor arguments, or metadata. For example, `PUSH32 0x00...ff00` would trigger a false positive. The byte `ff` is extremely common in bytecode.

Similarly, `'f4'` (DELEGATECALL) and `'f2'` (CALLCODE) will have high false positive rates.

**Impact**: Legitimate contracts are flagged as dangerous, causing unnecessary blocks. This erodes trust in the system and encourages operators to lower sensitivity or disable contract checking.

**Recommendation**: Implement a proper EVM disassembler that walks bytecode sequentially, distinguishing opcodes from PUSH data. At minimum, skip over PUSH1-PUSH32 data when scanning for opcodes.

---

## MEDIUM Findings

### M-01: Daily Volume Reset Uses Local Date String

**File**: `packages/core/src/shield.ts` line 132-136, `session-manager.ts` line 316-320
**Severity**: MEDIUM

```typescript
const today = new Date().toDateString();
```

`toDateString()` returns the local timezone date. If the process crosses midnight in a different timezone than expected, the daily volume resets at an unexpected time. In a cloud deployment, the server timezone may differ from the operator's expectation.

**Recommendation**: Use UTC date for consistency: `new Date().toISOString().slice(0, 10)`.

### M-02: mergePolicy() Allows Tiers Replacement Without Validation

**File**: `packages/core/src/policy.ts` lines 118-161
**Severity**: MEDIUM

`mergePolicy()` uses `overrides.tiers ?? base.tiers` — if overrides includes `tiers`, it **completely replaces** the tier array. An operator could accidentally pass an empty tiers array, causing `determineTier()` to return `undefined`, which falls through to conservative defaults (composite > 70 = block, > 30 = advise) — actually stricter than intended. But more importantly, a malicious override could replace all tiers with audit mode tiers that never block.

**Recommendation**: Validate that merged tiers still include at least one blocking tier. Warn or reject tier arrays that exclusively use audit mode.

### M-03: Output Filter Mnemonic Detection Heuristic Can Be Bypassed

**File**: `packages/core/src/output-filter.ts` lines 131-175
**Severity**: MEDIUM

The mnemonic detection relies on:
1. Words being 3-8 characters long
2. More than 40% being "uncommon" (not in `COMMON_ENGLISH_OVERLAP`)
3. Words being consecutive (within `mnemonicLength * 12` characters)

**Bypass vectors**:
- Seed phrases where BIP-39 words happen to also be in the common English set (e.g., "zoo zone zero zone...") would drop below the 40% threshold
- Adding extra words between mnemonic words breaks the consecutiveness check
- Using uppercase bypasses the `/\b[a-z]{3,8}\b/g` pattern entirely
- Encoding the mnemonic (base64, reverse, interspersed with punctuation)

**Recommendation**: Load the full BIP-39 wordlist (2048 words) and match against it directly. Check for case-insensitive matches. Add detection for encoded/obfuscated mnemonics. The current `COMMON_ENGLISH_OVERLAP` is not a proper BIP-39 wordlist.

### M-04: Private Key Detection Regex Misses Common Formats

**File**: `packages/core/src/output-filter.ts` lines 115-120
**Severity**: MEDIUM

The private key patterns require specific context:
- Pattern 1: Requires `0x` prefix and no adjacent hex chars
- Pattern 2: Requires surrounding whitespace/quotes

**Missed formats**:
- `"key": "abc123..."` where the 64 hex chars are in a JSON value but the preceding char is `"` followed by the hex (pattern 2's lookbehind includes `"`, but JSON like `"abc...` starts right after the quote with no space)
- Private keys with mixed case that aren't 0x-prefixed
- Keys output as `[32 bytes hex]` with brackets

Actually, on closer inspection, pattern 2's lookbehind `(?<=[\s"'` + "`=:])" does include `"`, so `"abc123..."` would match. But `key=abc123...` without quotes after `=` is caught. The main gap is keys output without any surrounding delimiters (e.g., on a line by themselves).

**Recommendation**: Add a pattern for standalone 64 hex char lines: `/^[0-9a-fA-F]{64}$/gm`. Also detect keys split across multiple lines.

### M-05: Etherscan API Key Leaked in URL Query String

**File**: `packages/intelligence/src/provider.ts` line 77
**Severity**: MEDIUM

```typescript
const url = `${apiUrl}?module=contract&action=getabi&address=${address}&apikey=${apiKey}`;
```

The Etherscan API key is passed as a URL query parameter. This means:
- It appears in server logs at Etherscan
- It may be logged by any proxy/CDN between the agent and Etherscan
- It appears in Node.js HTTP trace logs if enabled
- On redirect, it could be leaked in the Referer header

**Recommendation**: Check if the Etherscan API supports passing the key via header. If not, document this as a known limitation and recommend using a dedicated API key with restricted permissions.

### M-06: Claude Skill Hook Fails Open

**File**: `packages/claude-skill/hooks/evaluate-transaction.mjs` lines 117-120, 196-208
**Severity**: MEDIUM

On any error (stdin parse failure, Wardex evaluation failure), the hook allows the tool call to proceed:
```javascript
} catch {
  process.exit(0);  // Allow
}
```

If an attacker can cause the hook to error (e.g., by crafting tool input that crashes `JSON.parse` or causes the dynamic import to fail), all tool calls will be allowed without evaluation.

**Recommendation**: Default to deny (exit code 2) on errors, not allow (exit code 0). At minimum, default to 'ask' (which prompts the user). The current behavior means a broken Wardex installation provides zero protection.

### M-07: Co-pilot Tier Block Threshold Is 100 (Never Blocks)

**File**: `packages/core/src/policy.ts` line 35
**Severity**: MEDIUM

```typescript
blockThreshold: 100, // advisory only
```

Copilot mode tier has `blockThreshold: 100`, which means `scores.composite >= 100` is required to block. Since composite is clamped to 0-100, only a perfect 100 composite score would trigger a block. However, the policy engine's critical-findings override (line 85-88) does override this for critical severity findings. This is a design choice but worth documenting clearly.

**Recommendation**: This is functioning as designed (critical findings still block in copilot mode), but document explicitly that copilot mode will not block any non-critical finding regardless of composite score. Consider whether the advisory-only behavior for composite=99 is intended.

### M-08: Audit Log Contains Full Transaction Data

**File**: `packages/core/src/shield.ts` lines 148-163
**Severity**: MEDIUM

The audit log stores the full `TransactionRequest` including `data` field (calldata). For tokens with encoded user data in calldata, this could retain sensitive information. The 10,000 entry limit means up to 10,000 transactions' calldata is retained in memory.

**Recommendation**: Consider truncating or hashing the `data` field in audit entries. Add an option to disable calldata retention.

### M-09: No Timeout on Intelligence RPC Calls

**File**: `packages/intelligence/src/provider.ts` line 45-66
**Severity**: MEDIUM

The `rpcCall()` function uses `fetch()` with no timeout. A slow or unresponsive RPC endpoint will hang the evaluation pipeline indefinitely, effectively DoS-ing all transaction processing.

**Recommendation**: Add `AbortController` with a configurable timeout (default: 5 seconds) to all fetch calls.

### M-10: WardexValidationModule Does Not Track Daily Spending in validateUserOp

**File**: `packages/contracts/src/WardexValidationModule.sol` lines 154-181
**Severity**: MEDIUM

The `validateUserOp()` function checks spending limits via `checkSpendingLimit()` (view function) but never calls `_recordSpending()` to update the daily counter. The `_recordSpending()` function exists (lines 249-263) but is never called from `validateUserOp()` or any external function.

**Impact**: The daily spending limit is never enforced on-chain. An attacker can submit unlimited transactions within the per-tx limit.

**Recommendation**: Call `_recordSpending()` within `validateUserOp()` after validation passes. Note that since `validateUserOp` returns before execution, you may need to use a postOp hook or record spending optimistically.

---

## LOW Findings

### L-01: createMiddlewareContext Accepts Partial Overrides with Spread Last

**File**: `packages/core/src/pipeline.ts` lines 39-76
**Severity**: LOW

```typescript
return { ...defaults, ...overrides };
```

The `...overrides` spread at the end means any property in overrides (including `riskScores`, `reasons`, `metadata`) will overwrite the defaults. A caller could inject pre-populated risk scores or reasons that persist through the pipeline.

### L-02: Address Denylist Check Is O(n) Linear Scan

**File**: `packages/core/src/middleware/address-checker.ts` lines 46-48
**Severity**: LOW

Denylist checking iterates the array with `.some()`. For large denylists (1000+ entries), this becomes slow. Should use a Set for O(1) lookups.

### L-03: Session Key deriveAddress Uses SHA-256, Not secp256k1

**File**: `packages/signer/src/session-manager.ts` lines 370-373
**Severity**: LOW

```typescript
private deriveAddress(privateKey: string): string {
  const hash = crypto.createHash('sha256').update(privateKey).digest('hex');
  return '0x' + hash.slice(0, 40);
}
```

This produces addresses that are not valid Ethereum addresses (they're not derived from the secp256k1 public key). While the comment says "simplified", this means session keys cannot be used for actual on-chain signing. The same issue exists in `delegation-manager.ts` line 562-564.

### L-04: Escalation Tracker Never Resets After Freeze

**File**: `packages/core/src/middleware/context-analyzer.ts` lines 95-136
**Severity**: LOW

The escalation tracker accumulates forever (with 30-minute window cleanup). After a freeze/unfreeze cycle, old escalation data from before the freeze persists and may immediately trigger escalation detection again.

### L-05: MCP Server Creates Shield on Every Startup

**File**: `packages/mcp-server/src/index.ts` lines 34-43
**Severity**: LOW

The MCP server creates a fresh `WardexShield` on startup, losing all behavioral profile, audit log, and daily volume data. On restart cycles (e.g., due to crashes or updates), protection effectiveness is reduced.

### L-06: Multicall Detection Is Superficial

**File**: `packages/core/src/middleware/transaction-decoder.ts` lines 186-195
**Severity**: LOW

Multicall transactions only get a medium-severity warning. The individual operations within the multicall are not decoded or analyzed. An attacker can hide an infinite approval inside a multicall's `bytes[]` array.

### L-07: Intelligence Provider Cache Not Bounded

**File**: `packages/intelligence/src/provider.ts` lines 96-98
**Severity**: LOW

The reputation and contract caches grow unboundedly. With TTL-only expiration, a targeted attack could cache thousands of entries by querying many unique addresses, consuming memory.

### L-08: scryptSync Used with Default Parameters

**File**: `packages/signer/src/isolated-process.ts` lines 147
**Severity**: LOW

`crypto.scryptSync(password, salt, 32)` uses Node.js defaults (N=16384, r=8, p=1). For key derivation protecting cryptocurrency private keys, higher parameters (N=2^20, r=8, p=1) are recommended by OWASP.

### L-09: SignerServer Doesn't Limit Concurrent Connections

**File**: `packages/signer/src/isolated-process.ts` line 229
**Severity**: LOW

`net.createServer()` with no `maxConnections` allows unlimited concurrent connections, enabling local DoS.

---

## Informational / Design Observations

### I-01: No Replay Protection Between Evaluations
The shield does not track whether a specific transaction has already been evaluated. The same transaction can be evaluated repeatedly with potentially different results (e.g., if behavioral profile changes between calls).

### I-02: Allowlist Addresses Bypass All Risk Scoring
In address-checker.ts line 121-122, allowlisted addresses get `addressScore = 0` regardless of other findings. A compromised allowlisted contract would receive reduced scrutiny.

### I-03: Explorer API URL Is Hardcoded to Etherscan
In shield.ts line 82: `explorerApiUrl: 'https://api.etherscan.io/api'` — this is hardcoded regardless of the chain ID. For non-Ethereum chains (Base, Polygon, etc.), this will query the wrong API.

### I-04: No Mechanism to Rotate the Signer Shared Secret
If the HMAC shared secret is compromised, there's no API to rotate it without restarting both the signer server and all clients.

### I-05: Delegation Salt Is Random But Not Verified
The salt in DelegationManager.createDelegation() is random, but when the delegation is redeemed on-chain, there's no check that the salt matches what was issued. The salt is part of the EIP-712 signature, so it's implicitly verified, but there's no explicit uniqueness check off-chain.

---

## Recommendations Priority

| Priority | Finding | Estimated Fix Effort |
|----------|---------|---------------------|
| 1 | C-03: Address validation | 2 hours |
| 2 | C-04: updatePolicy authentication | 4 hours |
| 3 | C-05: Custom middleware isolation | 4 hours |
| 4 | C-02: Key zeroing | 2 hours (+ document limitations) |
| 5 | C-01: Volume tracking TOCTOU | 2 hours |
| 6 | H-03: Approval token replay | 2 hours |
| 7 | H-08: Opcode false positives | 8 hours |
| 8 | H-05: Float precision | 4 hours |
| 9 | H-01: Behavioral poisoning | 2 hours |
| 10 | H-06: Rate limiting | 3 hours |
| 11 | H-07: Unfreeze cooldown | 2 hours |
| 12 | H-04: Socket authentication | 6 hours |
| 13 | H-02: Regex state | 1 hour |
| 14 | M-10: On-chain daily tracking | 4 hours (Solidity) |
| 15 | M-06: Fail-open hook | 1 hour |
| 16 | M-03: Mnemonic bypass | 4 hours |
| 17 | M-09: RPC timeout | 1 hour |
| 18 | M-01: UTC daily reset | 30 minutes |

**Estimated total effort**: ~52 hours

---

## Files Reviewed

| Package | Files | Lines |
|---------|-------|-------|
| @wardexai/core | shield.ts, types.ts, policy.ts, pipeline.ts, output-filter.ts, context-analyzer.ts, transaction-decoder.ts, value-assessor.ts, address-checker.ts, contract-checker.ts, behavioral-comparator.ts, risk-aggregator.ts, policy-engine.ts, ethers.ts, viem.ts | ~2,100 |
| @wardexai/signer | isolated-process.ts, session-manager.ts, delegation-manager.ts, enforcer-mapping.ts | ~1,360 |
| @wardexai/intelligence | provider.ts, contract-analyzer.ts, denylist.ts | ~400 |
| @wardexai/mcp-server | index.ts | ~356 |
| @wardexai/claude-skill | evaluate-transaction.mjs | ~213 |
| @wardexai/contracts | WardexValidationModule.sol, Deploy.s.sol, Verify.s.sol | ~440 |
| **Total** | **21 files** | **~4,870 lines** |
