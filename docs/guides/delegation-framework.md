# MetaMask Delegation Framework

Wardex integrates with MetaMask's Delegation Framework to add on-chain enforcement to agent wallet sessions. Instead of relying solely on the SDK to block out-of-scope transactions, you create EIP-712 signed delegations backed by caveat enforcer smart contracts. Even if the Wardex SDK is bypassed, compromised, or crashed, the blockchain itself rejects transactions that violate session boundaries.

This is defense-in-depth: the SDK provides fast off-chain checks, and the delegation enforcers provide the hard on-chain backstop.

---

## How It Works

1. The wallet owner creates a **delegation** that grants limited authority to a delegate (the agent's session key).
2. The delegation includes **caveats** -- each caveat points to an enforcer smart contract with ABI-encoded terms.
3. The owner signs the delegation using EIP-712 typed structured data.
4. When the agent transacts, it **redeems** the delegation through the DeleGatorCore contract. Each enforcer validates its terms on-chain.
5. If any enforcer rejects, the entire transaction reverts.

Wardex's `DelegationManager` handles all of this: mapping your `SessionKeyConfig` to the correct enforcers, producing the signing payload, and encoding the redemption calldata.

---

## Step 1: Install

The `DelegationManager` is included in `@wardexai/signer`:

```bash
npm install @wardexai/signer
```

No dependency on `@metamask/delegation-toolkit` at runtime. Wardex handles all ABI encoding internally using ethers.js.

---

## Step 2: Create a DelegationManager

Initialize the manager with your chain ID. The canonical MetaMask Delegation Framework v1.3.0 contract addresses are built in.

```typescript
import { DelegationManager } from '@wardexai/signer';

const delegations = new DelegationManager({
  chainId: 8453, // Base
});
```

To override contract addresses (custom deployment or future versions):

```typescript
const delegations = new DelegationManager({
  chainId: 8453,
  delegationManagerAddress: '0xYourCustomDelegationManager',
  enforcerAddresses: {
    allowedTargets: '0xYourCustomAllowedTargets',
    // ...other overrides merged with defaults
  },
});
```

---

## Step 3: Create a Delegation

Create a delegation from a `SessionKeyConfig`. This maps each config field to the appropriate enforcer caveat.

```typescript
const delegation = delegations.createDelegation(
  {
    allowedContracts: [
      '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // Uniswap V3 Router
      '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad', // Universal Router
    ],
    maxValuePerTx: '500000000000000000',    // 0.5 ETH per transaction
    maxDailyVolume: '2000000000000000000',   // 2 ETH daily cap
    durationSeconds: 3600,                    // 1 hour session
    forbidInfiniteApprovals: true,
  },
  '0xOwnerAddress', // The wallet owner granting authority
);

console.log(delegation.id);        // UUID
console.log(delegation.delegate);  // Generated session key address
console.log(delegation.caveats);   // Array of enforcer terms
console.log(delegation.signature); // '' (unsigned -- Step 4 will sign it)
```

### Caveat mapping

Each `SessionKeyConfig` field maps to a specific enforcer contract:

| Config Field | Enforcer Contract | Terms Encoding | On-Chain Effect |
|-------------|-------------------|----------------|-----------------|
| `allowedContracts` | AllowedTargetsEnforcer | `abi.encode(address[])` | Reverts if target is not in the list |
| `maxValuePerTx` | ValueLteEnforcer | `abi.encode(uint256)` | Reverts if `msg.value` exceeds the cap |
| `maxDailyVolume` | NativeTokenPeriodTransferEnforcer | `abi.encode(uint256, uint256)` with period=86400 | Reverts if cumulative native transfers in a 24-hour period exceed the allowance |
| `durationSeconds` | TimestampEnforcer | `abi.encode(uint256, uint256)` with afterTimestamp=0 | Reverts if `block.timestamp` is past the deadline |
| `forbidInfiniteApprovals` | Off-chain (default) or AllowedMethodsEnforcer (strict) | See [Infinite Approval Strategies](#the-forbidInfiniteApprovals-gap) | Depends on strategy chosen |

---

## Step 4: Get the Signing Payload

The delegation is not valid until the wallet owner signs it. Wardex never holds the owner's private key, so you retrieve the EIP-712 typed data and have the owner sign it externally.

```typescript
const payload = delegations.getSigningPayload(delegation.id);
// payload = {
//   domain: {
//     name: 'DelegationManager',
//     version: '1',
//     chainId: 8453,
//     verifyingContract: '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3'
//   },
//   types: {
//     Delegation: [
//       { name: 'delegate', type: 'address' },
//       { name: 'delegator', type: 'address' },
//       { name: 'authority', type: 'bytes32' },
//       { name: 'caveats', type: 'Caveat[]' },
//       { name: 'salt', type: 'uint256' },
//     ],
//     Caveat: [
//       { name: 'enforcer', type: 'address' },
//       { name: 'terms', type: 'bytes' },
//     ],
//   },
//   value: {
//     delegate: '0x...',
//     delegator: '0xOwnerAddress',
//     authority: '0x0000...0000',
//     caveats: [...],
//     salt: '123...',
//   },
// }
```

Sign with ethers.js:

```typescript
const signature = await ownerWallet.signTypedData(
  payload.domain,
  payload.types,
  payload.value,
);
```

Or with viem:

```typescript
const signature = await walletClient.signTypedData({
  domain: payload.domain,
  types: payload.types,
  primaryType: 'Delegation',
  message: payload.value,
});
```

---

## Step 5: Attach the Signature

Store the owner's signature on the delegation to activate it:

```typescript
delegations.setSignature(delegation.id, signature);
console.log(delegation.signature); // '0x...' (now signed and active)
```

The delegation is now ready for use. Transactions can be validated and redeemed.

---

## Step 6: Validate Transactions

Before submitting a transaction on-chain, validate it off-chain against the delegation boundaries. This provides fast feedback without spending gas on reverted transactions.

```typescript
const result = delegations.validateTransaction(
  delegation.id,
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45', // target
  '100000000000000000',                           // 0.1 ETH
  '0x38ed1739...',                                 // swap calldata
);

if (result.valid) {
  console.log('Transaction is within delegation scope');
} else {
  console.log('Rejected:', result.reason);
  // e.g. "Target 0x... is not in the allowed contracts list"
  // e.g. "Transaction value exceeds per-tx limit"
  // e.g. "Transaction would exceed daily volume limit"
  // e.g. "Delegation has expired"
  // e.g. "Infinite token approval detected - delegation forbids this"
}
```

After a transaction is confirmed on-chain, record it against the delegation state:

```typescript
delegations.recordTransaction(delegation.id, '100000000000000000');
```

This updates the daily volume counter used by off-chain validation.

### Double-check pattern

For maximum safety, validate with both the Wardex SDK and the delegation:

```typescript
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({ policy: defaultPolicy(), mode: 'adaptive' });

// Layer 1: Wardex SDK evaluation (checks prompt injection, behavioral anomaly, etc.)
const verdict = await wardex.evaluate({ to, value, data, chainId });

if (verdict.decision === 'block' || verdict.decision === 'freeze') {
  console.log('Wardex blocked:', verdict.reasons);
  return;
}

// Layer 2: Delegation validation (checks contract allowlist, value limits, etc.)
const delegationCheck = delegations.validateTransaction(delegation.id, to, value, data);

if (!delegationCheck.valid) {
  console.log('Delegation rejected:', delegationCheck.reason);
  return;
}

// Both layers passed -- safe to submit on-chain
```

---

## Step 7: Prepare Redemption Calldata

To execute a transaction through the delegation on-chain, prepare the redemption calldata for the DeleGatorCore contract:

```typescript
const redemption = delegations.prepareRedemption(delegation.id, [
  {
    target: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
    value: 100000000000000000n,    // 0.1 ETH
    callData: '0x38ed1739...',     // swapExactTokensForTokens
  },
]);

if (redemption) {
  console.log(redemption.target);   // DelegationManager contract address
  console.log(redemption.value);    // Total native value across all executions
  console.log(redemption.calldata); // ABI-encoded redeemDelegations call

  // Send as a regular transaction or use as UserOp callData (ERC-4337)
  await wallet.sendTransaction({
    to: redemption.target,
    value: redemption.value,
    data: redemption.calldata,
  });
}
```

You can batch multiple executions in a single redemption:

```typescript
const redemption = delegations.prepareRedemption(delegation.id, [
  { target: routerAddress, value: 0n, callData: approveCalldata },
  { target: routerAddress, value: 100000000000000000n, callData: swapCalldata },
]);
```

---

## Step 8: Rotation and Lifecycle

### Rotate a delegation

Revokes the current delegation and creates a new one with a fresh delegate key, salt, and expiration. The new delegation still needs to be signed by the owner.

```typescript
const newDelegation = delegations.rotateDelegation(delegation.id);
// Old delegation is now revoked
// New delegation has the same config but fresh credentials

// Owner must sign the new delegation
const newPayload = delegations.getSigningPayload(newDelegation.id);
const newSignature = await ownerWallet.signTypedData(
  newPayload.domain,
  newPayload.types,
  newPayload.value,
);
delegations.setSignature(newDelegation.id, newSignature);
```

### Revoke a delegation

```typescript
delegations.revokeDelegation(delegation.id);
// Immediate -- all subsequent validateTransaction calls return { valid: false }
```

### List active delegations

```typescript
const active = delegations.getActiveDelegations();
// Returns all non-revoked, non-expired delegations
```

### Clean up expired delegations

```typescript
const removed = delegations.cleanup();
console.log(`Removed ${removed} expired/revoked delegations`);
```

---

## Enforcer Contract Addresses

Wardex uses the canonical MetaMask Delegation Framework v1.3.0 deployment. These addresses are the same across all 35+ supported EVM chains.

| Enforcer | Address |
|----------|---------|
| DelegationManager | `0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3` |
| AllowedTargetsEnforcer | `0x7F20f61b1f09b08D970938F6fa563634d65c4EeB` |
| ValueLteEnforcer | `0x92Bf12322527cAA612fd31a0e810472BBB106A8F` |
| NativeTokenPeriodTransferEnforcer | `0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9` |
| TimestampEnforcer | `0x1046bb45C8d673d4ea75321280DB34899413c069` |
| AllowedMethodsEnforcer | `0x6E3eB4b22d7C264FBbb1c25e1d50267136EF4e74` |
| LimitedCallsEnforcer | `0x04658B29F6b82ed55274221a06Fc97D318E25416` |
| AllowedCalldataEnforcer | `0xc2b0d624c1c4319760C96503BA27C347F3260f55` |

To retrieve these programmatically:

```typescript
import { getDefaultEnforcerAddresses } from '@wardexai/signer';

const addresses = getDefaultEnforcerAddresses();
console.log(addresses.allowedTargets);
// '0x7F20f61b1f09b08D970938F6fa563634d65c4EeB'
```

---

## The forbidInfiniteApprovals Gap

The `forbidInfiniteApprovals` config field has a nuance: there is no single enforcer in the Delegation Framework that says "block `approve()` calls with value > 2^128." Wardex handles this with two strategies.

### Strategy 1: Off-chain only (default)

The `DelegationManager` checks calldata off-chain in `validateTransaction()`. If it detects an `approve(address,uint256)` call with an amount >= 2^128, or a `setApprovalForAll(address,bool)` set to true, validation fails.

This catches infinite approvals before they reach the chain, but only if the transaction goes through Wardex.

### Strategy 2: Strict on-chain blocking

Enable `strictInfiniteApprovalBlocking` to add an AllowedMethodsEnforcer caveat that whitelists only safe function selectors:

```typescript
const delegations = new DelegationManager({
  chainId: 8453,
  strictInfiniteApprovalBlocking: true,
});
```

With strict mode, the AllowedMethodsEnforcer is configured with these allowed selectors:

| Selector | Function |
|----------|----------|
| `0xa9059cbb` | `transfer(address,uint256)` |
| `0x23b872dd` | `transferFrom(address,address,uint256)` |
| `0x38ed1739` | `swapExactTokensForTokens(...)` |
| `0x8803dbee` | `swapTokensForExactTokens(...)` |
| `0x5ae401dc` | `multicall(uint256,bytes[])` |

Any call to `approve()` (`0x095ea7b3`) or `setApprovalForAll()` (`0xa22cb465`) reverts on-chain because those selectors are not in the allowlist.

**Trade-off**: Strict mode limits the agent to only the five whitelisted function selectors. If your agent needs to call other contract functions (e.g., `deposit`, `withdraw`, `addLiquidity`), use the default off-chain strategy and rely on the Wardex SDK to catch infinite approvals.

---

## Session Keys vs. Delegations

Wardex offers two scoping mechanisms. They enforce the same boundaries with different trust models:

| | SessionManager | DelegationManager |
|-|----------------|-------------------|
| **Enforcement** | Off-chain (Wardex SDK) | On-chain (enforcer contracts) |
| **Trust model** | Trust the SDK process | Trust the blockchain |
| **Signing** | SDK manages keys internally | Owner signs EIP-712 externally |
| **Bypass resistance** | If SDK is down, no enforcement | Enforcers hold even if SDK is bypassed |
| **Gas cost** | Zero (off-chain validation) | Gas for on-chain enforcer checks |
| **Setup** | `new SessionManager()` | `new DelegationManager({ chainId })` + owner signature |
| **Best for** | Fast iteration, testing, low-value ops | Production, high-value ops, regulatory requirements |

For maximum security, use both: `SessionManager` for fast off-chain gating, and `DelegationManager` for the on-chain backstop.

---

## What's Next?

- **Session keys**: See the [Operator Quickstart](../operator-quickstart.md) for the simpler `SessionManager` API (off-chain only).
- **MCP Server**: Add the [MCP Server](./mcp-server.md) to expose Wardex tools to Claude Code.
- **Auto-interception**: Install the [Claude Code Skill](./claude-skill.md) for automatic PreToolUse hook evaluation.
- **On-chain validation**: Deploy the `WardexValidationModule` (ERC-4337) for spending limits on smart accounts -- see `packages/contracts/`.
