# @wardexai/signer API Reference

The signer package provides isolated key management, session key lifecycle, delegation management, and enforcer mapping for AI agent wallets. Key material never touches the AI agent process.

## Installation

```bash
npm install @wardexai/signer
```

## Imports

```typescript
import {
  // Isolated process signer
  SignerServer,
  SignerClient,
  encryptPrivateKey,
  decryptPrivateKey,
  generateApprovalToken,
  verifyApprovalToken,
  // Session keys (ERC-7715)
  SessionManager,
  // Delegation framework
  DelegationManager,
  // Enforcer mapping utilities
  mapSessionConfigToCaveats,
  getDefaultEnforcerAddresses,
  encodeAllowedTargets,
  encodeValueLte,
  encodeTimestamp,
  encodeNativeTokenPeriod,
  encodeBlockedApprovalMethods,
  decodeAllowedTargets,
  decodeValueLte,
  decodeTimestamp,
  decodeNativeTokenPeriod,
} from '@wardexai/signer';
```

---

## SignerServer

The signer server runs in an isolated OS process and holds the encrypted private key. It listens on a Unix socket and only signs transactions that include a valid Wardex HMAC approval token. The AI agent process never has access to private key material.

### Import

```typescript
import { SignerServer } from '@wardexai/signer';
```

### Constructor

```typescript
new SignerServer(config: SignerServerConfig)
```

#### config

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config.socketPath` | `string` | Yes | Unix socket path for IPC communication. |
| `config.keyFilePath` | `string` | Yes | Path to the AES-256-GCM encrypted key file. |
| `config.keyPassword` | `string` | Yes | Password for key decryption (should come from an environment variable). |
| `config.sharedSecret` | `string` | Yes | Shared HMAC secret between the SDK and signer for approval token verification. |
| `config.signFn` | `(data: string, privateKey: string) => Promise<string>` | Yes | Pluggable signing function for different key types. |
| `config.getAddressFn` | `(privateKey: string) => string` | Yes | Function that derives the public address from a private key. |

### Methods

### start

Starts the signer server: loads and decrypts the private key from disk, then begins listening on the Unix socket with restrictive permissions (`0o600`).

```typescript
start(): Promise<void>
```

#### Usage

```typescript
const server = new SignerServer({
  socketPath: '/tmp/wardex-signer.sock',
  keyFilePath: '/secure/keyfile.json',
  keyPassword: process.env.SIGNER_PASSWORD!,
  sharedSecret: process.env.SIGNER_SECRET!,
  signFn: async (data, pk) => { /* sign with secp256k1 */ },
  getAddressFn: (pk) => { /* derive address */ },
});

await server.start();
console.log('Signer server running');
```

### stop

Stops the signer server, zeroes out key material in memory, and removes the socket file.

```typescript
stop(): Promise<void>
```

#### Usage

```typescript
await server.stop();
```

---

## SignerClient

The signer client is used by the agent process to communicate with the isolated signer server over a Unix socket. It has no access to key material.

### Import

```typescript
import { SignerClient } from '@wardexai/signer';
```

### Constructor

```typescript
new SignerClient(config: SignerClientConfig)
```

#### config

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config.socketPath` | `string` | Yes | Unix socket path to connect to. |
| `config.timeout` | `number` | No | Request timeout in milliseconds. Default: `10000`. |

### Methods

### signTransaction

Sends a transaction to the isolated signer for signing. Requires a valid HMAC approval token.

```typescript
signTransaction(
  serializedTx: string,
  transactionHash: string,
  approvalToken: string
): Promise<string>
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `serializedTx` | `string` | Yes | The serialized transaction data to sign. |
| `transactionHash` | `string` | Yes | Hash of the transaction (used for approval token verification). |
| `approvalToken` | `string` | Yes | HMAC-SHA256 approval token from `generateApprovalToken`. |

#### Return Type

`Promise<string>` -- The signed transaction.

#### Errors

Throws `Error` if the signer rejects the request (invalid token, timeout, or connection failure).

---

### signMessage

Sends a message to the isolated signer for signing. Requires a valid HMAC approval token.

```typescript
signMessage(
  message: string,
  approvalToken: string
): Promise<string>
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `message` | `string` | Yes | The message to sign. |
| `approvalToken` | `string` | Yes | HMAC-SHA256 approval token. |

#### Return Type

`Promise<string>` -- The message signature.

---

### getAddress

Requests the signer's public address from the isolated process.

```typescript
getAddress(): Promise<string>
```

#### Return Type

`Promise<string>` -- The signer's Ethereum address.

---

### healthCheck

Checks if the isolated signer process is available and responsive.

```typescript
healthCheck(): Promise<boolean>
```

#### Return Type

`Promise<boolean>` -- `true` if the signer is healthy, `false` otherwise.

#### Usage

```typescript
const client = new SignerClient({ socketPath: '/tmp/wardex-signer.sock' });

const healthy = await client.healthCheck();
if (!healthy) {
  console.error('Signer process is not responding');
}
```

---

## encryptPrivateKey

Encrypts a private key for storage at rest using AES-256-GCM with scrypt key derivation.

### Import

```typescript
import { encryptPrivateKey } from '@wardexai/signer';
```

### Usage

```typescript
import { encryptPrivateKey } from '@wardexai/signer';
import fs from 'node:fs';

const encrypted = encryptPrivateKey(
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  'strong-password-from-env'
);

fs.writeFileSync('/secure/keyfile.json', JSON.stringify(encrypted));
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `privateKey` | `string` | Yes | The private key to encrypt. |
| `password` | `string` | Yes | The password used to derive the encryption key via scrypt. |

### Return Type

```typescript
interface EncryptedKeyFile {
  version: 1;
  algorithm: 'aes-256-gcm';
  iv: string;       // Hex-encoded 16-byte IV
  authTag: string;   // Hex-encoded GCM authentication tag
  encryptedKey: string; // Hex-encoded ciphertext
  salt: string;      // Hex-encoded 32-byte scrypt salt
}
```

---

## decryptPrivateKey

Decrypts a private key from an encrypted key file.

### Import

```typescript
import { decryptPrivateKey } from '@wardexai/signer';
```

### Usage

```typescript
import { decryptPrivateKey } from '@wardexai/signer';
import fs from 'node:fs';

const keyFile = JSON.parse(fs.readFileSync('/secure/keyfile.json', 'utf8'));
const privateKey = decryptPrivateKey(keyFile, 'strong-password-from-env');
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `keyFile` | `EncryptedKeyFile` | Yes | The encrypted key file object (as produced by `encryptPrivateKey`). |
| `password` | `string` | Yes | The password used during encryption. |

### Return Type

`string` -- The decrypted private key.

### Errors

Throws if the password is incorrect or the data is tampered (GCM authentication failure).

---

## generateApprovalToken

Generates a cryptographic HMAC-SHA256 approval token that proves Wardex evaluated and approved a specific transaction. The token binds to both the transaction hash and a timestamp.

### Import

```typescript
import { generateApprovalToken } from '@wardexai/signer';
```

### Usage

```typescript
const token = generateApprovalToken(
  '0xabc123...', // transaction hash
  'shared-secret-between-sdk-and-signer'
);
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `transactionHash` | `string` | Yes | The hash of the transaction being approved. |
| `sharedSecret` | `string` | Yes | Shared secret between the Wardex SDK and the signer process. |
| `timestamp` | `number` | No | Unix timestamp in milliseconds. Defaults to `Date.now()`. |

### Return Type

`string` -- An 80-character hex string: 64 chars of HMAC + 16 chars of hex-encoded timestamp.

---

## verifyApprovalToken

Verifies an approval token against a transaction hash using timing-safe comparison. Tokens expire after 5 minutes to prevent replay attacks.

### Import

```typescript
import { verifyApprovalToken } from '@wardexai/signer';
```

### Usage

```typescript
const isValid = verifyApprovalToken(
  token,
  '0xabc123...', // transaction hash
  'shared-secret-between-sdk-and-signer'
);

if (!isValid) {
  throw new Error('Invalid approval token');
}
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | `string` | Yes | The approval token to verify (80 hex characters). |
| `transactionHash` | `string` | Yes | The hash of the transaction to verify against. |
| `sharedSecret` | `string` | Yes | Shared secret between the Wardex SDK and the signer process. |

### Return Type

`boolean` -- `true` if the token is valid and not expired, `false` otherwise.

### Validation Rules

- Token must be exactly 80 hex characters.
- Timestamp embedded in the token must be within 5 minutes of the current time.
- HMAC comparison uses `crypto.timingSafeEqual` to prevent timing attacks.

---

## SessionManager

Manages ERC-7715 scoped session keys for AI agent wallets. Session keys allow an agent to transact within strict, pre-defined boundaries without needing the full owner key for each operation.

### Import

```typescript
import { SessionManager } from '@wardexai/signer';
```

### Constructor

```typescript
new SessionManager()
```

No configuration parameters. The `SessionManager` maintains internal state for sessions, session states, and private keys.

### Methods

### createSession

Creates a new session key with the given boundaries. Generates a new keypair internally -- the private key never leaves the `SessionManager`.

```typescript
createSession(config: SessionKeyConfig): SessionKey
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | [`SessionKeyConfig`](./types.md#sessionkeyconfig) | Yes | Session boundary configuration. |

#### config.allowedContracts

```typescript
const session = manager.createSession({
  allowedContracts: ['0xUniswapRouter', '0xAaveLendingPool'],
  // ...
});
```

Type: `string[]` -- Allowed target contract addresses. Normalized to lowercase internally.

#### config.maxValuePerTx

```typescript
const session = manager.createSession({
  maxValuePerTx: '100000000000000000', // 0.1 ETH
  // ...
});
```

Type: `string` -- Maximum value per single transaction in wei.

#### config.maxDailyVolume

```typescript
const session = manager.createSession({
  maxDailyVolume: '1000000000000000000', // 1 ETH
  // ...
});
```

Type: `string` -- Maximum cumulative daily volume in wei. Resets at midnight.

#### config.durationSeconds

```typescript
const session = manager.createSession({
  durationSeconds: 3600, // 1 hour
  // ...
});
```

Type: `number` -- Session duration in seconds from creation.

#### config.forbidInfiniteApprovals

```typescript
const session = manager.createSession({
  forbidInfiniteApprovals: true,
  // ...
});
```

Type: `boolean` -- Whether to block ERC-20 `approve` calls with amounts exceeding 2^128 and `setApprovalForAll` calls.

#### Return Type

[`SessionKey`](./types.md#sessionkey) -- The session key metadata (private key stays internal).

#### Usage

```typescript
const manager = new SessionManager();

const session = manager.createSession({
  allowedContracts: ['0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D'],
  maxValuePerTx: '100000000000000000',   // 0.1 ETH
  maxDailyVolume: '1000000000000000000', // 1 ETH
  durationSeconds: 3600,                  // 1 hour
  forbidInfiniteApprovals: true,
});

console.log('Session ID:', session.id);
console.log('Session address:', session.address);
console.log('Expires at:', session.expiresAt);
```

---

### validateTransaction

Validates whether a transaction is within the session key's boundaries. Checks revocation, expiration, target contract allowlist, per-transaction value limit, daily volume limit, and infinite approval blocking.

```typescript
validateTransaction(
  sessionId: string,
  to: string,
  value: string,
  data?: string
): SessionValidationResult
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionId` | `string` | Yes | The session key ID. |
| `to` | `string` | Yes | Target address of the transaction. |
| `value` | `string` | Yes | Transaction value in wei. |
| `data` | `string` | No | Encoded calldata (checked for infinite approvals). |

#### Return Type

[`SessionValidationResult`](./types.md#sessionvalidationresult)

#### Usage

```typescript
const result = manager.validateTransaction(
  session.id,
  '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
  '50000000000000000', // 0.05 ETH
);

if (!result.valid) {
  console.error('Transaction rejected:', result.reason);
}
```

---

### recordTransaction

Records a confirmed transaction against the session state. Call this after a transaction is successfully executed to update daily volume and transaction count tracking.

```typescript
recordTransaction(sessionId: string, value: string, to: string): void
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionId` | `string` | Yes | The session key ID. |
| `value` | `string` | Yes | Transaction value in wei. |
| `to` | `string` | Yes | Target address (tracked in `contractsUsed`). |

---

### revokeSession

Immediately revokes a session key. Zeroes out the private key material in memory.

```typescript
revokeSession(sessionId: string): boolean
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionId` | `string` | Yes | The session key ID to revoke. |

#### Return Type

`boolean` -- `true` if the session was found and revoked, `false` if not found.

---

### getSession

Gets a session key by ID.

```typescript
getSession(sessionId: string): SessionKey | undefined
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionId` | `string` | Yes | The session key ID. |

#### Return Type

[`SessionKey | undefined`](./types.md#sessionkey)

---

### getSessionState

Gets the current runtime state of a session, including daily volume spent, transaction count, and contracts used.

```typescript
getSessionState(sessionId: string): SessionState | undefined
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionId` | `string` | Yes | The session key ID. |

#### Return Type

[`SessionState | undefined`](./types.md#sessionstate)

---

### getActiveSessions

Lists all active sessions (non-revoked, non-expired).

```typescript
getActiveSessions(): SessionKey[]
```

#### Return Type

[`SessionKey[]`](./types.md#sessionkey)

---

### rotateSession

Rotates a session: revokes the old one and creates a new one with the same configuration but a fresh key and expiration.

```typescript
rotateSession(sessionId: string): SessionKey | null
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionId` | `string` | Yes | The session key ID to rotate. |

#### Return Type

[`SessionKey | null`](./types.md#sessionkey) -- The new session key, or `null` if the original was not found.

#### Usage

```typescript
const newSession = manager.rotateSession(session.id);
if (newSession) {
  console.log('Rotated to new session:', newSession.id);
}
```

---

### getExpiringSessionsSoon

Gets sessions that are near expiration, within the given time window.

```typescript
getExpiringSessionsSoon(withinSeconds: number): SessionKey[]
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `withinSeconds` | `number` | Yes | Time window in seconds. Returns sessions expiring within this window. |

#### Return Type

[`SessionKey[]`](./types.md#sessionkey)

#### Usage

```typescript
// Find sessions expiring within the next 5 minutes
const expiring = manager.getExpiringSessionsSoon(300);
for (const session of expiring) {
  manager.rotateSession(session.id);
}
```

---

### cleanup

Removes all expired and revoked sessions from memory. Zeroes out any remaining private key material before deletion.

```typescript
cleanup(): number
```

#### Return Type

`number` -- The number of sessions removed.

---

## DelegationManager

Manages EIP-712 signed delegations backed by MetaMask's Delegation Framework. Mirrors the `SessionManager` API but produces on-chain-enforceable delegations with caveat enforcer contracts.

Key design: `createDelegation()` does not sign. Signing requires the owner's private key, which Wardex never holds. The owner calls `getSigningPayload()` to get the EIP-712 typed data, signs externally, then calls `setSignature()`.

### Import

```typescript
import { DelegationManager } from '@wardexai/signer';
```

### Constructor

```typescript
new DelegationManager(config: DelegationManagerConfig)
```

#### config

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config.chainId` | `number` | Yes | Chain ID for EIP-712 domain separator. |
| `config.delegationManagerAddress` | `string` | No | DelegationManager contract address. Defaults to canonical v1.3.0 deployment. |
| `config.enforcerAddresses` | `Partial<EnforcerAddresses>` | No | Custom enforcer addresses (merged with canonical defaults). |
| `config.strictInfiniteApprovalBlocking` | `boolean` | No | If true, adds AllowedMethodsEnforcer to block approve/setApprovalForAll at the contract level. |

### Methods

### createDelegation

Creates a new unsigned delegation with caveats mapped from a `SessionKeyConfig`. The delegation must be signed by the owner before it can be used.

```typescript
createDelegation(
  sessionConfig: SessionKeyConfig,
  delegator: string
): WardexDelegation
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `sessionConfig` | [`SessionKeyConfig`](./types.md#sessionkeyconfig) | Yes | Session boundaries to map to caveat enforcers. |
| `delegator` | `string` | Yes | The owner address granting authority. |

#### Return Type

[`WardexDelegation`](./types.md#wardexdelegation) -- An unsigned delegation.

#### Usage

```typescript
const dm = new DelegationManager({ chainId: 1 });

const delegation = dm.createDelegation(
  {
    allowedContracts: ['0xUniswapRouter'],
    maxValuePerTx: '100000000000000000',
    maxDailyVolume: '1000000000000000000',
    durationSeconds: 3600,
    forbidInfiniteApprovals: true,
  },
  '0xOwnerAddress'
);

console.log('Delegation ID:', delegation.id);
console.log('Delegate:', delegation.delegate);
console.log('Signed:', delegation.signature !== ''); // false
```

---

### validateTransaction

Validates whether a transaction is within the delegation's boundaries. Performs the same off-chain checks as `SessionManager` for defense-in-depth. On-chain enforcers provide the real backstop.

```typescript
validateTransaction(
  delegationId: string,
  to: string,
  value: string,
  data?: string
): SessionValidationResult
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID. |
| `to` | `string` | Yes | Target address. |
| `value` | `string` | Yes | Transaction value in wei. |
| `data` | `string` | No | Encoded calldata. |

#### Return Type

[`SessionValidationResult`](./types.md#sessionvalidationresult)

#### Additional Checks

- Returns invalid if the delegation has not been signed (no `signature`).

---

### recordTransaction

Records a confirmed transaction against the delegation state.

```typescript
recordTransaction(delegationId: string, value: string): void
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID. |
| `value` | `string` | Yes | Transaction value in wei. |

---

### revokeDelegation

Immediately revokes a delegation.

```typescript
revokeDelegation(delegationId: string): boolean
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID. |

#### Return Type

`boolean` -- `true` if found and revoked, `false` if not found.

---

### rotateDelegation

Rotates a delegation: revokes the old one and creates a new unsigned delegation with the same config and delegator.

```typescript
rotateDelegation(delegationId: string): WardexDelegation | null
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID to rotate. |

#### Return Type

[`WardexDelegation | null`](./types.md#wardexdelegation) -- The new unsigned delegation, or `null` if the original was not found.

---

### getDelegation

Gets a delegation by ID.

```typescript
getDelegation(id: string): WardexDelegation | undefined
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | `string` | Yes | The delegation ID. |

#### Return Type

[`WardexDelegation | undefined`](./types.md#wardexdelegation)

---

### getActiveDelegations

Lists all active delegations (non-revoked, non-expired).

```typescript
getActiveDelegations(): WardexDelegation[]
```

#### Return Type

[`WardexDelegation[]`](./types.md#wardexdelegation)

---

### cleanup

Removes all expired and revoked delegations from memory.

```typescript
cleanup(): number
```

#### Return Type

`number` -- The number of delegations removed.

---

### getSigningPayload

Returns the EIP-712 signing payload for a delegation. The owner must sign this payload externally to activate the delegation.

```typescript
getSigningPayload(delegationId: string): {
  domain: EIP712Domain;
  types: Record<string, TypedDataField[]>;
  value: Record<string, unknown>;
} | null
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID. |

#### Return Type

An object with `domain`, `types`, and `value` suitable for EIP-712 signing, or `null` if not found.

#### Usage

```typescript
const payload = dm.getSigningPayload(delegation.id);
if (payload) {
  // Sign with ethers.js
  const signature = await ownerWallet.signTypedData(
    payload.domain,
    payload.types,
    payload.value
  );
  dm.setSignature(delegation.id, signature);
}
```

---

### setSignature

Stores the EIP-712 signature for a delegation. Must be called after the owner signs the payload from `getSigningPayload()`.

```typescript
setSignature(delegationId: string, signature: string): void
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID. |
| `signature` | `string` | Yes | The EIP-712 signature from the delegator. |

#### Errors

- Throws `Error` if the delegation is not found.
- Throws `Error` if the delegation has been revoked.

---

### prepareRedemption

Prepares the ABI-encoded calldata for redeeming a delegation via `DeleGatorCore.redeemDelegations()`. The returned calldata can be used in an ERC-4337 UserOp or sent directly to the DeleGatorCore contract.

```typescript
prepareRedemption(
  delegationId: string,
  executions: Execution[]
): { target: string; value: bigint; calldata: string } | null
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegationId` | `string` | Yes | The delegation ID. |
| `executions` | [`Execution[]`](./types.md#execution) | Yes | Array of operations to execute via delegated authority. |

#### Return Type

```typescript
{
  target: string;   // DelegationManager contract address
  value: bigint;     // Total native value across all executions
  calldata: string;  // ABI-encoded redeemDelegations calldata
} | null
```

Returns `null` if the delegation is not found or not signed.

#### Usage

```typescript
const redemption = dm.prepareRedemption(delegation.id, [
  {
    target: '0xUniswapRouter',
    value: 0n,
    callData: '0x38ed1739...', // swapExactTokensForTokens calldata
  },
]);

if (redemption) {
  // Send as UserOp or direct transaction
  await signer.sendTransaction({
    to: redemption.target,
    value: redemption.value,
    data: redemption.calldata,
  });
}
```

---

### getEnforcerAddresses

Returns a copy of the enforcer addresses used by this `DelegationManager` instance.

```typescript
getEnforcerAddresses(): EnforcerAddresses
```

#### Return Type

[`EnforcerAddresses`](./types.md#enforceraddresses)

---

## mapSessionConfigToCaveats

Maps a Wardex `SessionKeyConfig` to an array of caveat terms for a MetaMask Delegation Framework delegation. Each field in the config maps to a specific enforcer contract.

### Import

```typescript
import { mapSessionConfigToCaveats } from '@wardexai/signer';
```

### Usage

```typescript
import { mapSessionConfigToCaveats, getDefaultEnforcerAddresses } from '@wardexai/signer';

const caveats = mapSessionConfigToCaveats(
  {
    allowedContracts: ['0xUniswapRouter'],
    maxValuePerTx: '100000000000000000',
    maxDailyVolume: '1000000000000000000',
    durationSeconds: 3600,
    forbidInfiniteApprovals: true,
  },
  getDefaultEnforcerAddresses(),
  { strictInfiniteApprovalBlocking: true }
);
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `config` | [`SessionKeyConfig`](./types.md#sessionkeyconfig) | Yes | Session boundaries to map. |
| `addresses` | [`EnforcerAddresses`](./types.md#enforceraddresses) | No | Enforcer contract addresses. Defaults to canonical v1.3.0 addresses. |
| `options.strictInfiniteApprovalBlocking` | `boolean` | No | If true, adds `AllowedMethodsEnforcer` to block `approve`/`setApprovalForAll` at the contract level. Default: off-chain only. |

### Return Type

[`CaveatTerm[]`](./types.md#caveatterm)

### Mapping Table

| SessionKeyConfig Field | Enforcer Contract | Encoding |
|------------------------|-------------------|----------|
| `allowedContracts` | `AllowedTargetsEnforcer` | `abi.encode(address[])` |
| `maxValuePerTx` | `ValueLteEnforcer` | `abi.encode(uint256)` |
| `maxDailyVolume` | `NativeTokenPeriodTransferEnforcer` | `abi.encode(uint256, uint256)` (allowance, period=86400) |
| `durationSeconds` | `TimestampEnforcer` | `abi.encode(uint256, uint256)` (after=0, before=now+duration) |
| `forbidInfiniteApprovals` (strict) | `AllowedMethodsEnforcer` | `abi.encode(bytes4[])` (safe selectors only) |

---

## getDefaultEnforcerAddresses

Returns the canonical enforcer contract addresses for MetaMask Delegation Framework v1.3.0. These addresses are the same on all 35+ supported EVM chains.

### Import

```typescript
import { getDefaultEnforcerAddresses } from '@wardexai/signer';
```

### Usage

```typescript
const addresses = getDefaultEnforcerAddresses();
console.log('AllowedTargets:', addresses.allowedTargets);
console.log('DelegationManager:', addresses.delegationManager);
```

### Return Type

[`EnforcerAddresses`](./types.md#enforceraddresses)

---

## Encoding Functions

Low-level ABI encoding functions for individual enforcer terms. Used internally by `mapSessionConfigToCaveats`, but exported for advanced usage.

### encodeAllowedTargets

ABI-encodes contract addresses for the `AllowedTargetsEnforcer`.

```typescript
encodeAllowedTargets(contracts: string[]): string
```

Format: `abi.encode(address[])`

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contracts` | `string[]` | Yes | Array of allowed contract addresses. |

---

### encodeValueLte

ABI-encodes the maximum native value for the `ValueLteEnforcer`.

```typescript
encodeValueLte(maxWei: string): string
```

Format: `abi.encode(uint256)`

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `maxWei` | `string` | Yes | Maximum value in wei. |

---

### encodeTimestamp

ABI-encodes the expiration deadline for the `TimestampEnforcer`. Sets `afterTimestamp=0` (no start constraint) and `beforeTimestamp=now+durationSeconds`.

```typescript
encodeTimestamp(durationSeconds: number): string
```

Format: `abi.encode(uint256, uint256)` -- `(afterTimestamp, beforeTimestamp)`

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `durationSeconds` | `number` | Yes | Duration from now until expiry. |

---

### encodeNativeTokenPeriod

ABI-encodes the volume limit for the `NativeTokenPeriodTransferEnforcer`.

```typescript
encodeNativeTokenPeriod(maxWei: string, periodSeconds?: number): string
```

Format: `abi.encode(uint256, uint256)` -- `(allowance, period)`

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `maxWei` | `string` | Yes | Maximum native token transfer in the period (wei). |
| `periodSeconds` | `number` | No | Period length in seconds. Default: `86400` (24 hours). |

---

### encodeBlockedApprovalMethods

ABI-encodes an allowlist of safe function selectors for the `AllowedMethodsEnforcer`, excluding `approve` and `setApprovalForAll`.

```typescript
encodeBlockedApprovalMethods(): string
```

Format: `abi.encode(bytes4[])`

Allowed selectors:

| Selector | Function |
|----------|----------|
| `0xa9059cbb` | `transfer(address,uint256)` |
| `0x23b872dd` | `transferFrom(address,address,uint256)` |
| `0x38ed1739` | `swapExactTokensForTokens` |
| `0x8803dbee` | `swapTokensForExactTokens` |
| `0x5ae401dc` | `multicall(uint256,bytes[])` |

---

## Decoding Functions

Helpers for inspecting existing delegation caveat terms.

### decodeAllowedTargets

Decodes `AllowedTargetsEnforcer` terms back into an array of addresses.

```typescript
decodeAllowedTargets(terms: string): string[]
```

---

### decodeValueLte

Decodes `ValueLteEnforcer` terms back into a max value (wei string).

```typescript
decodeValueLte(terms: string): string
```

---

### decodeTimestamp

Decodes `TimestampEnforcer` terms back into timestamp values.

```typescript
decodeTimestamp(terms: string): {
  afterTimestamp: number;
  beforeTimestamp: number;
}
```

---

### decodeNativeTokenPeriod

Decodes `NativeTokenPeriodTransferEnforcer` terms back into allowance and period.

```typescript
decodeNativeTokenPeriod(terms: string): {
  allowance: string;
  periodSeconds: number;
}
```
