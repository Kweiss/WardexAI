# @wardexai/intelligence API Reference

On-chain threat intelligence for Wardex. Provides address reputation scoring, contract bytecode analysis, and denylist management.

## Installation

```bash
npm install @wardexai/intelligence
```

> **Note**: This is an optional package. `@wardexai/core` works standalone without it. When installed, `shield.ts` dynamically imports it and wires the intelligence provider into the `addressChecker` and `contractChecker` middleware.

---

## `createIntelligenceProvider()`

Creates an intelligence provider that fetches on-chain data via JSON-RPC.

### Import

```typescript
import { createIntelligenceProvider } from '@wardexai/intelligence';
```

### Usage

```typescript
const intel = createIntelligenceProvider({
  rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
  chainId: 1,
  denylistPath: './denylists/mainnet.json',       // optional
  explorerApiKey: 'YOUR_ETHERSCAN_KEY',            // optional
  explorerApiUrl: 'https://api.etherscan.io/api',  // optional
});
```

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `rpcUrl` | `string` | Yes | JSON-RPC endpoint for on-chain queries |
| `chainId` | `number` | Yes | Chain ID |
| `denylistPath` | `string` | No | Path to local denylist JSON file |
| `explorerApiKey` | `string` | No | Block explorer API key (Etherscan/etc.) |
| `explorerApiUrl` | `string` | No | Block explorer API base URL |

### Returns

`IntelligenceProvider` — an object with the following methods:

---

## `IntelligenceProvider`

### `getAddressReputation(address)`

Fetches reputation data for an Ethereum address. Combines denylist checks, on-chain activity analysis, and contract verification status.

```typescript
const reputation = await intel.getAddressReputation('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45');

console.log(reputation);
// {
//   address: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
//   score: 75,                // 0-100, higher = safer
//   isDenylisted: false,
//   isAllowlisted: false,
//   ageDays: 0,               // Populated in v2
//   transactionCount: 48523,
//   labels: ['contract', 'verified'],
//   isVerified: true,
//   riskFactors: [],
// }
```

**Score modifiers:**
| Condition | Score Impact |
|---|---|
| Denylisted | Score = 0 |
| > 100 transactions | +15 |
| > 10 transactions | +5 |
| 0 transactions | -20 |
| Contract verified | +10 |
| Contract not verified | -10 |

**Caching**: Results are cached for 5 minutes per address.

---

### `getContractAnalysis(address)`

Analyzes contract bytecode for dangerous patterns.

```typescript
const analysis = await intel.getContractAnalysis('0xSuspiciousContract...');

console.log(analysis);
// {
//   address: '0x...',
//   isVerified: false,
//   isProxy: true,
//   implementationAddress: '0x...',
//   dangerousPatterns: [
//     { name: 'DELEGATECALL', pattern: 'f4', severity: 'high', description: '...' }
//   ],
//   allowsInfiniteApproval: true,
//   hasSelfDestruct: false,
//   hasUnsafeDelegatecall: true,
//   risk: 'high',
// }
```

**Risk determination:**
| Condition | Risk Level |
|---|---|
| Has SELFDESTRUCT | `critical` |
| DELEGATECALL + unverified | `high` |
| Proxy + unverified | `high` |
| Unverified contract | `medium` |
| Dangerous patterns + verified | `medium` |
| Verified, no dangerous patterns | `low` |
| Not a contract (EOA) | `safe` |

**Patterns detected:**
- `SELFDESTRUCT` (opcode `ff`)
- `DELEGATECALL` (opcode `f4`)
- `CALLCODE` (opcode `f2`)
- EIP-1167 minimal proxy pattern
- EIP-1967 transparent proxy pattern
- `approve(address,uint256)` selector

**Caching**: Results are cached for 5 minutes per address.

---

### `isDenylisted(address)`

Synchronous check against the local denylist.

```typescript
if (intel.isDenylisted('0xbad...')) {
  console.log('Address is on the denylist!');
}
```

---

### `refresh()`

Reloads the denylist from disk and clears all caches.

```typescript
await intel.refresh();
```

---

## Denylist Management

### `loadDenylist(path)`

Loads a denylist from a JSON file.

```typescript
import { loadDenylist } from '@wardexai/intelligence';

const entries = loadDenylist('./denylists/mainnet.json');
```

**File format** (JSON array):
```json
[
  {
    "address": "0xdead000000000000000000000000000000000001",
    "reason": "Known phishing contract",
    "severity": "critical",
    "reportedAt": "2025-01-01T00:00:00.000Z",
    "source": "internal-research"
  }
]
```

### `saveDenylist(path, entries)`

Saves a denylist to a JSON file.

```typescript
import { saveDenylist, createDenylistEntry } from '@wardexai/intelligence';

const entry = createDenylistEntry(
  '0xbad...',
  'Identified as honeypot contract',
  'critical',
  'manual-review'
);

saveDenylist('./denylists/mainnet.json', [entry]);
```

### `createDenylistEntry(address, reason, severity, source)`

Creates a properly formatted denylist entry.

```typescript
import { createDenylistEntry } from '@wardexai/intelligence';

const entry = createDenylistEntry(
  '0xdead000000000000000000000000000000000001',
  'Known phishing contract',
  'critical',
  'community-report'
);
// Returns: { address, reason, severity, reportedAt: new Date().toISOString(), source }
```

---

## `analyzeContractBytecode(code)`

Low-level bytecode analysis function. Used internally by `getContractAnalysis()` but also available for direct use.

```typescript
import { analyzeContractBytecode } from '@wardexai/intelligence';

const analysis = analyzeContractBytecode('0x6080604052...');

console.log(analysis);
// {
//   hasSelfDestruct: false,
//   hasDelegatecall: true,
//   isProxy: true,
//   implementationAddress: '0x...',
//   hasApproveFunction: true,
//   patterns: [
//     { name: 'DELEGATECALL', pattern: 'f4', severity: 'high', description: '...' },
//     { name: 'EIP-1967 Proxy', pattern: '360894...', severity: 'medium', description: '...' }
//   ],
// }
```

---

## Wiring into WardexShield

When `@wardexai/intelligence` is installed and `intelligence` config is provided, `shield.ts` automatically wires it in:

```typescript
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex.sock' },
  mode: 'adaptive',
  intelligence: {
    rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
    chainId: 1,
    denylistPath: './denylists/mainnet.json',
    explorerApiKey: 'YOUR_ETHERSCAN_KEY',
  },
});

// Now address checks and contract analysis use live on-chain data
```

Without intelligence configured, the `addressChecker` and `contractChecker` middleware use stub implementations that rely only on the policy's allowlists/denylists.

---

## Types

### `IntelligenceProviderConfig`

```typescript
interface IntelligenceProviderConfig {
  rpcUrl: string;
  chainId: number;
  denylistPath?: string;
  explorerApiKey?: string;
  explorerApiUrl?: string;
}
```

### `IntelligenceProvider`

```typescript
interface IntelligenceProvider {
  getAddressReputation(address: string): Promise<AddressReputation>;
  getContractAnalysis(address: string): Promise<ContractAnalysis>;
  isDenylisted(address: string): boolean;
  refresh(): Promise<void>;
}
```

### `DenylistEntry`

```typescript
interface DenylistEntry {
  address: string;
  reason: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reportedAt: string;
  source: string;
}
```

### `BytecodeAnalysis`

```typescript
interface BytecodeAnalysis {
  hasSelfDestruct: boolean;
  hasDelegatecall: boolean;
  isProxy: boolean;
  implementationAddress?: string;
  hasApproveFunction: boolean;
  patterns: ContractPattern[];
}
```

---

## What's Next?

- **[Core API Reference](./core.md)** — WardexShield and middleware
- **[Types Reference](./types.md)** — AddressReputation and ContractAnalysis types
- **[Threat Model](../security/threat-model.md)** — How intelligence data is used
