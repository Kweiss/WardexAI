# @wardexai/signer

Signer and delegation utilities for Wardex.

## What It Provides

- Isolated process signer over Unix socket IPC
- Approval-token based signing flow
- Session key management (ERC-7715)
- MetaMask Delegation Framework integration
- EIP-712 signature verification for delegations (`setSignature`)
- Full function-encoded redemption calldata (`prepareRedemption`)

## Install

```bash
npm install @wardexai/signer
```

## Quick Example

```ts
import { DelegationManager } from '@wardexai/signer';

const dm = new DelegationManager({ chainId: 1 });
const delegation = dm.createDelegation(sessionConfig, ownerAddress);
const payload = dm.getSigningPayload(delegation.id);
// owner signs EIP-712 payload externally
dm.setSignature(delegation.id, ownerSignature);
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs/guides
