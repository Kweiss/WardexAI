# @wardexai/signer

Signer and delegation utilities for Wardex.

## What It Provides

- Isolated process signer over Unix socket IPC
- Approval-token based signing flow
- Session key management (ERC-7715)
- MetaMask Delegation Framework integration

## Install

```bash
npm install @wardexai/signer
```

## Quick Example

```ts
import { DelegationManager } from '@wardexai/signer';

const dm = new DelegationManager({ chainId: 1 });
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs/guides
