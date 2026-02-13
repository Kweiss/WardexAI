# @wardexai/core

Core security engine for Wardex AI agent wallet protection.

## What It Provides

- Middleware-based transaction and context evaluation pipeline
- Risk scoring and tiered policy enforcement
- Output filtering for sensitive material redaction
- Provider wrappers for ethers.js v6 and viem

## Install

```bash
npm install @wardexai/core
```

## Quick Example

```ts
import { createWardex, defaultPolicy } from '@wardexai/core';

const wardex = createWardex({
  policy: defaultPolicy(),
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex-signer.sock' },
  mode: 'adaptive',
});

const verdict = await wardex.evaluate({
  to: '0x1111111111111111111111111111111111111111',
  value: '100000000000000000',
  chainId: 1,
});
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs
