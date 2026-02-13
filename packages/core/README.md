# @wardexai/core

Core security engine for Wardex AI agent wallet protection.

## What It Provides

- Middleware-based transaction and context evaluation pipeline
- Risk scoring and tiered policy enforcement
- Output filtering for sensitive material redaction
- Provider wrappers for ethers.js v6 and viem
- Chain-aware explorer integration defaults for intelligence providers

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

Intelligence configuration supports explicit explorer overrides:

```ts
const wardex = createWardex({
  // ...
  intelligence: {
    rpcUrl: 'https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY',
    chainId: 1,
    explorerApiKey: process.env.ETHERSCAN_API_KEY,
    // Optional override when chain defaults are not suitable:
    // explorerApiUrl: 'https://api.etherscan.io/api',
  },
});
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs
