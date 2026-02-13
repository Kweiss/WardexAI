# @wardexai/intelligence

Threat intelligence package for Wardex.

## What It Provides

- Address reputation lookups
- Contract bytecode analysis (proxy/danger patterns)
- Local denylist integration
- Cached intelligence provider for `@wardexai/core`

## Install

```bash
npm install @wardexai/intelligence
```

## Quick Example

```ts
import { createIntelligenceProvider } from '@wardexai/intelligence';

const intel = createIntelligenceProvider({
  rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
  chainId: 1,
  explorerApiKey: process.env.ETHERSCAN_API_KEY,
  // Optional explicit explorer endpoint:
  // explorerApiUrl: 'https://api.etherscan.io/api',
});
```

## Links

- Monorepo: https://github.com/Kweiss/Wardex
- Docs: https://github.com/Kweiss/Wardex/tree/main/docs/api-reference
