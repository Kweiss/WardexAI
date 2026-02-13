import { describe, it, expect } from 'vitest';
import {
  createValueAssessor,
  createMiddlewareContext,
  defaultPolicy,
} from '@wardexai/core';

const USDC = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';

describe('Value Assessor Precision', () => {
  it('should estimate large ETH values without Number(BigInt) overflow artifacts', async () => {
    const assessor = createValueAssessor({ ethPriceUsd: 3500 });
    const ctx = createMiddlewareContext({
      transaction: {
        to: USDC,
        value: '9008000000000000000000', // 9008 ETH
        chainId: 1,
      },
      policy: defaultPolicy(),
    });

    await assessor(ctx, async () => {});
    const estimated = ctx.metadata.estimatedValueUsd as number;

    expect(Number.isFinite(estimated)).toBe(true);
    expect(estimated).toBeGreaterThan(30_000_000);
  });

  it('should support non-18 token decimals for transfer valuation', async () => {
    const assessor = createValueAssessor({
      tokenPricesUsd: new Map([[USDC, 1]]),
      tokenDecimals: new Map([[USDC, 6]]),
    });

    const ctx = createMiddlewareContext({
      transaction: {
        to: USDC,
        value: '0',
        chainId: 1,
      },
      decoded: {
        raw: { to: USDC, value: '0', chainId: 1 },
        isApproval: false,
        isTransfer: true,
        involvesEth: false,
        parameters: { amount: '1500000' }, // 1.5 USDC (6 decimals)
        estimatedValueUsd: 0,
      },
      policy: defaultPolicy(),
    });

    await assessor(ctx, async () => {});
    const estimated = ctx.decoded?.estimatedValueUsd ?? 0;

    expect(estimated).toBeGreaterThan(1.4);
    expect(estimated).toBeLessThan(1.6);
  });
});
