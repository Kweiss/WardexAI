/**
 * createWardex - Main Entry Point
 *
 * The primary function that creates a Wardex security shield.
 * This is the recommended way to initialize Wardex.
 *
 * Usage:
 *
 * ```typescript
 * import { createWardex, defaultPolicy } from '@wardexai/core';
 *
 * const wardex = createWardex({
 *   policy: defaultPolicy(),
 *   signer: { type: 'isolated-process', endpoint: 'unix:///tmp/wardex-signer.sock' },
 *   mode: 'adaptive',
 * });
 *
 * // Evaluate a transaction
 * const verdict = await wardex.evaluate({
 *   to: '0x...',
 *   value: '1000000000000000000', // 1 ETH in wei
 *   chainId: 1,
 * });
 *
 * if (verdict.decision === 'approve') {
 *   // Safe to proceed
 * } else {
 *   console.log('Blocked:', verdict.reasons);
 * }
 * ```
 */

import type { WardexConfig, WardexShield } from './types.js';
import { createShield } from './shield.js';

/**
 * Creates a new Wardex security shield.
 *
 * @param config - Configuration including policy, signer, and mode
 * @returns A WardexShield instance for evaluating transactions
 */
export function createWardex(config: WardexConfig): WardexShield {
  // Validate required config
  if (!config.policy) {
    throw new Error('Wardex requires a security policy. Use defaultPolicy() for sensible defaults.');
  }
  if (!config.signer) {
    throw new Error('Wardex requires a signer configuration. The AI agent must never have direct key access.');
  }
  if (!config.mode) {
    throw new Error('Wardex requires an enforcement mode: "guardian", "copilot", or "adaptive".');
  }

  return createShield(config);
}
