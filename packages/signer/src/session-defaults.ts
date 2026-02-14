/**
 * Production Session Defaults
 *
 * Conservative default boundaries for session keys. These values
 * prioritize safety — operators can loosen them explicitly when
 * creating sessions via the `createSessionWithDefaults` helper.
 */

import type { SessionKeyConfig } from './session-manager.js';

/**
 * Conservative production defaults for session key boundaries.
 *
 * - 1-hour duration limits blast radius of compromised keys
 * - 0.1 ETH per-tx cap prevents large single losses
 * - 1 ETH daily cap bounds total exposure
 * - Empty allowedContracts forces operator to explicitly define scope
 * - Infinite approvals are forbidden by default
 */
export const PRODUCTION_DEFAULTS: Readonly<SessionKeyConfig> = {
  durationSeconds: 3600, // 1 hour
  maxValuePerTx: '100000000000000000', // 0.1 ETH in wei
  maxDailyVolume: '1000000000000000000', // 1 ETH in wei
  allowedContracts: [], // must be set explicitly
  forbidInfiniteApprovals: true,
};

/**
 * Creates a session config by merging user overrides onto PRODUCTION_DEFAULTS.
 *
 * Requires `allowedContracts` to be a non-empty array — sessions without
 * an explicit contract allowlist are rejected to prevent accidental
 * broad-scope keys in production.
 *
 * @param overrides - Partial session config; at minimum must include a non-empty `allowedContracts`
 * @returns A complete SessionKeyConfig ready to pass to `SessionManager.createSession()`
 * @throws If `allowedContracts` is missing or empty after merge
 */
export function createSessionWithDefaults(
  overrides: Partial<SessionKeyConfig> & { allowedContracts: string[] },
): SessionKeyConfig {
  if (!overrides.allowedContracts || overrides.allowedContracts.length === 0) {
    throw new Error(
      'allowedContracts must be a non-empty array. ' +
        'Session keys without an explicit contract allowlist are not permitted in production.',
    );
  }

  return {
    ...PRODUCTION_DEFAULTS,
    ...overrides,
  };
}
