/**
 * @wardexai/signer
 *
 * Isolated signer implementations for Wardex.
 * Key material never touches the AI agent process.
 */

export {
  SignerServer,
  SignerClient,
  encryptPrivateKey,
  decryptPrivateKey,
  generateApprovalToken,
  verifyApprovalToken,
  verifyAndConsumeApprovalToken,
  generateConnectionAuthProof,
  verifyConnectionAuthProof,
} from './isolated-process.js';

export type {
  SignerServerConfig,
  SignerClientConfig,
} from './isolated-process.js';

export { SessionManager } from './session-manager.js';

export type {
  SessionKeyConfig,
  SessionKey,
  SessionState,
  SessionValidationResult,
} from './session-manager.js';

export { DelegationManager } from './delegation-manager.js';

export type {
  DelegationManagerConfig,
  WardexDelegation,
  Execution,
  EIP712Domain,
  TypedDataField,
} from './delegation-manager.js';

export {
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
} from './enforcer-mapping.js';

export type {
  CaveatTerm,
  EnforcerAddresses,
} from './enforcer-mapping.js';
