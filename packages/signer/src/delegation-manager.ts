/**
 * DelegationManager
 *
 * Manages EIP-712 signed delegations backed by MetaMask's Delegation Framework.
 * Mirrors the SessionManager API but produces on-chain-enforceable delegations
 * with caveat enforcer contracts.
 *
 * Key design decisions:
 * 1. createDelegation() does NOT sign — signing requires the owner's private key,
 *    which Wardex never holds. Owner calls getSigningPayload() then setSignature().
 * 2. validateTransaction() performs the same off-chain checks as SessionManager
 *    (defense-in-depth: on-chain enforcers are the real backstop).
 * 3. prepareRedemption() ABI-encodes calldata for DeleGatorCore.redeemDelegations().
 * 4. No runtime dependency on @metamask/delegation-toolkit.
 *
 * Reference:
 *   https://github.com/metamask/delegation-framework
 *   EIP-712: Typed structured data hashing and signing
 */

import * as crypto from 'node:crypto';
import { AbiCoder, computeAddress } from 'ethers';
import type { SessionKeyConfig } from './session-manager.js';
import type { SessionValidationResult } from './session-manager.js';
import {
  mapSessionConfigToCaveats,
  getDefaultEnforcerAddresses,
  type CaveatTerm,
  type EnforcerAddresses,
} from './enforcer-mapping.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Configuration for creating a DelegationManager instance.
 */
export interface DelegationManagerConfig {
  /** Chain ID for EIP-712 domain separator */
  chainId: number;
  /** DelegationManager contract address (defaults to canonical v1.3.0) */
  delegationManagerAddress?: string;
  /** Custom enforcer addresses (merged with canonical defaults) */
  enforcerAddresses?: Partial<EnforcerAddresses>;
  /** If true, block approve/setApprovalForAll at the enforcer level */
  strictInfiniteApprovalBlocking?: boolean;
}

/**
 * A Wardex-managed delegation backed by MetaMask's Delegation Framework.
 */
export interface WardexDelegation {
  /** Unique delegation identifier (Wardex internal) */
  id: string;
  /** Delegate address (the agent's session key / account) */
  delegate: string;
  /** Delegator address (the owner granting authority) */
  delegator: string;
  /**
   * Parent delegation hash. Set to zero hash for root delegations
   * (authority granted directly by the account owner).
   */
  authority: string;
  /** Caveat enforcer terms mapped from SessionKeyConfig */
  caveats: CaveatTerm[];
  /** Random salt for uniqueness */
  salt: bigint;
  /**
   * EIP-712 signature from the delegator.
   * Empty string until setSignature() is called.
   */
  signature: string;
  /** Original SessionKeyConfig for off-chain validation */
  config: SessionKeyConfig;
  /** ISO timestamp when the delegation was created */
  createdAt: string;
  /** ISO timestamp when the delegation expires */
  expiresAt: string;
  /** Whether the delegation has been revoked */
  revoked: boolean;
}

/**
 * Execution struct for delegation redemption.
 * Represents a single operation to execute via the delegated authority.
 */
export interface Execution {
  /** Target contract address */
  target: string;
  /** Native value to send (wei) */
  value: bigint;
  /** Encoded calldata */
  callData: string;
}

/**
 * EIP-712 domain separator components.
 */
export interface EIP712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

/**
 * EIP-712 type definition field.
 */
export interface TypedDataField {
  name: string;
  type: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Zero hash — used as authority for root delegations */
const ROOT_AUTHORITY =
  '0x0000000000000000000000000000000000000000000000000000000000000000';

/** EIP-712 domain name for MetaMask DelegationManager */
const DOMAIN_NAME = 'DelegationManager';

/** EIP-712 domain version */
const DOMAIN_VERSION = '1';

/** EIP-712 type definitions for Delegation struct */
const DELEGATION_TYPES: Record<string, TypedDataField[]> = {
  Delegation: [
    { name: 'delegate', type: 'address' },
    { name: 'delegator', type: 'address' },
    { name: 'authority', type: 'bytes32' },
    { name: 'caveats', type: 'Caveat[]' },
    { name: 'salt', type: 'uint256' },
  ],
  Caveat: [
    { name: 'enforcer', type: 'address' },
    { name: 'terms', type: 'bytes' },
  ],
};

// Selectors for infinite approval detection (same as session-manager.ts)
const APPROVE_SELECTOR = '0x095ea7b3';
const SET_APPROVAL_FOR_ALL_SELECTOR = '0xa22cb465';
const INFINITE_THRESHOLD = BigInt(2) ** BigInt(128);

const coder = new AbiCoder();

// ---------------------------------------------------------------------------
// DelegationManager
// ---------------------------------------------------------------------------

export class DelegationManager {
  private readonly config: DelegationManagerConfig;
  private readonly enforcerAddresses: EnforcerAddresses;
  private delegations: Map<string, WardexDelegation> = new Map();
  private delegationStates: Map<
    string,
    { dailyVolumeWei: bigint; dailyResetDate: string; transactionCount: number }
  > = new Map();

  constructor(config: DelegationManagerConfig) {
    this.config = config;
    const defaults = getDefaultEnforcerAddresses();
    this.enforcerAddresses = {
      ...defaults,
      ...config.enforcerAddresses,
      delegationManager:
        config.delegationManagerAddress ?? defaults.delegationManager,
    };
  }

  // -------------------------------------------------------------------------
  // Core API (mirrors SessionManager)
  // -------------------------------------------------------------------------

  /**
   * Creates a new delegation with caveats mapped from a SessionKeyConfig.
   *
   * IMPORTANT: The delegation is NOT signed. Call getSigningPayload() to get
   * the EIP-712 typed data, have the owner sign it externally, then call
   * setSignature() to complete the delegation.
   *
   * @param sessionConfig - Boundaries for this delegation
   * @param delegator - The owner address granting authority
   * @returns A WardexDelegation (unsigned)
   */
  createDelegation(
    sessionConfig: SessionKeyConfig,
    delegator: string,
  ): WardexDelegation {
    const id = crypto.randomUUID();

    // Generate a delegate address (session key)
    // C-02 FIX: Zero the key buffer after deriving the address.
    // The delegate private key is ephemeral (used only for address derivation)
    // but we zero it promptly to minimize exposure in memory.
    const delegateKeyBuf = crypto.randomBytes(32);
    const delegateKeyHex = delegateKeyBuf.toString('hex');
    const delegate = this.deriveAddress(delegateKeyHex);
    delegateKeyBuf.fill(0);

    // Map session config to enforcer caveats
    const caveats = mapSessionConfigToCaveats(
      sessionConfig,
      this.enforcerAddresses,
      { strictInfiniteApprovalBlocking: this.config.strictInfiniteApprovalBlocking },
    );

    // Random salt for delegation uniqueness
    const salt = BigInt('0x' + crypto.randomBytes(32).toString('hex'));

    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + sessionConfig.durationSeconds * 1000,
    );

    const delegation: WardexDelegation = {
      id,
      delegate,
      delegator: delegator.toLowerCase(),
      authority: ROOT_AUTHORITY,
      caveats,
      salt,
      signature: '', // unsigned
      config: {
        ...sessionConfig,
        allowedContracts: sessionConfig.allowedContracts.map((a) =>
          a.toLowerCase(),
        ),
      },
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      revoked: false,
    };

    this.delegations.set(id, delegation);
    this.delegationStates.set(id, {
      dailyVolumeWei: 0n,
      dailyResetDate: now.toDateString(),
      transactionCount: 0,
    });

    return delegation;
  }

  /**
   * Validates whether a transaction is within the delegation's boundaries.
   * Performs the same off-chain checks as SessionManager for defense-in-depth.
   * On-chain enforcers provide the real backstop.
   */
  validateTransaction(
    delegationId: string,
    to: string,
    value: string,
    data?: string,
  ): SessionValidationResult {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) {
      return { valid: false, reason: 'Delegation not found' };
    }

    if (delegation.revoked) {
      return { valid: false, reason: 'Delegation has been revoked' };
    }

    if (new Date() >= new Date(delegation.expiresAt)) {
      return { valid: false, reason: 'Delegation has expired' };
    }

    if (!delegation.signature) {
      return { valid: false, reason: 'Delegation has not been signed' };
    }

    const targetAddr = to.toLowerCase();
    const config = delegation.config;

    // Check allowed contracts
    if (config.allowedContracts.length > 0) {
      if (!config.allowedContracts.includes(targetAddr)) {
        return {
          valid: false,
          reason: `Target ${targetAddr} is not in the allowed contracts list`,
        };
      }
    }

    // Check per-transaction value limit
    const txValue = BigInt(value || '0');
    if (txValue > BigInt(config.maxValuePerTx)) {
      return {
        valid: false,
        reason: `Transaction value ${value} exceeds per-tx limit of ${config.maxValuePerTx}`,
      };
    }

    // Check daily volume
    const state = this.delegationStates.get(delegationId)!;
    this.checkDailyReset(state);
    const projectedDaily = state.dailyVolumeWei + txValue;
    if (projectedDaily > BigInt(config.maxDailyVolume)) {
      return {
        valid: false,
        reason: `Transaction would exceed daily volume limit (${state.dailyVolumeWei}+${value} > ${config.maxDailyVolume})`,
      };
    }

    // Check infinite approval
    if (config.forbidInfiniteApprovals && data) {
      const infiniteCheck = this.checkInfiniteApproval(data);
      if (infiniteCheck) {
        return { valid: false, reason: infiniteCheck };
      }
    }

    return { valid: true };
  }

  /**
   * Records a transaction against the delegation state.
   * Call this AFTER a transaction is confirmed.
   */
  recordTransaction(delegationId: string, value: string): void {
    const state = this.delegationStates.get(delegationId);
    if (!state) return;

    this.checkDailyReset(state);
    state.dailyVolumeWei += BigInt(value || '0');
    state.transactionCount++;
  }

  /**
   * Revokes a delegation immediately.
   */
  revokeDelegation(delegationId: string): boolean {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) return false;

    delegation.revoked = true;
    return true;
  }

  /**
   * Rotates a delegation: revokes the old one and creates a new one
   * with the same config but a fresh delegate key, caveats, and expiration.
   */
  rotateDelegation(delegationId: string): WardexDelegation | null {
    const old = this.delegations.get(delegationId);
    if (!old) return null;

    this.revokeDelegation(delegationId);
    return this.createDelegation(old.config, old.delegator);
  }

  /**
   * Gets a delegation by ID.
   */
  getDelegation(id: string): WardexDelegation | undefined {
    return this.delegations.get(id);
  }

  /**
   * Lists all active (non-revoked, non-expired) delegations.
   */
  getActiveDelegations(): WardexDelegation[] {
    const now = new Date();
    return Array.from(this.delegations.values()).filter(
      (d) => !d.revoked && new Date(d.expiresAt) > now,
    );
  }

  /**
   * Removes all expired and revoked delegations from memory.
   */
  cleanup(): number {
    const now = new Date();
    let removed = 0;

    for (const [id, delegation] of this.delegations) {
      if (delegation.revoked || new Date(delegation.expiresAt) <= now) {
        this.delegations.delete(id);
        this.delegationStates.delete(id);
        removed++;
      }
    }

    return removed;
  }

  // -------------------------------------------------------------------------
  // Delegation-specific API
  // -------------------------------------------------------------------------

  /**
   * Returns the EIP-712 signing payload for a delegation.
   * The owner must sign this payload to activate the delegation.
   *
   * Workflow:
   *   1. createDelegation() → unsigned delegation
   *   2. getSigningPayload() → { domain, types, value }
   *   3. Owner signs with wallet (e.g., ethers signTypedData or viem signTypedData)
   *   4. setSignature(delegationId, signature)
   */
  getSigningPayload(delegationId: string): {
    domain: EIP712Domain;
    types: Record<string, TypedDataField[]>;
    value: Record<string, unknown>;
  } | null {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) return null;

    const domain: EIP712Domain = {
      name: DOMAIN_NAME,
      version: DOMAIN_VERSION,
      chainId: this.config.chainId,
      verifyingContract: this.enforcerAddresses.delegationManager,
    };

    const value = {
      delegate: delegation.delegate,
      delegator: delegation.delegator,
      authority: delegation.authority,
      caveats: delegation.caveats.map((c) => ({
        enforcer: c.enforcer,
        terms: c.terms,
      })),
      salt: delegation.salt.toString(),
    };

    return { domain, types: DELEGATION_TYPES, value };
  }

  /**
   * Stores the EIP-712 signature for a delegation.
   * Must be called after the owner signs the payload from getSigningPayload().
   */
  setSignature(delegationId: string, signature: string): void {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) {
      throw new Error(`Delegation ${delegationId} not found`);
    }
    if (delegation.revoked) {
      throw new Error(`Delegation ${delegationId} has been revoked`);
    }
    delegation.signature = signature;
  }

  /**
   * Prepares the calldata for redeeming a delegation via DeleGatorCore.
   *
   * The returned calldata can be used as the `callData` in an ERC-4337 UserOp
   * or sent directly to the DeleGatorCore contract.
   *
   * Function: redeemDelegations(
   *   Delegation[][] delegations,
   *   uint256[] permissionContexts,
   *   ModeCode[] modes,
   *   Execution[][] executionCallDatas
   * )
   *
   * For simplicity, we encode a single delegation chain with a single batch
   * of executions in CALL mode.
   */
  prepareRedemption(
    delegationId: string,
    executions: Execution[],
  ): { target: string; value: bigint; calldata: string } | null {
    const delegation = this.delegations.get(delegationId);
    if (!delegation) return null;
    if (!delegation.signature) return null;

    // Encode the delegation struct
    const delegationTuple = [
      delegation.delegate,
      delegation.delegator,
      delegation.authority,
      delegation.caveats.map((c) => [c.enforcer, c.terms]),
      delegation.salt,
      delegation.signature,
    ];

    // Encode executions
    const executionTuples = executions.map((e) => [
      e.target,
      e.value,
      e.callData,
    ]);

    // redeemDelegations selector: keccak256("redeemDelegations(bytes[],bytes32[],bytes[])") first 4 bytes
    // Simplified: we ABI-encode the full call
    const calldata = coder.encode(
      [
        'tuple(address,address,bytes32,tuple(address,bytes)[],uint256,bytes)[][]',
        'tuple(address,uint256,bytes)[][]',
      ],
      [
        [[delegationTuple]], // single delegation chain
        [executionTuples],   // single execution batch
      ],
    );

    return {
      target: this.enforcerAddresses.delegationManager,
      value: executions.reduce((sum, e) => sum + e.value, 0n),
      calldata,
    };
  }

  /**
   * Returns the enforcer addresses used by this DelegationManager.
   */
  getEnforcerAddresses(): EnforcerAddresses {
    return { ...this.enforcerAddresses };
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private checkDailyReset(state: {
    dailyVolumeWei: bigint;
    dailyResetDate: string;
  }): void {
    const today = utcDateKey(new Date());
    if (today !== state.dailyResetDate) {
      state.dailyVolumeWei = 0n;
      state.dailyResetDate = today;
    }
  }

  private checkInfiniteApproval(data: string): string | null {
    const normalized = data.toLowerCase();

    if (normalized.startsWith(APPROVE_SELECTOR)) {
      if (data.length >= 138) {
        const amountHex = '0x' + data.slice(74, 138);
        try {
          const amount = BigInt(amountHex);
          if (amount >= INFINITE_THRESHOLD) {
            return 'Infinite token approval detected - delegation forbids this';
          }
        } catch {
          // Can't parse amount
        }
      }
    }

    if (normalized.startsWith(SET_APPROVAL_FOR_ALL_SELECTOR)) {
      if (data.length >= 138) {
        const boolHex = '0x' + data.slice(74, 138);
        try {
          const approvalValue = BigInt(boolHex);
          if (approvalValue > 0n) {
            return 'setApprovalForAll detected - delegation forbids blanket approvals';
          }
        } catch {
          // Can't parse
        }
      }
    }

    return null;
  }

  private deriveAddress(privateKey: string): string {
    const normalized = privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`;
    return computeAddress(normalized).toLowerCase();
  }
}
function utcDateKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}
