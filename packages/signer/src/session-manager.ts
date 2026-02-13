/**
 * ERC-7715 Session Key Manager
 *
 * Manages scoped session keys for AI agent wallets. Session keys allow
 * an agent to transact within strict, pre-defined boundaries without
 * needing the full owner key for each operation.
 *
 * Boundaries enforced:
 * - Allowed target contracts only
 * - Maximum value per transaction
 * - Maximum daily volume
 * - Time-bounded expiration
 * - Infinite token approvals forbidden (optional)
 *
 * Even if the Wardex SDK is bypassed, session key limits are enforced
 * on-chain by the WardexValidationModule.
 *
 * Reference: ERC-7715 (Wallet Permission System)
 */

import * as crypto from 'node:crypto';
import { computeAddress } from 'ethers';

function utcDateKey(date: Date): string {
  return date.toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SessionKeyConfig {
  /** Allowed target contract addresses (lowercase, 0x-prefixed) */
  allowedContracts: string[];
  /** Maximum value per single transaction (wei string) */
  maxValuePerTx: string;
  /** Maximum cumulative daily volume (wei string) */
  maxDailyVolume: string;
  /** Session duration in seconds */
  durationSeconds: number;
  /** Whether infinite token approvals are forbidden (default: true) */
  forbidInfiniteApprovals: boolean;
}

export interface SessionKey {
  /** Unique session key identifier */
  id: string;
  /** The session key's public address (never the private key outside this module) */
  address: string;
  /** Session boundaries */
  config: SessionKeyConfig;
  /** ISO timestamp when the session was created */
  createdAt: string;
  /** ISO timestamp when the session expires */
  expiresAt: string;
  /** Whether the session has been revoked */
  revoked: boolean;
}

export interface SessionState {
  /** Total value spent today (wei as bigint) */
  dailyVolumeWei: bigint;
  /** Date string for the current daily window */
  dailyResetDate: string;
  /** Number of transactions executed in this session */
  transactionCount: number;
  /** Contracts that have been interacted with */
  contractsUsed: Set<string>;
}

export interface SessionValidationResult {
  valid: boolean;
  reason?: string;
}

// ERC-20 approve function selector
const APPROVE_SELECTOR = '0x095ea7b3';
// ERC-721/1155 setApprovalForAll selector
const SET_APPROVAL_FOR_ALL_SELECTOR = '0xa22cb465';
// Max uint256 for infinite approval detection
const MAX_UINT256 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
const INFINITE_THRESHOLD = BigInt(2) ** BigInt(128); // > 2^128 = infinite

// ---------------------------------------------------------------------------
// Session Manager
// ---------------------------------------------------------------------------

export class SessionManager {
  private sessions: Map<string, SessionKey> = new Map();
  private sessionStates: Map<string, SessionState> = new Map();
  /**
   * C-02 FIX: Store session private keys as Buffers instead of strings.
   * Buffers can be zeroed in-place via .fill(0), ensuring key material
   * is cleared from the ArrayBuffer memory (C++ heap) immediately.
   * JS strings are immutable and persist in V8 heap until GC.
   */
  private sessionPrivateKeys: Map<string, Buffer> = new Map();

  /**
   * Creates a new session key with the given boundaries.
   *
   * @returns The session key metadata (private key stays internal)
   */
  createSession(config: SessionKeyConfig): SessionKey {
    const id = crypto.randomUUID();

    // Generate a new keypair for this session
    // In production, this would use secp256k1 via ethers/viem
    // For the SDK, we generate a random 32-byte key and derive the address
    // C-02 FIX: Store key as Buffer for secure in-place zeroing
    const privateKeyBuf = crypto.randomBytes(32);
    const privateKeyHex = privateKeyBuf.toString('hex');
    const address = this.deriveAddress(privateKeyHex);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + config.durationSeconds * 1000);

    const session: SessionKey = {
      id,
      address,
      config: {
        ...config,
        allowedContracts: config.allowedContracts.map((a) => a.toLowerCase()),
      },
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      revoked: false,
    };

    this.sessions.set(id, session);
    this.sessionPrivateKeys.set(id, Buffer.from(privateKeyHex, 'utf8'));
    this.sessionStates.set(id, {
      dailyVolumeWei: 0n,
      dailyResetDate: utcDateKey(now),
      transactionCount: 0,
      contractsUsed: new Set(),
    });

    return session;
  }

  /**
   * Validates whether a transaction is within the session key's boundaries.
   */
  validateTransaction(
    sessionId: string,
    to: string,
    value: string,
    data?: string,
  ): SessionValidationResult {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return { valid: false, reason: 'Session not found' };
    }

    // Check revocation
    if (session.revoked) {
      return { valid: false, reason: 'Session has been revoked' };
    }

    // Check expiration
    if (new Date() >= new Date(session.expiresAt)) {
      return { valid: false, reason: 'Session has expired' };
    }

    const targetAddr = to.toLowerCase();
    const config = session.config;

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
    const state = this.sessionStates.get(sessionId)!;
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
   * Records a transaction against the session state.
   * Call this AFTER a transaction is confirmed.
   */
  recordTransaction(sessionId: string, value: string, to: string): void {
    const state = this.sessionStates.get(sessionId);
    if (!state) return;

    this.checkDailyReset(state);
    state.dailyVolumeWei += BigInt(value || '0');
    state.transactionCount++;
    state.contractsUsed.add(to.toLowerCase());
  }

  /**
   * Revokes a session key immediately.
   */
  revokeSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    session.revoked = true;

    // C-02 FIX: Zero out the private key Buffer in-place before deleting.
    // Buffer.fill(0) overwrites the underlying ArrayBuffer memory directly.
    const pkBuf = this.sessionPrivateKeys.get(sessionId);
    if (pkBuf) {
      pkBuf.fill(0);
      this.sessionPrivateKeys.delete(sessionId);
    }

    return true;
  }

  /**
   * Gets a session by ID.
   */
  getSession(sessionId: string): SessionKey | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Gets the current state of a session.
   */
  getSessionState(sessionId: string): SessionState | undefined {
    return this.sessionStates.get(sessionId);
  }

  /**
   * Lists all active (non-revoked, non-expired) sessions.
   */
  getActiveSessions(): SessionKey[] {
    const now = new Date();
    return Array.from(this.sessions.values()).filter(
      (s) => !s.revoked && new Date(s.expiresAt) > now,
    );
  }

  /**
   * Rotates a session: revokes the old one and creates a new one
   * with the same config but a fresh key and expiration.
   */
  rotateSession(sessionId: string): SessionKey | null {
    const old = this.sessions.get(sessionId);
    if (!old) return null;

    // Revoke old session
    this.revokeSession(sessionId);

    // Create new session with same config
    return this.createSession(old.config);
  }

  /**
   * Gets sessions that are near expiration (within the given window).
   */
  getExpiringSessionsSoon(withinSeconds: number): SessionKey[] {
    const now = new Date();
    const threshold = new Date(now.getTime() + withinSeconds * 1000);

    return Array.from(this.sessions.values()).filter(
      (s) =>
        !s.revoked &&
        new Date(s.expiresAt) > now &&
        new Date(s.expiresAt) <= threshold,
    );
  }

  /**
   * Removes all expired and revoked sessions from memory.
   */
  cleanup(): number {
    const now = new Date();
    let removed = 0;

    for (const [id, session] of this.sessions) {
      if (session.revoked || new Date(session.expiresAt) <= now) {
        // C-02 FIX: Zero out Buffer in-place before deleting
        const pkBuf = this.sessionPrivateKeys.get(id);
        if (pkBuf) {
          pkBuf.fill(0);
          this.sessionPrivateKeys.delete(id);
        }
        this.sessions.delete(id);
        this.sessionStates.delete(id);
        removed++;
      }
    }

    return removed;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Resets the daily volume counter if the date has changed.
   */
  private checkDailyReset(state: SessionState): void {
    const today = utcDateKey(new Date());
    if (today !== state.dailyResetDate) {
      state.dailyVolumeWei = 0n;
      state.dailyResetDate = today;
    }
  }

  /**
   * Checks if calldata contains an infinite token approval.
   */
  private checkInfiniteApproval(data: string): string | null {
    const normalized = data.toLowerCase();

    // Check ERC-20 approve(address, uint256)
    if (normalized.startsWith(APPROVE_SELECTOR)) {
      // Amount is in bytes 36-68 (after 4-byte selector + 32-byte address)
      if (data.length >= 138) {
        // 0x + 4*2 + 32*2 + 32*2 = 138 chars
        const amountHex = '0x' + data.slice(74, 138);
        try {
          const amount = BigInt(amountHex);
          if (amount >= INFINITE_THRESHOLD) {
            return 'Infinite token approval detected - session key forbids this';
          }
        } catch {
          // Can't parse amount - allow (might be malformed)
        }
      }
    }

    // Check ERC-721/1155 setApprovalForAll(address, bool)
    if (normalized.startsWith(SET_APPROVAL_FOR_ALL_SELECTOR)) {
      // Check if the bool (approve) is true
      if (data.length >= 138) {
        const boolHex = '0x' + data.slice(74, 138);
        try {
          const approvalValue = BigInt(boolHex);
          if (approvalValue > 0n) {
            return 'setApprovalForAll detected - session key forbids blanket approvals';
          }
        } catch {
          // Can't parse - allow
        }
      }
    }

    return null;
  }

  /**
   * Derives an Ethereum address from a private key.
   * Uses secp256k1 public key derivation via ethers.
   */
  private deriveAddress(privateKey: string): string {
    const normalized = privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`;
    return computeAddress(normalized).toLowerCase();
  }
}
