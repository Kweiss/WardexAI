/**
 * IsolatedProcessSigner
 *
 * A signer that runs in a separate OS process, communicating over Unix socket.
 * The AI agent process NEVER has access to private key material.
 *
 * Architecture:
 * - The signer process holds the encrypted private key
 * - The agent process sends transaction requests + Wardex approval tokens
 * - The signer verifies the approval token before signing
 * - Only the signed transaction is returned (never the key)
 *
 * This module provides:
 * 1. SignerServer - runs in the isolated process (holds keys)
 * 2. SignerClient - used by the agent process (no key access)
 */

import * as net from 'node:net';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

// ---------------------------------------------------------------------------
// Protocol Messages
// ---------------------------------------------------------------------------

interface SignRequest {
  type: 'sign_transaction';
  transactionHash: string;
  serializedTx: string;
  approvalToken: string;
}

interface SignMessageRequest {
  type: 'sign_message';
  message: string;
  approvalToken: string;
}

interface GetAddressRequest {
  type: 'get_address';
}

interface HealthCheckRequest {
  type: 'health_check';
}

interface AuthResponseRequest {
  type: 'auth_response';
  hmac: string;
}

type SignerRequest =
  | SignRequest
  | SignMessageRequest
  | GetAddressRequest
  | HealthCheckRequest
  | AuthResponseRequest;

interface AuthChallengeMessage {
  type: 'auth_challenge';
  nonce: string;
}

interface SignerResponse {
  success: boolean;
  data?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Approval Token Management
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographic approval token that proves Wardex evaluated
 * and approved a specific transaction.
 *
 * The token is an HMAC of the transaction hash, using a shared secret
 * between the Wardex SDK and the signer process.
 */
export function generateApprovalToken(
  transactionHash: string,
  sharedSecret: string,
  timestamp?: number
): string {
  const ts = timestamp ?? Date.now();
  const hmac = crypto.createHmac('sha256', sharedSecret);
  hmac.update(transactionHash);
  hmac.update(ts.toString());
  // Token format: hex(HMAC) + '.' + hex(timestamp)
  const mac = hmac.digest('hex');
  const tsHex = ts.toString(16).padStart(16, '0');
  return mac + tsHex;
}

/** Maximum age of an approval token before it's considered expired (5 minutes). */
const APPROVAL_TOKEN_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * Verifies an approval token against a transaction hash.
 * Uses HMAC-SHA256 with timing-safe comparison to prevent timing attacks.
 * Tokens expire after 5 minutes to prevent replay.
 */
export function verifyApprovalToken(
  token: string,
  transactionHash: string,
  sharedSecret: string,
  nowMs?: number
): boolean {
  // Token format: 64 hex chars (HMAC) + 16 hex chars (timestamp) = 80 chars
  if (!/^[0-9a-f]{80}$/i.test(token)) return false;

  const receivedMac = token.slice(0, 64);
  const tsHex = token.slice(64);
  const timestamp = parseInt(tsHex, 16);

  // Check token age (reject expired tokens)
  const now = nowMs ?? Date.now();
  const age = now - timestamp;
  if (age > APPROVAL_TOKEN_MAX_AGE_MS || age < 0) return false;

  // Recompute the expected HMAC
  const hmac = crypto.createHmac('sha256', sharedSecret);
  hmac.update(transactionHash);
  hmac.update(timestamp.toString());
  const expectedMac = hmac.digest('hex');

  // Timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(receivedMac, 'hex'),
      Buffer.from(expectedMac, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * Verifies and consumes an approval token for one-time use.
 * Prevents replay by tracking tokens within their validity window.
 */
export function verifyAndConsumeApprovalToken(
  token: string,
  transactionHash: string,
  sharedSecret: string,
  usedTokens: Map<string, number>,
  nowMs?: number
): boolean {
  const now = nowMs ?? Date.now();

  // Remove expired entries from the replay cache.
  for (const [usedToken, consumedAt] of usedTokens.entries()) {
    if (now - consumedAt > APPROVAL_TOKEN_MAX_AGE_MS) {
      usedTokens.delete(usedToken);
    }
  }

  // Single-use enforcement.
  if (usedTokens.has(token)) {
    return false;
  }

  if (!verifyApprovalToken(token, transactionHash, sharedSecret, now)) {
    return false;
  }

  usedTokens.set(token, now);
  return true;
}

/**
 * Creates a connection-auth proof for signer IPC handshake.
 * HMAC(sharedSecret, nonce) binds the client to possession of the secret.
 */
export function generateConnectionAuthProof(
  nonce: string,
  sharedSecret: string
): string {
  const hmac = crypto.createHmac('sha256', sharedSecret);
  hmac.update('wardex-ipc-auth-v1:');
  hmac.update(nonce);
  return hmac.digest('hex');
}

/**
 * Verifies a connection-auth proof with timing-safe compare.
 */
export function verifyConnectionAuthProof(
  nonce: string,
  sharedSecret: string,
  proof: string
): boolean {
  if (!/^[0-9a-f]{64}$/i.test(proof)) return false;
  const expected = generateConnectionAuthProof(nonce, sharedSecret);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(proof, 'hex')
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Encrypted Key Storage
// ---------------------------------------------------------------------------

interface EncryptedKeyFile {
  version: 1;
  algorithm: 'aes-256-gcm';
  iv: string;
  authTag: string;
  encryptedKey: string;
  salt: string;
}

/**
 * Encrypts a private key for storage at rest.
 */
export function encryptPrivateKey(
  privateKey: string,
  password: string
): EncryptedKeyFile {
  const salt = crypto.randomBytes(32);
  const key = crypto.scryptSync(password, salt, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    version: 1,
    algorithm: 'aes-256-gcm',
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    encryptedKey: encrypted,
    salt: salt.toString('hex'),
  };
}

/**
 * Decrypts a private key from storage.
 */
export function decryptPrivateKey(
  keyFile: EncryptedKeyFile,
  password: string
): string {
  const salt = Buffer.from(keyFile.salt, 'hex');
  const key = crypto.scryptSync(password, salt, 32);
  const iv = Buffer.from(keyFile.iv, 'hex');
  const authTag = Buffer.from(keyFile.authTag, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(keyFile.encryptedKey, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

// ---------------------------------------------------------------------------
// Signer Server (runs in isolated process)
// ---------------------------------------------------------------------------

export interface SignerServerConfig {
  /** Unix socket path */
  socketPath: string;
  /** Encrypted key file path */
  keyFilePath: string;
  /** Password for key decryption (should come from env var) */
  keyPassword: string;
  /** Shared secret for approval token verification */
  sharedSecret: string;
  /** Require challenge-response auth for every socket connection (default: true) */
  requireClientAuth?: boolean;
  /** Max simultaneous client connections (default: 100) */
  maxConnections?: number;
  /** Max new connections per second (default: 200) */
  connectionRateLimitPerSecond?: number;
  /** Sign function - pluggable to support different key types */
  signFn: (data: string, privateKey: string) => Promise<string>;
  /** Get address function */
  getAddressFn: (privateKey: string) => string;
}

export class SignerServer {
  private server: net.Server | null = null;
  /**
   * C-02 FIX: Store private key in a Buffer instead of a string.
   * Buffers are backed by ArrayBuffer (C++ heap) and can be zeroed in-place.
   * JS strings are immutable — assigning '0'.repeat(n) creates a new string
   * while the original persists in the V8 heap until GC, leaking key material.
   */
  private privateKeyBuf: Buffer = Buffer.alloc(0);
  private usedApprovalTokens: Map<string, number> = new Map();
  private activeConnections = 0;
  private connectionWindowEpochSecond = 0;
  private connectionWindowCount = 0;
  private config: SignerServerConfig;

  constructor(config: SignerServerConfig) {
    this.config = config;
  }

  /**
   * Starts the signer server, loading the encrypted key.
   */
  async start(): Promise<void> {
    // Load and decrypt private key into Buffer for secure zeroing
    const keyFileContent = fs.readFileSync(this.config.keyFilePath, 'utf8');
    const keyFile: EncryptedKeyFile = JSON.parse(keyFileContent);
    const decryptedKey = decryptPrivateKey(keyFile, this.config.keyPassword);
    this.privateKeyBuf = Buffer.from(decryptedKey, 'utf8');

    // Remove existing socket file if it exists
    if (fs.existsSync(this.config.socketPath)) {
      fs.unlinkSync(this.config.socketPath);
    }

    // Start Unix socket server
    this.server = net.createServer((connection) => {
      const maxConnections = this.config.maxConnections ?? 100;
      const rateLimitPerSecond = this.config.connectionRateLimitPerSecond ?? 200;

      if (this.activeConnections >= maxConnections || this.isConnectionRateLimited(rateLimitPerSecond)) {
        const errorResponse: SignerResponse = {
          success: false,
          error: 'Connection limit exceeded',
        };
        connection.write(JSON.stringify(errorResponse) + '\n');
        connection.destroy();
        return;
      }

      this.activeConnections++;
      connection.on('close', () => {
        this.activeConnections = Math.max(0, this.activeConnections - 1);
      });

      this.handleConnection(connection);
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(this.config.socketPath, () => {
        // Set restrictive permissions on the socket
        fs.chmodSync(this.config.socketPath, 0o600);
        resolve();
      });
      this.server!.on('error', reject);
    });
  }

  /**
   * Stops the signer server and zeroes out key material.
   */
  async stop(): Promise<void> {
    // C-02 FIX: Zero out the private key Buffer in-place.
    // Buffer.fill(0) overwrites the underlying ArrayBuffer memory directly,
    // unlike string reassignment which leaves the original in V8 heap.
    this.privateKeyBuf.fill(0);
    this.privateKeyBuf = Buffer.alloc(0);
    this.usedApprovalTokens.clear();

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          // Clean up socket file
          if (fs.existsSync(this.config.socketPath)) {
            fs.unlinkSync(this.config.socketPath);
          }
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private handleConnection(connection: net.Socket): void {
    let buffer = '';
    const requireClientAuth = this.config.requireClientAuth ?? true;
    let authenticated = !requireClientAuth;
    const nonce = crypto.randomBytes(16).toString('hex');

    if (requireClientAuth) {
      const challenge: AuthChallengeMessage = { type: 'auth_challenge', nonce };
      connection.write(JSON.stringify(challenge) + '\n');
    }

    connection.on('data', async (data) => {
      buffer += data.toString();

      // Try to parse complete JSON messages (newline-delimited)
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const request = JSON.parse(line) as SignerRequest;

          if (!authenticated) {
            if (
              request.type !== 'auth_response' ||
              !verifyConnectionAuthProof(nonce, this.config.sharedSecret, request.hmac)
            ) {
              const errorResponse: SignerResponse = {
                success: false,
                error: 'Authentication failed',
              };
              connection.write(JSON.stringify(errorResponse) + '\n');
              connection.destroy();
              return;
            }

            authenticated = true;
            const authOkResponse: SignerResponse = {
              success: true,
              data: 'authenticated',
            };
            connection.write(JSON.stringify(authOkResponse) + '\n');
            continue;
          }

          const response = await this.handleRequest(request);
          connection.write(JSON.stringify(response) + '\n');
        } catch (err) {
          const errorResponse: SignerResponse = {
            success: false,
            error: err instanceof Error ? err.message : 'Unknown error',
          };
          connection.write(JSON.stringify(errorResponse) + '\n');
        }
      }
    });
  }

  private isConnectionRateLimited(rateLimitPerSecond: number): boolean {
    if (rateLimitPerSecond <= 0) return false;
    const nowSecond = Math.floor(Date.now() / 1000);
    if (nowSecond !== this.connectionWindowEpochSecond) {
      this.connectionWindowEpochSecond = nowSecond;
      this.connectionWindowCount = 0;
    }
    this.connectionWindowCount++;
    return this.connectionWindowCount > rateLimitPerSecond;
  }

  private async handleRequest(request: SignerRequest): Promise<SignerResponse> {
    switch (request.type) {
      case 'health_check':
        return { success: true, data: 'healthy' };

      case 'get_address':
        return {
          success: true,
          data: this.config.getAddressFn(this.privateKeyBuf.toString('utf8')),
        };

      case 'sign_transaction': {
        // Verify the Wardex approval token
        if (
          !verifyAndConsumeApprovalToken(
            request.approvalToken,
            request.transactionHash,
            this.config.sharedSecret,
            this.usedApprovalTokens
          )
        ) {
          return {
            success: false,
            error: 'Invalid or replayed approval token - transaction was not approved by Wardex',
          };
        }

        try {
          const signature = await this.config.signFn(
            request.serializedTx,
            this.privateKeyBuf.toString('utf8')
          );
          return { success: true, data: signature };
        } catch (err) {
          return {
            success: false,
            error: err instanceof Error ? err.message : 'Signing failed',
          };
        }
      }

      case 'sign_message': {
        if (
          !verifyAndConsumeApprovalToken(
            request.approvalToken,
            request.message,
            this.config.sharedSecret,
            this.usedApprovalTokens
          )
        ) {
          return {
            success: false,
            error: 'Invalid or replayed approval token - message signing was not approved by Wardex',
          };
        }

        try {
          const signature = await this.config.signFn(
            request.message,
            this.privateKeyBuf.toString('utf8')
          );
          return { success: true, data: signature };
        } catch (err) {
          return {
            success: false,
            error: err instanceof Error ? err.message : 'Signing failed',
          };
        }
      }

      default:
        return { success: false, error: 'Unknown request type' };
    }
  }
}

// ---------------------------------------------------------------------------
// Signer Client (used by agent process - NO key access)
// ---------------------------------------------------------------------------

export interface SignerClientConfig {
  /** Unix socket path to connect to */
  socketPath: string;
  /** Shared secret used for connection challenge-response auth */
  sharedSecret?: string;
  /** Timeout for requests in ms */
  timeout?: number;
}

export class SignerClient {
  private config: SignerClientConfig;

  constructor(config: SignerClientConfig) {
    this.config = config;
  }

  /**
   * Sends a request to the isolated signer and waits for a response.
   */
  private async sendRequest(request: SignerRequest): Promise<SignerResponse> {
    const timeout = this.config.timeout ?? 10_000;

    return new Promise((resolve, reject) => {
      const client = net.createConnection(this.config.socketPath);
      let buffer = '';
      let resolved = false;
      let authenticated = false;
      let requestSent = false;
      let gotAuthChallenge = false;

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          client.destroy();
          reject(new Error('Signer request timed out'));
        }
      }, timeout);

      client.on('connect', () => {
        // Backward-compatibility fallback: old signer servers may not
        // emit an auth challenge. If no challenge is seen quickly, send
        // the request directly.
        setTimeout(() => {
          if (!resolved && !requestSent && !gotAuthChallenge) {
            requestSent = true;
            authenticated = true;
            client.write(JSON.stringify(request) + '\n');
          }
        }, 50);
      });

      client.on('data', (data) => {
        buffer += data.toString();
        const lines = buffer.split('\n');

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const message = JSON.parse(line) as SignerResponse | AuthChallengeMessage;

            if (
              typeof message === 'object' &&
              message !== null &&
              'type' in message &&
              message.type === 'auth_challenge'
            ) {
              gotAuthChallenge = true;
              if (!this.config.sharedSecret) {
                if (!resolved) {
                  resolved = true;
                  clearTimeout(timer);
                  client.destroy();
                  reject(new Error('Signer auth challenge received but sharedSecret is not configured'));
                }
                return;
              }

              const proof = generateConnectionAuthProof(
                message.nonce,
                this.config.sharedSecret
              );
              const authRequest: AuthResponseRequest = {
                type: 'auth_response',
                hmac: proof,
              };
              client.write(JSON.stringify(authRequest) + '\n');
              continue;
            }

            const response = message as SignerResponse;

            if (!authenticated && response.success && response.data === 'authenticated') {
              authenticated = true;
              if (!requestSent) {
                requestSent = true;
                client.write(JSON.stringify(request) + '\n');
              }
              continue;
            }

            if (!resolved) {
              resolved = true;
              clearTimeout(timer);
              client.destroy();
              resolve(response);
            }
          } catch {
            // Incomplete JSON, wait for more data
          }
        }
      });

      client.on('error', (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          reject(err);
        }
      });
    });
  }

  async signTransaction(
    serializedTx: string,
    transactionHash: string,
    approvalToken: string
  ): Promise<string> {
    const response = await this.sendRequest({
      type: 'sign_transaction',
      serializedTx,
      transactionHash,
      approvalToken,
    });

    if (!response.success || !response.data) {
      throw new Error(response.error ?? 'Signing failed');
    }

    return response.data;
  }

  async signMessage(
    message: string,
    approvalToken: string
  ): Promise<string> {
    const response = await this.sendRequest({
      type: 'sign_message',
      message,
      approvalToken,
    });

    if (!response.success || !response.data) {
      throw new Error(response.error ?? 'Message signing failed');
    }

    return response.data;
  }

  async getAddress(): Promise<string> {
    const response = await this.sendRequest({ type: 'get_address' });

    if (!response.success || !response.data) {
      throw new Error(response.error ?? 'Failed to get address');
    }

    return response.data;
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.sendRequest({ type: 'health_check' });
      return response.success;
    } catch {
      return false;
    }
  }
}
