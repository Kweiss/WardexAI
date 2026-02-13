/**
 * Test Scenario: Isolated Signer
 *
 * Verifies the signer's key isolation, approval token verification,
 * and encrypted key storage.
 */

import { describe, it, expect } from 'vitest';
import {
  generateApprovalToken,
  verifyApprovalToken,
  encryptPrivateKey,
  decryptPrivateKey,
} from '@wardexai/signer';

describe('Approval Token Management', () => {
  const SHARED_SECRET = 'test-shared-secret-for-wardex-unit-tests';
  const TX_HASH = '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';

  it('should generate and verify a valid approval token', () => {
    const timestamp = Date.now();
    const token = generateApprovalToken(TX_HASH, SHARED_SECRET, timestamp);

    expect(token).toHaveLength(80); // 64 hex (HMAC) + 16 hex (timestamp)
    expect(verifyApprovalToken(token, TX_HASH, SHARED_SECRET)).toBe(true);
  });

  it('should reject tokens with wrong transaction hash', () => {
    const token = generateApprovalToken(TX_HASH, SHARED_SECRET);
    const wrongHash = '0x0000000000000000000000000000000000000000000000000000000000000000';

    expect(verifyApprovalToken(token, wrongHash, SHARED_SECRET)).toBe(false);
  });

  it('should reject tokens with wrong shared secret', () => {
    const token = generateApprovalToken(TX_HASH, SHARED_SECRET);

    expect(verifyApprovalToken(token, TX_HASH, 'wrong-secret')).toBe(false);
  });

  it('should reject expired tokens (older than 5 minutes)', () => {
    // Generate token with a timestamp 6 minutes in the past
    const oldTimestamp = Date.now() - 6 * 60 * 1000;
    const token = generateApprovalToken(TX_HASH, SHARED_SECRET, oldTimestamp);

    expect(verifyApprovalToken(token, TX_HASH, SHARED_SECRET)).toBe(false);
  });

  it('should reject tokens with future timestamps', () => {
    const futureTimestamp = Date.now() + 60 * 1000;
    const token = generateApprovalToken(TX_HASH, SHARED_SECRET, futureTimestamp);

    // Future timestamps should be rejected (age < 0)
    expect(verifyApprovalToken(token, TX_HASH, SHARED_SECRET)).toBe(false);
  });

  it('should reject malformed tokens', () => {
    expect(verifyApprovalToken('', TX_HASH, SHARED_SECRET)).toBe(false);
    expect(verifyApprovalToken('short', TX_HASH, SHARED_SECRET)).toBe(false);
    expect(verifyApprovalToken('x'.repeat(80), TX_HASH, SHARED_SECRET)).toBe(false);
    expect(verifyApprovalToken('0'.repeat(64), TX_HASH, SHARED_SECRET)).toBe(false); // too short
  });

  it('should generate different tokens for different transactions', () => {
    const ts = Date.now();
    const token1 = generateApprovalToken(TX_HASH, SHARED_SECRET, ts);
    const token2 = generateApprovalToken(
      '0x1111111111111111111111111111111111111111111111111111111111111111',
      SHARED_SECRET,
      ts
    );

    expect(token1).not.toBe(token2);
  });

  it('should reject replayed tokens after first successful consumption', async () => {
    const { verifyAndConsumeApprovalToken } = await import(
      '@wardexai/signer/dist/isolated-process.js'
    );
    const usedTokens = new Map<string, number>();
    const timestamp = Date.now();
    const token = generateApprovalToken(TX_HASH, SHARED_SECRET, timestamp);

    expect(
      verifyAndConsumeApprovalToken(token, TX_HASH, SHARED_SECRET, usedTokens, timestamp + 1000)
    ).toBe(true);

    // Same token reused within validity window must be rejected.
    expect(
      verifyAndConsumeApprovalToken(token, TX_HASH, SHARED_SECRET, usedTokens, timestamp + 2000)
    ).toBe(false);
  });
});

describe('Encrypted Key Storage', () => {
  const TEST_PRIVATE_KEY = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
  const PASSWORD = 'secure-test-password-for-wardex';

  it('should encrypt and decrypt a private key correctly', () => {
    const encrypted = encryptPrivateKey(TEST_PRIVATE_KEY, PASSWORD);

    expect(encrypted.version).toBe(1);
    expect(encrypted.algorithm).toBe('aes-256-gcm');
    expect(encrypted.iv).toHaveLength(32); // 16 bytes = 32 hex chars
    expect(encrypted.salt).toHaveLength(64); // 32 bytes = 64 hex chars

    const decrypted = decryptPrivateKey(encrypted, PASSWORD);
    expect(decrypted).toBe(TEST_PRIVATE_KEY);
  });

  it('should fail decryption with wrong password', () => {
    const encrypted = encryptPrivateKey(TEST_PRIVATE_KEY, PASSWORD);

    expect(() => {
      decryptPrivateKey(encrypted, 'wrong-password');
    }).toThrow();
  });

  it('should produce different ciphertexts for the same key (random IV and salt)', () => {
    const encrypted1 = encryptPrivateKey(TEST_PRIVATE_KEY, PASSWORD);
    const encrypted2 = encryptPrivateKey(TEST_PRIVATE_KEY, PASSWORD);

    expect(encrypted1.encryptedKey).not.toBe(encrypted2.encryptedKey);
    expect(encrypted1.iv).not.toBe(encrypted2.iv);
    expect(encrypted1.salt).not.toBe(encrypted2.salt);
  });
});

describe('Connection Auth Proof', () => {
  const SHARED_SECRET = 'test-shared-secret-for-wardex-unit-tests';

  it('should generate and verify a valid connection auth proof', async () => {
    const { generateConnectionAuthProof, verifyConnectionAuthProof } = await import(
      '@wardexai/signer/dist/isolated-process.js'
    );
    const nonce = 'abcd1234deadbeefabcd1234deadbeef';
    const proof = generateConnectionAuthProof(nonce, SHARED_SECRET);

    expect(proof).toHaveLength(64);
    expect(verifyConnectionAuthProof(nonce, SHARED_SECRET, proof)).toBe(true);
  });

  it('should reject invalid connection auth proof', async () => {
    const { generateConnectionAuthProof, verifyConnectionAuthProof } = await import(
      '@wardexai/signer/dist/isolated-process.js'
    );
    const nonce = 'abcd1234deadbeefabcd1234deadbeef';
    const proof = generateConnectionAuthProof(nonce, SHARED_SECRET);

    expect(verifyConnectionAuthProof(nonce, 'wrong-secret', proof)).toBe(false);
    expect(verifyConnectionAuthProof(nonce, SHARED_SECRET, '0'.repeat(64))).toBe(false);
  });
});
