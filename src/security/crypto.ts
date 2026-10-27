import crypto from 'node:crypto';
import { config } from '../config.js';

const KEY_BUFFER = Buffer.from(config.appSecretKey, 'hex');

/**
 * Encrypts sensitive strings (e.g. Okta client secrets, Salesforce sync tokens)
 * using AES-256-GCM with an authenticated tag and random 96-bit IV.
 */
export function encryptSecret(plaintext: string): string {
  if (!plaintext) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY_BUFFER, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypts AES-256-GCM ciphertext produced by encryptSecret.
 */
export function decryptSecret(ciphertext: string): string {
  if (!ciphertext) return '';
  const parts = ciphertext.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted secret format');
  }
  const [ivHex, tagHex, encHex] = parts;
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    KEY_BUFFER,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encHex, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

/**
 * Constant-time SHA-256 hash comparison to prevent timing side-channel attacks.
 */
export function timingSafeStringEqual(a: string, b: string): boolean {
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

/**
 * Computes a short non-reversible fingerprint of a bearer token for in-memory caching
 * so raw tokens are never used as cache keys or logged.
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * PKCE Helpers (RFC 7636) for OAuth 2.0 / OIDC flows
 */
export function generatePkcePair(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function generateStateToken(): string {
  return crypto.randomBytes(24).toString('base64url');
}
