// RFC 6238 time-based one-time passwords (6 digits, 30-second steps, HMAC-SHA1): the second factor
// of password sign-in. Compatible with Google Authenticator, Microsoft Authenticator, 1Password, etc.
import crypto from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_MS = 30_000;
const DIGITS = 6;

export const TOTP_CODE_PATTERN = /^\d{6}$/;

export function base32Encode(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(text: string): Buffer {
  const clean = text.replace(/[\s=-]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error('The TOTP secret is not valid base32.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** A new random 160-bit secret, base32 encoded (what authenticator apps expect). */
export function generateTotpSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

/** The 30-second step a time falls in. */
export function totpStep(nowMs: number = Date.now()): number {
  return Math.floor(nowMs / STEP_MS);
}

/** The code for one step. */
export function totpCode(secretBase32: string, step: number): string {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(step));
  const hmac = crypto.createHmac('sha1', base32Decode(secretBase32)).update(message).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary = hmac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * The step `code` is valid for (the current one, or one either side for clock drift), or null. A step
 * at or before `lastUsedStep` is refused, so a code that already signed someone in cannot be replayed:
 * the caller stores the returned step as the new lastUsedStep.
 */
export function verifyTotp(
  secretBase32: string,
  code: unknown,
  lastUsedStep: number,
  nowMs: number = Date.now()
): number | null {
  if (typeof code !== 'string') return null;
  const candidate = code.replace(/\s/g, '');
  if (!TOTP_CODE_PATTERN.test(candidate)) return null;
  const current = totpStep(nowMs);
  let matched: number | null = null;
  // Every candidate step is compared, in constant time, so timing does not say which one matched.
  for (const step of [current - 1, current, current + 1]) {
    const expected = Buffer.from(totpCode(secretBase32, step));
    if (crypto.timingSafeEqual(expected, Buffer.from(candidate)) && step > lastUsedStep && matched === null) {
      matched = step;
    }
  }
  return matched;
}

/** The otpauth:// URI authenticator apps import (as a QR code or pasted). */
export function totpProvisioningUri(secretBase32: string, accountName: string, issuer = 'Salesforce MCP Admin'): string {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const params = new URLSearchParams({ secret: secretBase32, issuer, algorithm: 'SHA1', digits: String(DIGITS), period: '30' });
  return `otpauth://totp/${label}?${params.toString()}`;
}
