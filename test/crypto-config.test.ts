import './helpers/env.js';
// Covers src/security/crypto.ts (AES-256-GCM secrets at rest, token helpers, PKCE) and
// src/config.ts (secret-key / bootstrap-admin resolution, buildConfig parsing), plus the real
// production fail-fast behaviour of `src/index.ts` in child processes.
import { describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { testTmpDir } from './helpers/env.js';
import {
  encryptSecret,
  decryptSecret,
  timingSafeStringEqual,
  hashToken,
  generatePkcePair,
  generateStateToken,
} from '../src/security/crypto.js';
import {
  config,
  buildConfig,
  resolveAppSecretKey,
  resolveBootstrapAdmin,
  DEV_FALLBACK_SECRET_KEY,
  DEFAULT_BOOTSTRAP_ADMIN,
} from '../src/config.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EXAMPLE_SECRET_KEY = '0123456789abcdef'.repeat(4);

const randomKey = () => crypto.randomBytes(32).toString('hex');

/** Flips the lowest bit of one hex digit, so exactly one byte of the decoded buffer changes. */
function flipHexDigit(hex: string, index: number): string {
  const flipped = (parseInt(hex[index], 16) ^ 0x1).toString(16);
  return hex.slice(0, index) + flipped + hex.slice(index + 1);
}

/** Independent base64url(sha256(ascii)) so the PKCE check does not reuse the implementation's call. */
function s256(verifier: string): string {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(verifier, 'ascii'))
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function splitSecret(encrypted: string): { iv: string; tag: string; ct: string } {
  const [iv, tag, ct] = encrypted.split(':');
  return { iv, tag, ct };
}

describe('crypto: encryptSecret / decryptSecret (AES-256-GCM)', () => {
  test('round-trips unicode strings', () => {
    const samples = [
      'pässwörd-Ünïcødé',
      '日本語のシークレット',
      'emoji 🔐🧪 and a ZWJ sequence 👩‍💻',
      'RTL مرحبا بالعالم and Hebrew שלום',
      'combining é vs precomposed é',
      'control chars \u0000 \t \n \r end',
      'astral plane 𝔘𝔫𝔦𝔠𝔬𝔡𝔢 𠜎',
      'colons:in:the:secret:value',
    ];
    for (const plaintext of samples) {
      assert.equal(decryptSecret(encryptSecret(plaintext)), plaintext);
    }
  });

  test('round-trips long strings', () => {
    const long = Array.from({ length: 20_000 }, (_, i) => `${i}:Ünïcødé ✓ 日本語 🔐|`).join('');
    assert.ok(long.length > 300_000);
    const encrypted = encryptSecret(long);
    assert.equal(splitSecret(encrypted).ct.length, Buffer.byteLength(long, 'utf8') * 2);
    assert.equal(decryptSecret(encrypted), long);

    const ascii = 'x'.repeat(1_000_000);
    assert.equal(decryptSecret(encryptSecret(ascii)), ascii);
  });

  test('produces lowercase-hex iv:tag:ciphertext with a 96-bit IV and a 128-bit tag', () => {
    const plaintext = 'shape-check-secret';
    const encrypted = encryptSecret(plaintext);
    assert.match(encrypted, /^[0-9a-f]{24}:[0-9a-f]{32}:[0-9a-f]+$/);
    assert.equal(splitSecret(encrypted).ct.length, Buffer.byteLength(plaintext, 'utf8') * 2);
  });

  test('two encryptions of the same plaintext differ because each uses a fresh random IV', () => {
    const plaintext = 'same plaintext every time';
    const first = encryptSecret(plaintext);
    const second = encryptSecret(plaintext);
    assert.notEqual(first, second);
    assert.notEqual(splitSecret(first).iv, splitSecret(second).iv);
    assert.equal(decryptSecret(first), plaintext);
    assert.equal(decryptSecret(second), plaintext);

    const ivs = new Set(Array.from({ length: 200 }, () => splitSecret(encryptSecret(plaintext)).iv));
    assert.equal(ivs.size, 200, 'IVs must never repeat under the same key');
  });

  test('output is standard AES-256-GCM under config.appSecretKey (interoperable both ways)', () => {
    const key = Buffer.from(config.appSecretKey, 'hex');
    assert.equal(key.length, 32);
    const plaintext = 'okta-client-secret-🔑';

    const { iv, tag, ct } = splitSecret(encryptSecret(plaintext));
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'), { authTagLength: 16 });
    decipher.setAuthTag(Buffer.from(tag, 'hex'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(ct, 'hex')), decipher.final()]).toString('utf8');
    assert.equal(decrypted, plaintext);

    const ownIv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, ownIv);
    const ownCt = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const external = `${ownIv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${ownCt.toString('hex')}`;
    assert.equal(decryptSecret(external), plaintext);
  });

  test('tampering with the ciphertext makes decryptSecret throw (GCM authentication)', () => {
    const { iv, tag, ct } = splitSecret(encryptSecret('tamper-ciphertext'));
    assert.equal(decryptSecret(`${iv}:${tag}:${ct}`), 'tamper-ciphertext');
    for (const index of [0, ct.length - 1]) {
      assert.throws(() => decryptSecret(`${iv}:${tag}:${flipHexDigit(ct, index)}`), Error);
    }
    // Swapping in a ciphertext body from another encryption is also rejected.
    const other = splitSecret(encryptSecret('tamper-ciphertexT'));
    assert.throws(() => decryptSecret(`${iv}:${tag}:${other.ct}`), Error);
  });

  test('tampering with the authentication tag makes decryptSecret throw', () => {
    const { iv, tag, ct } = splitSecret(encryptSecret('tamper-tag'));
    assert.equal(decryptSecret(`${iv}:${tag}:${ct}`), 'tamper-tag');
    for (const index of [0, 15, tag.length - 1]) {
      assert.throws(() => decryptSecret(`${iv}:${flipHexDigit(tag, index)}:${ct}`), Error);
    }
  });

  test('a truncated authentication tag is rejected rather than verified against a shorter MAC', () => {
    const { iv, tag, ct } = splitSecret(encryptSecret('truncated-tag'));
    for (const bytes of [12, 8, 4]) {
      assert.throws(() => decryptSecret(`${iv}:${tag.slice(0, bytes * 2)}:${ct}`), Error);
    }
  });

  test('tampering with the IV makes decryptSecret throw', () => {
    const { iv, tag, ct } = splitSecret(encryptSecret('tamper-iv'));
    assert.equal(decryptSecret(`${iv}:${tag}:${ct}`), 'tamper-iv');
    for (const index of [0, iv.length - 1]) {
      assert.throws(() => decryptSecret(`${flipHexDigit(iv, index)}:${tag}:${ct}`), Error);
    }
    assert.throws(() => decryptSecret(`${crypto.randomBytes(12).toString('hex')}:${tag}:${ct}`), Error);
  });

  test('a value without exactly three colon-separated segments throws a format error', () => {
    const { iv, tag, ct } = splitSecret(encryptSecret('segments'));
    for (const malformed of ['not-encrypted', `${iv}:${tag}`, `${iv}${tag}${ct}`, `${iv}:${tag}:${ct}:${ct}`, `:${iv}:${tag}:${ct}`]) {
      assert.throws(() => decryptSecret(malformed), /Invalid encrypted secret format/, malformed);
    }
  });

  test('the empty string maps to the empty string in both directions', () => {
    assert.equal(encryptSecret(''), '');
    assert.equal(decryptSecret(''), '');
  });
});

describe('crypto: token and PKCE helpers', () => {
  test('timingSafeStringEqual returns true for identical strings', () => {
    assert.equal(timingSafeStringEqual('s3cr3t-value', 's3cr3t-value'), true);
    assert.equal(timingSafeStringEqual('', ''), true);
    assert.equal(timingSafeStringEqual('Ünïcødé 🔐', 'Ünïcødé 🔐'), true);
  });

  test('timingSafeStringEqual returns false for different strings of the same length', () => {
    assert.equal(timingSafeStringEqual('s3cr3t-value', 's3cr3t-valuf'), false);
    assert.equal(timingSafeStringEqual('abc', 'ABC'), false);
  });

  test('timingSafeStringEqual returns false (and does not throw) for strings of different lengths', () => {
    assert.equal(timingSafeStringEqual('abc', 'abcd'), false);
    assert.equal(timingSafeStringEqual('s3cr3t-value', 's3cr3t'), false);
    assert.equal(timingSafeStringEqual('', 'a'), false);
  });

  test('hashToken is a stable lowercase SHA-256 hex digest that never contains the token', () => {
    assert.equal(hashToken('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(hashToken(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    const token = `00D000000000001!${crypto.randomBytes(24).toString('base64url')}`;
    const digest = hashToken(token);
    assert.match(digest, /^[0-9a-f]{64}$/);
    assert.equal(hashToken(token), digest, 'same token, same hash');
    assert.notEqual(hashToken(`${token}x`), digest);
    assert.ok(!digest.includes(token));
  });

  test('generatePkcePair returns an S256 pair: codeChallenge === base64url(sha256(codeVerifier))', () => {
    // RFC 7636 Appendix B vector validates the independent helper first.
    assert.equal(s256('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');

    const { codeVerifier, codeChallenge } = generatePkcePair();
    assert.equal(codeChallenge, s256(codeVerifier));
    assert.match(codeVerifier, /^[A-Za-z0-9\-._~]{43,128}$/, 'RFC 7636 verifier charset and length');
    assert.match(codeChallenge, /^[A-Za-z0-9_-]{43}$/, 'unpadded base64url SHA-256');
  });

  test('generatePkcePair returns a fresh verifier on every call', () => {
    const verifiers = new Set(Array.from({ length: 200 }, () => generatePkcePair().codeVerifier));
    assert.equal(verifiers.size, 200);
  });

  test('generateStateToken returns unique, URL-safe tokens with at least 128 bits', () => {
    const tokens = Array.from({ length: 1000 }, () => generateStateToken());
    assert.equal(new Set(tokens).size, tokens.length);
    for (const token of tokens) {
      assert.match(token, /^[A-Za-z0-9_-]+$/);
      assert.ok(Buffer.from(token, 'base64url').length >= 16, `state token too short: ${token}`);
    }
  });
});

describe('config: resolveAppSecretKey', () => {
  test('production without APP_SECRET_KEY throws a FATAL error', (t) => {
    const warn = t.mock.fn();
    for (const value of [undefined, '', '   ']) {
      assert.throws(
        () => resolveAppSecretKey({ NODE_ENV: 'production', APP_SECRET_KEY: value }, warn),
        /FATAL: APP_SECRET_KEY/,
        JSON.stringify(value)
      );
    }
    assert.equal(warn.mock.callCount(), 0);
  });

  test('production with the deterministic development fallback key throws', (t) => {
    const warn = t.mock.fn();
    assert.match(DEV_FALLBACK_SECRET_KEY, /^[0-9a-f]{64}$/);
    for (const value of [DEV_FALLBACK_SECRET_KEY, DEV_FALLBACK_SECRET_KEY.toUpperCase(), ` ${DEV_FALLBACK_SECRET_KEY}\n`]) {
      assert.throws(
        () => resolveAppSecretKey({ NODE_ENV: 'production', APP_SECRET_KEY: value }, warn),
        /FATAL: APP_SECRET_KEY/
      );
    }
    assert.equal(warn.mock.callCount(), 0);
  });

  test('production with the .env.example sample key throws', (t) => {
    const warn = t.mock.fn();
    const envExample = fs.readFileSync(path.join(REPO_ROOT, '.env.example'), 'utf8');
    const shippedSample = envExample.match(/^APP_SECRET_KEY=(.*)$/m)?.[1]?.trim();
    const samples = [EXAMPLE_SECRET_KEY, EXAMPLE_SECRET_KEY.toUpperCase()];
    if (shippedSample) samples.push(shippedSample);
    for (const value of samples) {
      assert.throws(
        () => resolveAppSecretKey({ NODE_ENV: 'production', APP_SECRET_KEY: value }, warn),
        /FATAL: APP_SECRET_KEY/,
        value
      );
    }
    assert.equal(warn.mock.callCount(), 0);
  });

  test('production with a key that is not exactly 64 hex characters throws', (t) => {
    const warn = t.mock.fn();
    const valid = randomKey();
    const malformed = [
      valid.slice(0, 63),
      `${valid}a`,
      `g${valid.slice(1)}`,
      `0x${valid.slice(2)}`,
      crypto.randomBytes(32).toString('base64'),
      'z'.repeat(64),
    ];
    for (const value of malformed) {
      assert.throws(
        () => resolveAppSecretKey({ NODE_ENV: 'production', APP_SECRET_KEY: value }, warn),
        /FATAL: APP_SECRET_KEY/,
        value
      );
    }
    assert.equal(warn.mock.callCount(), 0);
  });

  test('production with a fresh random 64-hex key returns it without warning', (t) => {
    const warn = t.mock.fn();
    const key = randomKey();
    assert.equal(resolveAppSecretKey({ NODE_ENV: 'production', APP_SECRET_KEY: key }, warn), key);
    assert.equal(warn.mock.callCount(), 0);
  });

  test('development/test without a key fall back to DEV_FALLBACK_SECRET_KEY deterministically and warn once', (t) => {
    for (const nodeEnv of ['development', 'test', undefined]) {
      const warn = t.mock.fn();
      const first = resolveAppSecretKey({ NODE_ENV: nodeEnv }, warn);
      assert.equal(first, DEV_FALLBACK_SECRET_KEY, String(nodeEnv));
      assert.equal(warn.mock.callCount(), 1, String(nodeEnv));
      assert.match(String(warn.mock.calls[0].arguments[0]), /APP_SECRET_KEY.*insecure development key/);

      const warnAgain = t.mock.fn();
      assert.equal(resolveAppSecretKey({ NODE_ENV: nodeEnv, APP_SECRET_KEY: '' }, warnAgain), first);
      assert.equal(warnAgain.mock.callCount(), 1);
    }
  });

  test('development with a malformed key falls back to DEV_FALLBACK_SECRET_KEY and warns once', (t) => {
    const warn = t.mock.fn();
    assert.equal(resolveAppSecretKey({ NODE_ENV: 'development', APP_SECRET_KEY: 'too-short' }, warn), DEV_FALLBACK_SECRET_KEY);
    assert.equal(warn.mock.callCount(), 1);
    assert.match(String(warn.mock.calls[0].arguments[0]), /insecure development key/);
  });

  test('test with a valid key returns that key without warning', (t) => {
    const warn = t.mock.fn();
    const key = randomKey();
    assert.equal(resolveAppSecretKey({ NODE_ENV: 'test', APP_SECRET_KEY: key }, warn), key);
    assert.equal(warn.mock.callCount(), 0);
  });
});

describe('config: resolveBootstrapAdmin', () => {
  test('defaults to DEFAULT_BOOTSTRAP_ADMIN (admin / admin123) and flags the default password', () => {
    assert.deepEqual({ ...DEFAULT_BOOTSTRAP_ADMIN }, { username: 'admin', password: 'admin123' });
    assert.deepEqual(resolveBootstrapAdmin({}), {
      username: DEFAULT_BOOTSTRAP_ADMIN.username,
      password: DEFAULT_BOOTSTRAP_ADMIN.password,
      usesDefaultPassword: true,
    });
  });

  test('ADMIN_BOOTSTRAP_USERNAME and ADMIN_BOOTSTRAP_PASSWORD override the defaults', () => {
    const password = `Pw-${crypto.randomBytes(12).toString('base64url')}`;
    assert.deepEqual(resolveBootstrapAdmin({ ADMIN_BOOTSTRAP_USERNAME: 'breakglass', ADMIN_BOOTSTRAP_PASSWORD: password }), {
      username: 'breakglass',
      password,
      usesDefaultPassword: false,
    });
  });

  test('legacy ADMIN_USERNAME is used when ADMIN_BOOTSTRAP_USERNAME is absent, and loses when both are set', () => {
    assert.equal(resolveBootstrapAdmin({ ADMIN_USERNAME: 'legacy-admin' }).username, 'legacy-admin');
    assert.equal(
      resolveBootstrapAdmin({ ADMIN_USERNAME: 'legacy-admin', ADMIN_BOOTSTRAP_USERNAME: 'new-admin' }).username,
      'new-admin'
    );
  });

  test('explicitly setting ADMIN_BOOTSTRAP_PASSWORD=admin123 still counts as the default password', () => {
    const resolved = resolveBootstrapAdmin({ ADMIN_BOOTSTRAP_USERNAME: 'ops', ADMIN_BOOTSTRAP_PASSWORD: 'admin123' });
    assert.equal(resolved.password, 'admin123');
    assert.equal(resolved.usesDefaultPassword, true);
  });

  test('an empty ADMIN_BOOTSTRAP_PASSWORD means "use the default" and is flagged as such', () => {
    const resolved = resolveBootstrapAdmin({ ADMIN_BOOTSTRAP_PASSWORD: '' });
    assert.equal(resolved.password, DEFAULT_BOOTSTRAP_ADMIN.password);
    assert.equal(resolved.usesDefaultPassword, true);
  });
});

describe('config: buildConfig', () => {
  // A valid key keeps resolveAppSecretKey from warning on console during these parsing tests.
  const baseEnv = () => ({ NODE_ENV: 'test', APP_SECRET_KEY: randomKey() });

  test('backend port defaults to 3001 and PORT is parsed as an integer', () => {
    assert.equal(buildConfig(baseEnv()).port, 3001);
    assert.equal(buildConfig({ ...baseEnv(), PORT: '4105' }).port, 4105);
  });

  test('BASE_URL defaults to http://localhost:3000 and trailing slashes are trimmed', () => {
    assert.equal(buildConfig(baseEnv()).baseUrl, 'http://localhost:3000');
    assert.equal(buildConfig({ ...baseEnv(), BASE_URL: 'https://portal.example.com/' }).baseUrl, 'https://portal.example.com');
    assert.equal(
      buildConfig({ ...baseEnv(), BASE_URL: 'https://portal.example.com/governance///' }).baseUrl,
      'https://portal.example.com/governance'
    );
  });

  test('SALESFORCE_ALLOWED_DOMAINS is split, trimmed, lower-cased and empty entries dropped', () => {
    assert.deepEqual(buildConfig(baseEnv()).salesforce.allowedDomains, ['.my.salesforce.com', '.salesforce.com', '.force.com']);
    assert.deepEqual(
      buildConfig({ ...baseEnv(), SALESFORCE_ALLOWED_DOMAINS: ' .My.Salesforce.COM , ACME.Force.com,, ' }).salesforce.allowedDomains,
      ['.my.salesforce.com', 'acme.force.com']
    );
  });

  test('TRUST_PROXY defaults to false (X-Forwarded-For not trusted) and parses booleans, hop counts and lists', () => {
    assert.equal(buildConfig(baseEnv()).trustProxy, false);
    assert.equal(buildConfig({ ...baseEnv(), TRUST_PROXY: 'loopback' }).trustProxy, 'loopback');
    assert.equal(buildConfig({ ...baseEnv(), TRUST_PROXY: 'true' }).trustProxy, true);
    assert.equal(buildConfig({ ...baseEnv(), TRUST_PROXY: 'false' }).trustProxy, false);
    assert.equal(buildConfig({ ...baseEnv(), TRUST_PROXY: '2' }).trustProxy, 2);
    assert.equal(buildConfig({ ...baseEnv(), TRUST_PROXY: 'loopback, 10.0.0.0/8' }).trustProxy, 'loopback, 10.0.0.0/8');
  });
});

// ---------------------------------------------------------------------------------------------
// Real startup: spawn `node --import tsx src/index.ts` with a fresh DB per case and PORT=0.
// ---------------------------------------------------------------------------------------------

const STARTUP_TIMEOUT_MS = 20_000;

interface ExitInfo {
  code: number | null;
  signal: NodeJS.Signals | null;
}

interface BackendRun {
  child: ChildProcess;
  stdout: string;
  stderr: string;
  exit: ExitInfo | null;
  closed: Promise<ExitInfo>;
}

function describeOutput(run: BackendRun): string {
  return `exit=${JSON.stringify(run.exit)}\n--- stdout ---\n${run.stdout}\n--- stderr ---\n${run.stderr}`;
}

/** Starts the real backend entry point; the child is always killed in t.after, even on failure. */
function startBackend(t: TestContext, envOverrides: Record<string, string>): BackendRun {
  const dbDir = fs.mkdtempSync(path.join(testTmpDir, 'startup-'));
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PORT: '0',
    DB_PATH: path.join(dbDir, 'governance.sqlite'),
    ...envOverrides,
  };
  delete env.NODE_TEST_CONTEXT;

  const child = spawn(process.execPath, ['--import', 'tsx', 'src/index.ts'], {
    cwd: REPO_ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: STARTUP_TIMEOUT_MS,
    killSignal: 'SIGKILL',
  });

  const run = { child, stdout: '', stderr: '', exit: null } as Omit<BackendRun, 'closed'> as BackendRun;
  child.stdout!.setEncoding('utf8');
  child.stderr!.setEncoding('utf8');
  child.stdout!.on('data', (chunk: string) => {
    run.stdout += chunk;
  });
  child.stderr!.on('data', (chunk: string) => {
    run.stderr += chunk;
  });
  run.closed = new Promise<ExitInfo>((resolve) => {
    child.once('close', (code, signal) => {
      run.exit = { code, signal };
      resolve(run.exit);
    });
    child.once('error', (err) => {
      run.stderr += `\n[spawn error] ${err.message}`;
      if (child.pid === undefined) {
        run.exit = { code: null, signal: null };
        resolve(run.exit);
      }
    });
  });

  t.after(async () => {
    if (run.exit === null && child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
    }
    await run.closed;
  });
  return run;
}

function waitForStdout(run: BackendRun, pattern: RegExp, timeoutMs = STARTUP_TIMEOUT_MS): Promise<void> {
  return new Promise((resolve, reject) => {
    const finish = (err?: Error) => {
      clearTimeout(timer);
      run.child.stdout!.off('data', onData);
      run.child.off('close', onClose);
      if (err) reject(err);
      else resolve();
    };
    const onData = () => {
      if (pattern.test(run.stdout)) finish();
    };
    const onClose = () => finish(new Error(`backend exited before printing ${pattern}\n${describeOutput(run)}`));
    const timer = setTimeout(
      () => finish(new Error(`timed out after ${timeoutMs}ms waiting for ${pattern}\n${describeOutput(run)}`)),
      timeoutMs
    );
    run.child.stdout!.on('data', onData);
    run.child.once('close', onClose);
    if (pattern.test(run.stdout)) finish();
    else if (run.exit) onClose();
  });
}

async function assertFatalStartup(run: BackendRun, mentions: RegExp): Promise<void> {
  const { code, signal } = await run.closed;
  assert.equal(signal, null, `backend must exit on its own within ${STARTUP_TIMEOUT_MS}ms\n${describeOutput(run)}`);
  assert.notEqual(code, 0, `backend must exit non-zero\n${describeOutput(run)}`);
  assert.match(run.stderr, /FATAL/, describeOutput(run));
  assert.match(run.stderr, mentions, describeOutput(run));
  assert.doesNotMatch(run.stdout + run.stderr, /Backend listening/, describeOutput(run));
}

async function stopBackend(run: BackendRun): Promise<ExitInfo> {
  assert.equal(run.exit, null, `backend should still be running after reporting it is listening\n${describeOutput(run)}`);
  run.child.kill('SIGTERM');
  return run.closed;
}

describe('startup fail-fast (child process running src/index.ts)', () => {
  test('a) production with APP_SECRET_KEY="" exits non-zero with a FATAL APP_SECRET_KEY error', { timeout: 30_000 }, async (t) => {
    const run = startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: '',
      ADMIN_BOOTSTRAP_PASSWORD: `Pw-${crypto.randomBytes(18).toString('base64url')}`,
    });
    await assertFatalStartup(run, /APP_SECRET_KEY/);
  });

  test('b) production with APP_SECRET_KEY = DEV_FALLBACK_SECRET_KEY exits non-zero with a FATAL error', { timeout: 30_000 }, async (t) => {
    const run = startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: DEV_FALLBACK_SECRET_KEY,
      ADMIN_BOOTSTRAP_PASSWORD: `Pw-${crypto.randomBytes(18).toString('base64url')}`,
    });
    await assertFatalStartup(run, /APP_SECRET_KEY/);
  });

  test('c) production with an empty ADMIN_BOOTSTRAP_PASSWORD on an empty DB refuses to seed the default admin', { timeout: 30_000 }, async (t) => {
    const run = startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: randomKey(),
      ADMIN_BOOTSTRAP_PASSWORD: '',
    });
    await assertFatalStartup(run, /ADMIN_BOOTSTRAP_PASSWORD/);
  });

  test('c2) production with ADMIN_BOOTSTRAP_PASSWORD=admin123 set explicitly on an empty DB also refuses to start', { timeout: 30_000 }, async (t) => {
    const run = startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: randomKey(),
      ADMIN_BOOTSTRAP_PASSWORD: 'admin123',
    });
    await assertFatalStartup(run, /ADMIN_BOOTSTRAP_PASSWORD/);
  });

  test('d) production with a strong APP_SECRET_KEY and ADMIN_BOOTSTRAP_PASSWORD starts and listens', { timeout: 30_000 }, async (t) => {
    const run = startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: randomKey(),
      ADMIN_BOOTSTRAP_PASSWORD: `Pw-${crypto.randomBytes(18).toString('base64url')}`,
    });
    await waitForStdout(run, /Backend listening/);
    await stopBackend(run);
    assert.doesNotMatch(run.stderr, /FATAL/, describeOutput(run));
    assert.doesNotMatch(run.stdout + run.stderr, /insecure development key/, describeOutput(run));
  });

  test('e) development with APP_SECRET_KEY="" starts and warns about the insecure development key', { timeout: 30_000 }, async (t) => {
    const run = startBackend(t, { NODE_ENV: 'development', APP_SECRET_KEY: '' });
    await waitForStdout(run, /Backend listening/);
    await stopBackend(run);
    assert.match(run.stdout + run.stderr, /APP_SECRET_KEY.*insecure development key/, describeOutput(run));
  });
});
