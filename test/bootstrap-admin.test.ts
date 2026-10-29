import './helpers/env.js';
// The break-glass portal login, end to end in real backend processes: the canonical development
// default, a configured production password, and production's refusal to run with publicly known
// passwords (with rotation of the bootstrap account when a strong password is configured).
import { describe, test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { testTmpDir } from './helpers/env.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = path.join(REPO_ROOT, 'src', 'index.ts');

interface Backend {
  port: number;
  child: ChildProcess;
}

/** Starts src/index.ts in its own process; resolves once it listens, rejects if it exits first. */
function startBackend(
  t: TestContext,
  env: Record<string, string>
): Promise<Backend> {
  const childEnv: NodeJS.ProcessEnv = { ...process.env, PORT: '0', ...env };
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, ['--import', 'tsx', ENTRY], { cwd: REPO_ROOT, env: childEnv });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });

  return new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error(`backend did not start in time:\n${output}`)), 25_000);
    const onData = (chunk: Buffer) => {
      output += chunk.toString();
      const match = output.match(/Backend listening on:\s+http:\/\/localhost:(\d+)/);
      if (match) {
        clearTimeout(timer);
        resolve({ port: Number(match[1]), child });
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(Object.assign(new Error(`backend exited with ${code}:\n${output}`), { output, code }));
    });
  });
}

async function stopBackend(backend: Backend): Promise<void> {
  if (backend.child.exitCode !== null) return;
  await new Promise<void>((resolve) => {
    backend.child.once('exit', () => resolve());
    backend.child.kill('SIGTERM');
  });
}

async function login(port: number, username: string, password: string): Promise<number> {
  const res = await fetch(`http://127.0.0.1:${port}/api/admin/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  await res.text();
  return res.status;
}

const freshDb = () => path.join(testTmpDir, `bootstrap-${crypto.randomBytes(4).toString('hex')}.sqlite`);
const strongKey = () => crypto.randomBytes(32).toString('hex');
const strongPassword = () => `Str0ng-${crypto.randomBytes(9).toString('base64url')}`;
// Explicit empty values: dotenv never overrides a defined key, so a local .env cannot interfere.
const UNSET_BOOTSTRAP = { ADMIN_BOOTSTRAP_USERNAME: '', ADMIN_BOOTSTRAP_PASSWORD: '', ADMIN_USERNAME: '' };

describe('bootstrap portal admin (real backend processes)', () => {
  test('development with ADMIN_BOOTSTRAP_* unset seeds the canonical admin / admin123 login', { timeout: 60_000 }, async (t) => {
    const backend = await startBackend(t, { NODE_ENV: 'development', APP_SECRET_KEY: '', DB_PATH: freshDb(), ...UNSET_BOOTSTRAP });
    assert.equal(await login(backend.port, 'admin', 'admin123'), 200);
    assert.equal(await login(backend.port, 'admin', 'wrong-password'), 401);
    await stopBackend(backend);
  });

  test('production with a configured ADMIN_BOOTSTRAP_PASSWORD: that password works and admin123 does not', { timeout: 60_000 }, async (t) => {
    const password = strongPassword();
    const backend = await startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: strongKey(),
      DB_PATH: freshDb(),
      ...UNSET_BOOTSTRAP,
      ADMIN_BOOTSTRAP_PASSWORD: password,
    });
    assert.equal(await login(backend.port, 'admin', password), 200);
    assert.equal(await login(backend.port, 'admin', 'admin123'), 401);
    await stopBackend(backend);
  });

  test('production refuses to run while an existing account has a known default password, and rotates the bootstrap account when a strong one is set', { timeout: 90_000 }, async (t) => {
    // A database first created by `npm run dev` (admin / admin123), later used in production
    const dbPath = freshDb();
    const dev = await startBackend(t, { NODE_ENV: 'development', APP_SECRET_KEY: '', DB_PATH: dbPath, ...UNSET_BOOTSTRAP });
    await stopBackend(dev);

    const key = strongKey();
    await assert.rejects(
      startBackend(t, { NODE_ENV: 'production', APP_SECRET_KEY: key, DB_PATH: dbPath, ...UNSET_BOOTSTRAP }),
      (err: any) => {
        assert.notEqual(err.code, 0);
        assert.match(err.output, /FATAL: Portal user 'admin' uses a publicly known default password/);
        assert.doesNotMatch(err.output, /Backend listening/);
        return true;
      }
    );

    const password = strongPassword();
    const prod = await startBackend(t, {
      NODE_ENV: 'production',
      APP_SECRET_KEY: key,
      DB_PATH: dbPath,
      ...UNSET_BOOTSTRAP,
      ADMIN_BOOTSTRAP_PASSWORD: password,
    });
    assert.equal(await login(prod.port, 'admin', password), 200);
    assert.equal(await login(prod.port, 'admin', 'admin123'), 401);
    await stopBackend(prod);
  });
});
