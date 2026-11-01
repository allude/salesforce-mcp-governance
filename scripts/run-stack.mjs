#!/usr/bin/env node
// Runs the Express MCP backend (:3001) and the Next.js Admin Portal (:3000) together,
// prefixes their output, and stops both when either exits or on Ctrl+C.
//   node scripts/run-stack.mjs dev     -> tsx watch src/index.ts + next dev
//   node scripts/run-stack.mjs start   -> node dist/index.js + next start (run `npm run build` first;
//                                          the backend runs with NODE_ENV=production unless set)
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { parseEnv } from 'node:util';

const mode = process.argv[2] === 'start' ? 'start' : 'dev';
const root = process.cwd();

// The services load .env themselves, but the values set below for them would take precedence,
// so the stack settings in .env are read here too (real environment variables still win).
try {
  const fileEnv = parseEnv(fs.readFileSync(path.join(root, '.env'), 'utf8'));
  for (const key of ['MCP_BACKEND_PORT', 'PORTAL_PORT', 'MCP_BACKEND_URL']) {
    if (process.env[key] === undefined && fileEnv[key]) process.env[key] = fileEnv[key];
  }
} catch {
  // no .env
}
let backendPort = process.env.MCP_BACKEND_PORT || '3001';
const portalPort = process.env.PORTAL_PORT || '3000';
const isWindows = process.platform === 'win32';

/** `next start` proxies to the backend URL baked into the build, so read it from the build output. */
function readBakedBackendUrl() {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, '.next', 'routes-manifest.json'), 'utf8'));
    const rewrites = Array.isArray(manifest.rewrites)
      ? manifest.rewrites
      : [...(manifest.rewrites?.beforeFiles || []), ...(manifest.rewrites?.afterFiles || []), ...(manifest.rewrites?.fallback || [])];
    const mcp = rewrites.find((r) => r.source === '/mcp');
    return mcp ? new URL(mcp.destination).origin : null;
  } catch {
    return null;
  }
}

if (mode === 'start') {
  const bakedBackendUrl = readBakedBackendUrl();
  if (!bakedBackendUrl || !fs.existsSync(path.join(root, 'dist', 'index.js'))) {
    console.error('No production build found (dist/index.js and .next/). Run `npm run build` first.');
    process.exit(1);
  }
  const bakedPort = new URL(bakedBackendUrl).port || '80';
  if (process.env.MCP_BACKEND_PORT && process.env.MCP_BACKEND_PORT !== bakedPort) {
    console.error(
      `The portal was built to proxy to ${bakedBackendUrl}, but MCP_BACKEND_PORT=${process.env.MCP_BACKEND_PORT}. ` +
        `Rebuild with MCP_BACKEND_URL=http://localhost:${process.env.MCP_BACKEND_PORT} npm run build.`
    );
    process.exit(1);
  }
  backendPort = bakedPort;
}
const bin = (name) => path.join(root, 'node_modules', '.bin', isWindows ? `${name}.cmd` : name);

const services = [
  {
    name: 'mcp',
    command: mode === 'dev' ? bin('tsx') : process.execPath,
    args: mode === 'dev' ? ['watch', 'src/index.ts'] : ['dist/index.js'],
    // `start` is the production build, so the backend applies its production fail-fast checks
    // (APP_SECRET_KEY, default passwords) unless NODE_ENV is set explicitly.
    env: { PORT: backendPort, ...(mode === 'start' ? { NODE_ENV: process.env.NODE_ENV || 'production' } : {}) },
  },
  {
    name: 'web',
    command: bin('next'),
    args: [mode, '--port', portalPort],
    // Only read by `next dev`; `next start` uses the URL baked in at build time (checked above).
    env: { MCP_BACKEND_URL: process.env.MCP_BACKEND_URL || `http://localhost:${backendPort}` },
  },
];

const children = [];
let shuttingDown = false;

const hasExited = (child) => child.exitCode !== null || child.signalCode !== null;

function signalGroup(child, signal) {
  try {
    // Each service runs in its own process group, so watchers, workers and the real server
    // underneath `tsx watch` stop too, even when the group leader has already exited.
    if (isWindows) {
      if (!hasExited(child)) child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch {
    // group already gone
  }
}

function stopAll(exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.exitCode = exitCode;
  for (const child of children) signalGroup(child, 'SIGTERM');

  const forceTimer = setTimeout(() => {
    for (const child of children) signalGroup(child, 'SIGKILL');
    process.exit(exitCode);
  }, 5000);
  Promise.all(
    children.map((c) => (hasExited(c) ? Promise.resolve() : new Promise((resolve) => c.once('exit', resolve))))
  ).then(() => {
    clearTimeout(forceTimer);
    process.exit(exitCode);
  });
}

for (const service of services) {
  const child = spawn(service.command, service.args, {
    cwd: root,
    env: { ...process.env, ...service.env },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: !isWindows,
    shell: isWindows,
  });
  children.push(child);
  for (const stream of [child.stdout, child.stderr]) {
    readline.createInterface({ input: stream }).on('line', (line) => console.log(`[${service.name}] ${line}`));
  }
  child.on('error', (err) => {
    console.error(`[${service.name}] failed to start: ${err.message}`);
    stopAll(1);
  });
  child.on('exit', (code, signal) => {
    if (!shuttingDown) {
      console.error(`[${service.name}] exited (${signal || code}); stopping the other service.`);
      stopAll(code || 1);
    }
  });
}

// Ctrl+C, a supervisor stop or closing the terminal is a deliberate stop (exit 0); a service that
// dies on its own makes the stack exit non-zero (see the 'exit' handler above), so supervisors restart it.
process.on('SIGINT', () => stopAll(0));
process.on('SIGTERM', () => stopAll(0));
process.on('SIGHUP', () => stopAll(0));
console.log(`Starting ${mode} stack: Admin Portal http://localhost:${portalPort} -> MCP backend http://localhost:${backendPort}`);
