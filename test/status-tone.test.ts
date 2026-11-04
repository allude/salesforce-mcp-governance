import './helpers/env.js';
// One mapping from a runtime status to its colour (src/components/ui/statusTone.ts): DENIED is rose,
// ERROR amber, ALLOWED emerald, wherever the portal shows them. No other file may map them itself.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { statusTone, statusToneClass } from '../src/components/ui/statusTone.js';
import { portalAuditResult } from '../src/components/views/portalAudit.js';
import { connectionStatusBadge } from '../src/components/views/orgConnectionState.js';

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src');

describe('statusTone', () => {
  test('MCP call outcomes: allowed emerald, denied rose, error amber', () => {
    assert.equal(statusTone('ALLOWED'), 'allowed');
    assert.equal(statusTone('DENIED'), 'denied');
    assert.equal(statusTone('ERROR'), 'error');
  });

  test('admin audit results use the same tones for the same outcomes', () => {
    assert.equal(statusTone('SUCCESS'), 'allowed');
    assert.equal(statusTone('DENIED'), 'denied');
    assert.equal(statusTone('FAILED'), 'error');
    assert.equal(portalAuditResult({ action: 'LOGIN_FAILED' }).tone, 'error');
    assert.equal(portalAuditResult({ action: 'OKTA_LOGIN_DENIED' }).tone, 'denied');
    assert.equal(portalAuditResult({ action: 'UPDATE_GROUP', result: 'SUCCESS' }).tone, 'allowed');
  });

  test('connection and freshness states: error and not verified are amber, never rose', () => {
    assert.equal(statusTone('connected'), 'allowed');
    assert.equal(statusTone('error'), 'error');
    assert.equal(statusTone('not_verified'), 'error');
    assert.equal(statusTone('disconnected'), 'neutral');
    assert.equal(statusTone('Degraded'), 'error');
    assert.equal(statusTone('Live'), 'allowed');
    assert.equal(statusTone('Paused'), 'neutral');
    assert.equal(connectionStatusBadge('error', '').tone, 'error');
  });

  test('anything unknown, empty or missing is neutral', () => {
    for (const value of ['', 'PENDING', 'allow', undefined, null]) assert.equal(statusTone(value), 'neutral');
  });

  test('tones map to the status token classes; neutral has none', () => {
    assert.equal(statusToneClass('allowed'), 'st-allowed');
    assert.equal(statusToneClass('denied'), 'st-denied');
    assert.equal(statusToneClass('error'), 'st-error');
    assert.equal(statusToneClass('neutral'), '');
  });
});

describe('only statusTone maps a status to a colour', () => {
  const files = (fs.readdirSync(SRC, { recursive: true, encoding: 'utf8' }) as string[])
    .filter((f) => /\.(tsx?|css)$/.test(f))
    .map((f) => path.join(SRC, f));

  test('no view compares a status to pick a tag, dot or colour itself', () => {
    // The old inline mappings: `status === 'DENIED' ? 'warn' : 'err'` and friends.
    const inline = /status\s*===\s*'(ALLOWED|DENIED|ERROR)'\s*\?\s*'(ok|warn|err)'/;
    const offenders = files.filter((f) => inline.test(fs.readFileSync(f, 'utf8').replace(/\s+/g, ' ')));
    assert.deepEqual(offenders.map((f) => path.relative(SRC, f)), []);
  });

  test('the traffic chart and legend paint with the status tokens, not hard-coded colours', () => {
    const views = fs.readFileSync(path.join(SRC, 'components/views/DashboardAndLogsViews.tsx'), 'utf8');
    assert.doesNotMatch(views, /rgba\(0,\s*163,\s*255/);
    assert.doesNotMatch(views, /className="b-seg (ok|warn|err)"/);
    const css = fs.readFileSync(path.join(SRC, 'app/globals.css'), 'utf8');
    for (const tone of ['allowed', 'denied', 'error']) {
      assert.match(css, new RegExp(`--status-${tone}:`));
      assert.match(css, new RegExp(`--status-${tone}-bg:`));
      assert.match(css, new RegExp(`--status-${tone}-border:`));
    }
  });
});
