'use client';

import React, { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { LoginForm } from './LoginForm';
import { applyTheme, oktaAuthErrorMessage, readJsonBody, readTheme } from './portalClient';
import { buildHref, safePortalHref } from './routes';

/**
 * `/`: the sign-in and boot page. Signed in already, it goes straight on; otherwise it shows the
 * password and Okta sign-in and then goes to `next` (rebuilt from the route map, so a crafted link
 * cannot send the admin anywhere else) or the dashboard. Okta failures come back as ?auth_error=<code>,
 * shown with fixed text only.
 */
export function SignInPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = safePortalHref(searchParams.get('next')) ?? buildHref('dashboard');
  const [checking, setChecking] = useState(true);
  const [oktaEnabled, setOktaEnabled] = useState(false);
  const [error, setError] = useState(() => oktaAuthErrorMessage(searchParams.get('auth_error')));
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => setTheme(readTheme()), []);

  useEffect(() => {
    // The code is shown once; a reload must not show it again.
    if (searchParams.get('auth_error')) {
      const params = new URLSearchParams(searchParams.toString());
      params.delete('auth_error');
      const q = params.toString();
      window.history.replaceState(null, '', `/${q ? `?${q}` : ''}`);
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/admin/session', { credentials: 'include', cache: 'no-store' });
        const d = await readJsonBody(res);
        if (cancelled) return;
        if (!res.ok) {
          setError(`The MCP backend is not reachable (${res.status}). Start it with \`npm run dev\` (backend on :3001).`);
        }
        setOktaEnabled(Boolean(d.oktaSso?.enabled));
        if (d.authenticated && d.user) {
          router.replace(next);
          return;
        }
      } catch {
        if (!cancelled) setError('The MCP backend is not reachable. Start it with `npm run dev` (backend on :3001).');
      }
      if (!cancelled) setChecking(false);
    })();
    return () => {
      cancelled = true;
    };
    // Once per visit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (checking) {
    return (
      <div className="boot" role="status" aria-live="polite">
        <span className="dot" aria-hidden="true" />
        <span className="mono">Initializing Salesforce MCP Control Plane…</span>
      </div>
    );
  }

  return (
    <main className="login-page">
      <div className="card login-card">
        <div className="card-h">
          <div className="login-brand">
            <div className="brand-mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" />
                <path d="M12 8v8M8 10l4 2 4-2" />
              </svg>
            </div>
            <div>
              <h1 className="brand-t">Salesforce MCP</h1>
              <div className="brand-s">Enterprise Governance Control Plane</div>
            </div>
          </div>
          <button
            type="button"
            className="btn gh sm"
            onClick={() => {
              const t = theme === 'dark' ? 'light' : 'dark';
              applyTheme(t);
              setTheme(t);
            }}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          >
            {theme === 'dark' ? '☀' : '☾'}
          </button>
        </div>
        <div className="card-b">
          <LoginForm oktaEnabled={oktaEnabled} error={error} autoFocus onSignedIn={() => router.replace(next)} />
        </div>
      </div>
    </main>
  );
}
