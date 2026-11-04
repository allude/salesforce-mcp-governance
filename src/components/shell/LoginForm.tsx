'use client';

import React, { useState } from 'react';
import { readJsonBody } from './portalClient';

export interface LoginResult {
  user: any;
  csrfToken: string;
  expiresAt: string | null;
}

/**
 * The password and Okta sign-in, shared by the sign-in page and the shell's re-auth dialog (which
 * signs in again without leaving the page, so unsaved drafts stay). `lockedUsername` fixes the account
 * the re-auth dialog may sign back in as.
 */
export function LoginForm({
  oktaEnabled,
  error,
  onSignedIn,
  lockedUsername,
  oktaNote,
  autoFocus = false,
}: {
  oktaEnabled: boolean;
  error?: string;
  onSignedIn: (result: LoginResult) => void | Promise<void>;
  lockedUsername?: string;
  /** Shown under the Okta button (the re-auth dialog says the page will reload). */
  oktaNote?: string;
  autoFocus?: boolean;
}) {
  const [username, setUsername] = useState(lockedUsername ?? '');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [localError, setLocalError] = useState('');
  const shown = localError || error || '';
  const userId = React.useId();
  const passId = React.useId();
  const errId = React.useId();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError('');
    setBusy(true);
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await readJsonBody(res);
      if (!res.ok) throw new Error(data.error || 'Authentication failed');
      if (lockedUsername && data.user?.username !== lockedUsername) {
        throw new Error(`Sign in as "${lockedUsername}" to keep this page's unsaved changes.`);
      }
      setPassword('');
      await onSignedIn({ user: data.user, csrfToken: data.csrfToken || '', expiresAt: data.expiresAt ?? null });
    } catch (err: any) {
      setLocalError(err?.message || 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      {shown && (
        <div id={errId} role="alert" className="login-err">
          {shown}
        </div>
      )}

      {oktaEnabled && (
        <>
          {/* Okta OIDC: the server redirects to Okta and verifies the callback. */}
          <a className="btn pri login-okta" href="/auth/okta/login">
            Continue with Okta SSO
          </a>
          {oktaNote && <p className="login-note">{oktaNote}</p>}
          <div className="login-or" aria-hidden="true">
            <span />
            <span>OR LOCAL ADMINISTRATOR</span>
            <span />
          </div>
        </>
      )}

      <form onSubmit={submit} aria-describedby={shown ? errId : undefined}>
        <div className="fld">
          <label htmlFor={userId}>Username</label>
          <input
            id={userId}
            name="username"
            className="inp mono"
            autoComplete="username"
            autoFocus={autoFocus && !lockedUsername}
            value={username}
            readOnly={Boolean(lockedUsername)}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="fld">
          <div className="login-pass-h">
            <label htmlFor={passId}>Password</label>
            {process.env.NODE_ENV !== 'production' && !lockedUsername && (
              <button
                type="button"
                className="btn gh sm"
                onClick={() => {
                  setUsername('admin');
                  setPassword('admin123');
                }}
              >
                Fill development default
              </button>
            )}
          </div>
          <input
            id={passId}
            name="password"
            type="password"
            className="inp mono"
            autoComplete="current-password"
            autoFocus={autoFocus && Boolean(lockedUsername)}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <button type="submit" className="btn login-submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in with password'}
        </button>
      </form>
    </div>
  );
}
