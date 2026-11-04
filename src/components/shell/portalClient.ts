/**
 * Small helpers the sign-in page and the portal shell share. Pure: no React.
 */
import type { AdminSession } from '@/types/governance';

/** Parses a JSON body without throwing on HTML or text error pages (a proxy 500, for example). */
export async function readJsonBody(res: Response): Promise<any> {
  const text = await res.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { error: `${res.status} ${res.statusText || 'Request failed'}` };
  }
}

export function toAdminSession(user: any, expiresAt?: string | null): AdminSession & { expiresAt: string | null } {
  return {
    username: user.username,
    name: user.name,
    displayName: user.name,
    role: user.role || user.groups?.[0] || 'Platform Admin',
    authMethod: user.authMethod,
    groups: user.groups,
    expiresAt: expiresAt ?? null,
  };
}

/**
 * Fixed messages for the codes /auth/okta/callback redirects with. Any other value is ignored, so a
 * crafted link cannot put its own text on the sign-in screen.
 */
export const OKTA_AUTH_ERRORS: Record<string, string> = {
  okta_error: 'Okta returned an error. Details are in the Admin Audit Logs.',
  invalid_callback: 'The Okta sign-in response was incomplete. Please try again.',
  expired_state: 'The Okta sign-in took too long or was started in another browser. Please try again.',
  state_mismatch: 'The Okta sign-in response did not match this browser session. Please try again.',
  group_denied: 'Your Okta account is not in the group required for this portal.',
  sso_failed: 'Okta sign-in failed. Details are in the Admin Audit Logs.',
};

export function oktaAuthErrorMessage(code: string | null): string {
  if (!code) return '';
  return OKTA_AUTH_ERRORS[code] || 'Okta sign-in failed. Please try again.';
}

export const THEME_STORAGE_KEY = 'mcp_portal_theme';

/**
 * Runs in <head> before the first paint, so the page never flashes the other theme: the stored choice,
 * else the system's. Kept as a string because it must run before React.
 */
export const THEME_BOOT_SCRIPT = `(function(){try{var t=localStorage.getItem('${THEME_STORAGE_KEY}');if(t!=='light'&&t!=='dark'){t=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'}document.documentElement.setAttribute('data-theme',t)}catch(e){}})();`;

export function readTheme(): 'dark' | 'light' {
  if (typeof document === 'undefined') return 'dark';
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

export function applyTheme(next: 'dark' | 'light'): void {
  document.documentElement.setAttribute('data-theme', next);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    // private mode: the choice lasts for this page only
  }
}
