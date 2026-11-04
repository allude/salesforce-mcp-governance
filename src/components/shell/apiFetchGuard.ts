/**
 * apiFetch sends the admin session cookie and the CSRF token, so it may only ever reach the Admin API.
 * This keeps admin credentials away from /mcp (Copilot's endpoint, which authenticates its own bearer
 * tokens), /auth/okta, /.well-known and any other origin. Relative to the portal's own origin only.
 */
export const ADMIN_API_PREFIX = '/api/admin/';

export class AdminApiUrlError extends Error {
  constructor(url: string) {
    super(`apiFetch only calls the Admin API (${ADMIN_API_PREFIX}…); refused ${JSON.stringify(url.slice(0, 120))}.`);
    this.name = 'AdminApiUrlError';
  }
}

/** Throws unless `url` is a same-origin path under /api/admin/ that cannot resolve anywhere else. */
export function assertAdminApiUrl(url: unknown): asserts url is string {
  if (typeof url !== 'string') throw new AdminApiUrlError(String(url));
  const ok =
    url.startsWith(ADMIN_API_PREFIX) &&
    // Dot segments (encoded or not) could climb out of /api/admin/ once resolved; backslashes are
    // read as slashes by URL parsers; control characters and whitespace have no place in a path.
    !/(^|\/)(\.|%2e){1,2}(\/|$|\?|#)/i.test(url.split(/[?#]/)[0]) &&
    !/%2f|%5c|\\/i.test(url.split(/[?#]/)[0]) &&
    !/[\s\u0000-\u001f\u007f]/.test(url);
  if (!ok) throw new AdminApiUrlError(url);
}
