/**
 * Reads the bearer token from an Authorization header. The rate limiters and the /mcp handler both
 * use this, so they always agree on whether a request carries a token and which one.
 *
 * RFC 6750 separates the scheme from the token with spaces only. Anything else (a tab, a
 * non-breaking space, no separator) or a blank token counts as no token at all.
 */
export function parseBearerToken(header: unknown): string {
  if (typeof header !== 'string') return '';
  const match = /^bearer +(.*)$/i.exec(header);
  return match ? match[1].replace(/^ +| +$/g, '') : '';
}

/**
 * Salesforce access tokens are printable ASCII with no spaces (`00D...!AQ...`). Anything else
 * cannot be valid, so it is refused without sending it to Salesforce.
 */
export function isPlausibleBearerToken(token: string): boolean {
  return token.length <= 4096 && /^[\x21-\x7e]+$/.test(token);
}
