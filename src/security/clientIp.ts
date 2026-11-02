import net from 'node:net';
import type { Request } from 'express';

/**
 * The rate-limit key for a client address. IPv6 clients usually control a whole /64, so keying on
 * the full address would give them a fresh bucket per address; IPv6 is keyed on its /64 instead.
 * IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) are keyed as the plain IPv4 address.
 */
export function rateLimitIpKey(ip: string | undefined): string {
  const address = (ip || '').split('%')[0];
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(address);
  if (mapped) return mapped[1];
  if (!net.isIPv6(address)) return address;
  return `${expandIPv6(address).slice(0, 4).join(':')}::/64`;
}

function expandIPv6(address: string): string[] {
  let text = address.toLowerCase();
  // An embedded IPv4 tail (::1.2.3.4) is two groups.
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number);
    text = `${text.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = text.split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail !== undefined && tail ? tail.split(':') : [];
  const missing = tail === undefined ? 0 : 8 - headGroups.length - tailGroups.length;
  return [...headGroups, ...Array(missing).fill('0'), ...tailGroups].map((group) => group.replace(/^0+(?=.)/, ''));
}

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

/**
 * Whether req.ip tells clients apart. Behind the portal's Next.js proxy with TRUST_PROXY off, every
 * request arrives from loopback, so req.ip is the same for everyone; a per-IP limit there would be
 * one limit shared by all callers, which anyone could use up. That only holds when the proxy is
 * not trusted and the connection itself comes from loopback.
 */
export function clientIpsAreDistinguishable(req: Request, trustProxy: boolean | number | string): boolean {
  const trusted = trustProxy !== false && trustProxy !== 0;
  if (trusted) return true;
  return !LOOPBACK.has(req.socket?.remoteAddress || '');
}
