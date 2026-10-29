import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        // Portal pages only; proxied backend responses keep the backend's own headers.
        source: '/((?!mcp|api/admin|auth/okta|\\.well-known|docs|healthz).*)',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          {
            key: 'Content-Security-Policy',
            value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
          },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
        ],
      },
    ];
  },
  async rewrites() {
    // Read when the rewrites are built: at `next dev` startup, and at `next build` for `next start`.
    const backendUrl = process.env.MCP_BACKEND_URL || 'http://localhost:3001';
    return [
      {
        source: '/mcp',
        destination: `${backendUrl}/mcp`,
      },
      {
        source: '/.well-known/:path*',
        destination: `${backendUrl}/.well-known/:path*`,
      },
      {
        source: '/api/admin/:path*',
        destination: `${backendUrl}/api/admin/:path*`,
      },
      {
        source: '/auth/okta/:path*',
        destination: `${backendUrl}/auth/okta/:path*`,
      },
      {
        source: '/healthz',
        destination: `${backendUrl}/healthz`,
      },
      {
        // OAuth resource metadata points `resource_documentation` here
        source: '/docs/:path*',
        destination: `${backendUrl}/docs/:path*`,
      },
    ];
  },
};

export default nextConfig;
