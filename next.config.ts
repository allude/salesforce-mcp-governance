import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  async rewrites() {
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
    ];
  },
};

export default nextConfig;
