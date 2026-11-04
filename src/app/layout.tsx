import type { Metadata } from 'next';
import './globals.css';
import { THEME_BOOT_SCRIPT } from '@/components/shell/portalClient';

export const metadata: Metadata = {
  title: 'Salesforce MCP · Admin Control Plane',
  description:
    'Enterprise Model Context Protocol (MCP) Governance & Policy Control Plane for Microsoft Copilot Studio, Okta SSO, and Salesforce REST API.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        {/* Sets data-theme before the first paint (stored choice, else the system's). */}
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="antialiased selection:bg-sky-500/25 selection:text-sky-200">
        {children}
      </body>
    </html>
  );
}
