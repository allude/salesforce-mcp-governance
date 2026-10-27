import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Salesforce MCP Governance & Admin Panel | Microsoft Copilot Studio',
  description:
    'Enterprise Model Context Protocol (MCP) Governance Panel for Microsoft Copilot Studio, Okta SSO, and Salesforce REST API.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-slate-50 text-slate-900 antialiased selection:bg-indigo-100 selection:text-indigo-900">
        {children}
      </body>
    </html>
  );
}
