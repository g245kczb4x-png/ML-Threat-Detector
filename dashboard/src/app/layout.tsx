import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Agentic Deception Command Center | SIEM Live threat Feed',
  description: 'Real-time security information and event management (SIEM) dashboard for monitoring intelligent deception honeypot sessions, probes, and exploitation attempts.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
      </head>
      <body className="font-sans antialiased bg-slate-950 text-slate-100 selection:bg-red-500/30 selection:text-red-200">
        {children}
      </body>
    </html>
  );
}
