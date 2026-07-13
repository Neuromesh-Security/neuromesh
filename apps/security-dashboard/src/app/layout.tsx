import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Neuromesh Security Dashboard",
  description:
    "Enterprise Edition command center for Zero Trust and eBPF runtime security.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
