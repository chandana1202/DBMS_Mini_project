import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Supply-Chain Vulnerability DB",
  description: "Tracks packages, CVEs and how they reach your projects",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
