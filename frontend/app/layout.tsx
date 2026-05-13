import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Decrypt Me",
  description: "A local browser decryption helper for common encrypted payloads."
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
