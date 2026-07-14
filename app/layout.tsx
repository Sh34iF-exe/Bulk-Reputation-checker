import type { Metadata } from "next";
import { IBM_Plex_Mono, Manrope } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const manrope = Manrope({
  variable: "--font-manrope",
  subsets: ["latin"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") || requestHeaders.get("host") || "localhost:3000";
  const protocol = requestHeaders.get("x-forwarded-proto") || (host.startsWith("localhost") ? "http" : "https");
  const socialImage = `${protocol}://${host}/og.png`;

  return {
    title: "SignalScope — Bulk Threat Intelligence Workbench",
    description:
      "Analyze IP addresses and file hashes in bulk, triage reputation signals, cache results locally, and export investigation-ready data.",
    applicationName: "SignalScope",
    keywords: ["threat intelligence", "IP reputation", "hash analysis", "cybersecurity"],
    openGraph: {
      title: "SignalScope — Investigate the signal. Lose the noise.",
      description: "A focused bulk IP and file-hash reputation workbench.",
      type: "website",
      images: [{ url: socialImage, width: 1792, height: 912, alt: "SignalScope threat intelligence radar" }],
    },
    twitter: {
      card: "summary_large_image",
      title: "SignalScope — Bulk Threat Intelligence Workbench",
      description: "A focused bulk IP and file-hash reputation workbench.",
      images: [socialImage],
    },
  };
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${manrope.variable} ${plexMono.variable}`}>{children}</body>
    </html>
  );
}
