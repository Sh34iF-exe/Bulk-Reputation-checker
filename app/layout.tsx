import type { Metadata } from "next";
import { IBM_Plex_Mono, Manrope } from "next/font/google";
import "./globals.css";

const manrope = Manrope({ variable: "--font-manrope", subsets: ["latin"] });
const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "IndicatorForge — IOC Analysis Toolkit",
  description:
    "Analyze IP addresses, file hashes, and URLs; manage a local intelligence database; and defang or refang indicators safely.",
  applicationName: "IndicatorForge",
  keywords: ["IOC analysis", "IP reputation", "hash analysis", "URL analysis", "defang", "refang"],
  openGraph: {
    title: "IndicatorForge — IOC Analysis Toolkit",
    description: "Bulk IOC analysis, local intelligence storage, and safe indicator transformation.",
    type: "website",
  },
  twitter: {
    card: "summary",
    title: "IndicatorForge — IOC Analysis Toolkit",
    description: "Bulk IOC analysis, local intelligence storage, and safe indicator transformation.",
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <body className={`${manrope.variable} ${plexMono.variable}`}>{children}</body>
    </html>
  );
}
