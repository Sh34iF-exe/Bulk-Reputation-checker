# IndicatorForge

IndicatorForge is a local-first IOC analysis toolkit for bulk IP, file-hash, and URL investigation. It includes a browser-local intelligence database and a standalone defang/refang converter.

## Features

- Bulk IPv4, IPv6, MD5, SHA-1, SHA-256, and URL analysis
- Optional VirusTotal and AbuseIPDB enrichment
- Public IP geolocation and local URL-structure checks
- Reverse-chronological browser-local database
- Type, verdict, and text filters with CSV export
- Executive charts for verdicts, indicator mix, and provider coverage
- Separate IOC converter for defanging and refanging values
- Dark-first interface with a saved light-mode preference

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Validate the build

```bash
npm run build
```

## Optional provider keys

Copy `.env.example` to `.env` and configure the providers you want to use:

```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

Without these keys, IndicatorForge still validates indicators, enriches public IP information, and evaluates structural URL signals. Missing reputation data is labelled as partial or unavailable.

## Local data

Analysis history is stored in browser local storage under `indicatorforge-db-v1`. The IOC Converter does not send its input to the analysis API and does not write to Local Database.

## Project structure

- `app/page.tsx` — application interface and local state
- `app/globals.css` — themes and responsive styling
- `app/api/analyze/route.ts` — analysis and provider integration
- `app/layout.tsx` — document metadata and fonts
