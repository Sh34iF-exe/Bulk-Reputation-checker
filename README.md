# IndicatorForge

IndicatorForge is a local-first IOC investigation workbench for analyzing IP addresses, file hashes, and URLs in bulk. It combines optional reputation-provider data with local validation, URL heuristics, browser-local history, filtering, charts, CSV export, and a standalone defang/refang converter.

The application is designed to run locally by default. Provider credentials are read by the server-side API route and are never stored in browser local storage.

## Features

- Bulk analysis of IPv4, IPv6, MD5, SHA-1, SHA-256, and URLs
- Optional VirusTotal enrichment for supported IOC types
- Optional AbuseIPDB enrichment for IP addresses
- Public IP geolocation through `ipwho.is`
- Local URL checks for suspicious structural characteristics
- Reverse-chronological Local Database with up to 250 recent records per IOC type
- IOC-type, verdict, and text filters
- Executive charts for verdict distribution, IOC mix, and provider coverage
- CSV export and clipboard copy for the currently filtered results
- Standalone IOC defang/refang converter that does not write to Local Database
- Dark-first theme with a saved light-theme preference
- Responsive desktop, tablet, and mobile navigation
- In-memory provider-response caching and duplicate-request coalescing

## Technology

- TypeScript
- React 19
- Next.js application structure
- Vinext and Vite
- Cloudflare Worker-compatible server runtime
- CSS with responsive breakpoints and theme variables
- Browser `localStorage` for Local Database records and theme preference

## Requirements

- Node.js `22.13.0` or newer
- npm

No separate database, Python runtime, Java runtime, or Docker installation is required for local development.

## Local setup

Clone or download the repository, then open the repository root—the directory containing `package.json`—in VS Code or a terminal.

```bash
git clone <repository-url>
cd <repository-folder>
npm ci
npm run dev
```

Open the local address printed by the terminal. It is normally:

```text
http://localhost:3000
```

If port 3000 is occupied, Vite may select another port. Use the exact URL shown in the terminal.

Press `Ctrl+C` in the terminal to stop the development server.

### Optional provider configuration

The application runs without private provider keys, but reputation results will be limited.

Create a local `.env` file from `.env.example`.

PowerShell:

```powershell
Copy-Item .env.example .env
```

macOS/Linux:

```bash
cp .env.example .env
```

Add the providers you want to use:

```env
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

Restart `npm run dev` after changing `.env`.

## API-key safety

- Real keys belong only in `.env`.
- `.env` files are excluded by `.gitignore`.
- `.env.example` is intentionally committed with empty values.
- Never place a key in `app/page.tsx`, `public/`, CSS, or any variable exposed to client-side code.
- Never commit a real key to Git, even temporarily. Removing it in a later commit does not remove it from repository history.
- If a key is ever committed or published, revoke it at the provider and issue a replacement.

Keeping a key server-side prevents browsers from reading it directly. It does not prevent visitors to a publicly deployed application from using the application endpoint and consuming the provider quota. Add authentication, request throttling, provider quotas, and abuse monitoring before exposing the analysis API publicly.

## Data and caching

### Local Database

Analysis history is stored in the current browser under:

```text
indicatorforge-db-v1
```

Records are stored newest-first and are limited to 250 recent entries per IOC type. They do not automatically synchronize between browsers, browser profiles, or computers. Clearing browser storage removes the saved records.

The IOC Converter operates separately. Converter input is not sent to the analysis API and is not written to Local Database.

### Provider-response cache

The server keeps an in-memory cache to avoid repeating provider calls for the same IOC and configured-provider combination:

- Successful, partial, and unavailable results: 15 minutes
- Provider errors: 60 seconds
- Maximum entries: 1,500
- Concurrent duplicate requests share the same in-flight analysis

The cache is process-local. It is cleared whenever the development server restarts and is not guaranteed to persist across serverless cold starts or multiple production instances.

## Project structure

```text
.
├── .openai/
│   └── hosting.json          # Required local Sites/Vinext configuration
├── app/
│   ├── api/analyze/route.ts  # Validation, provider calls, and response cache
│   ├── globals.css           # Themes, layout, and responsive styling
│   ├── layout.tsx            # Fonts and document metadata
│   └── page.tsx              # Interface, navigation, state, DB, and converter
├── build/
│   └── sites-vite-plugin.ts  # Required build integration
├── public/                   # Static assets
├── tests/                    # Automated source/build checks
├── worker/
│   └── index.ts              # Worker entry point
├── .env.example              # Safe provider-variable template
├── package.json              # Scripts and pinned dependency versions
├── package-lock.json         # Reproducible npm dependency tree
└── vite.config.ts            # Vinext/Vite/Worker configuration
```

Do not edit generated files inside `node_modules/`, `.vinext/`, `.wrangler/`, or `dist/`.

## Dependency and audit warnings

`npm ci` may display deprecation or audit warnings from transitive development dependencies. Do not run:

```text
npm audit fix --force
```

The forced command may replace the pinned React, Vinext, Vite, or Cloudflare packages with incompatible versions and cause import failures.

To inspect production-relevant findings:

```bash
npm audit --omit=dev
```

Dependency upgrades should be performed deliberately and followed by `npm run lint` and `npm test`. If a forced audit update has already changed the project, restore the original `package.json` and `package-lock.json`, remove `node_modules`, and run `npm ci`.

## Troubleshooting

### Import errors after `npm audit fix --force`

Restore the repository versions of `package.json` and `package-lock.json`, then run:

```powershell
Remove-Item -Recurse -Force node_modules
Remove-Item -Recurse -Force .vinext, dist, .wrangler -ErrorAction SilentlyContinue
npm cache verify
npm ci
npm run dev
```

### Provider results are partial or unavailable

Confirm that `.env` contains the expected provider variable, restart the development server, and verify that the provider account and quota are active. Missing provider data is intentionally reported as partial or unavailable rather than being treated as a clean verdict.

## Responsible use

IndicatorForge is a triage aid, not a substitute for professional incident-response judgment. Reputation providers can return incomplete, stale, or conflicting results. Validate important findings with additional evidence before making containment or enforcement decisions.
