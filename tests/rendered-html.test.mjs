import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const pageUrl = new URL("../app/page.tsx", import.meta.url);
const cssUrl = new URL("../app/globals.css", import.meta.url);
const routeUrl = new URL("../app/api/analyze/route.ts", import.meta.url);
const layoutUrl = new URL("../app/layout.tsx", import.meta.url);

test("keeps application views mounted and isolates result pipelines", async () => {
  const page = await readFile(pageUrl, "utf8");

  assert.match(page, /className="view-panel analyze-view" hidden=\{view !== "analyze"\}/);
  assert.match(page, /className="view-panel database-view" hidden=\{view !== "database"\}/);
  assert.match(page, /className="view-panel sanitizer-view" hidden=\{view !== "sanitizer"\}/);
  assert.match(page, /className="view-panel about-view" hidden=\{view !== "about"\}/);
  assert.match(page, /analysisFilteredResults/);
  assert.match(page, /databaseFilteredResults/);
  assert.match(page, /document\.documentElement\.scrollTop = 0/);
  assert.doesNotMatch(page, /\{view === "(?:analyze|database|sanitizer|about)" && \(/);
});

test("provides accessible navigation on mobile and tablet layouts", async () => {
  const [page, css] = await Promise.all([
    readFile(pageUrl, "utf8"),
    readFile(cssUrl, "utf8"),
  ]);

  assert.match(page, /className={`mobile-menu-button/);
  assert.match(page, /aria-controls="mobile-navigation"/);
  assert.match(page, /aria-expanded={mobileMenuOpen}/);
  assert.match(page, /id="mobile-navigation"/);
  assert.match(page, /aria-label="Mobile navigation"/);
  assert.match(page, /if \(event\.key === "Escape"\) setMobileMenuOpen\(false\)/);
  assert.match(css, /@media \(max-width: 1120px\)[\s\S]*\.mobile-menu-button \{ display: grid; \}/);
  assert.match(css, /\.mobile-navigation:not\(\[hidden\]\) \{ display: grid; \}/);
  assert.doesNotMatch(css, /body\s*\{[^}]*min-width:\s*320px/s);
  assert.match(css, /html\s*\{[^}]*overflow-x:\s*clip/s);
  assert.match(css, /\.site-shell\s*\{[^}]*min-width:\s*0[^}]*overflow-x:\s*clip/s);
  assert.match(css, /width:\s*min\(350px, 100%\)/);
  assert.match(css, /@media \(max-width: 360px\)[\s\S]*\.brand > span:last-child \{ display: none; \}/);
});

test("caches repeated IOC analysis and labels cached responses", async () => {
  const [page, route] = await Promise.all([
    readFile(pageUrl, "utf8"),
    readFile(routeUrl, "utf8"),
  ]);

  assert.match(route, /RESULT_CACHE_TTL_MS = 15 \* 60 \* 1000/);
  assert.match(route, /inFlightAnalyses/);
  assert.match(route, /analyzeIndicatorCached/);
  assert.match(route, /cacheHit: true/);
  assert.match(route, /ttlSeconds/);
  assert.match(page, /Cached response/);
});

test("uses readable supporting text and finished metadata", async () => {
  const [css, layout] = await Promise.all([
    readFile(cssUrl, "utf8"),
    readFile(layoutUrl, "utf8"),
  ]);

  assert.doesNotMatch(css, /font-size:\s*[789]px\b/);
  assert.doesNotMatch(css, /font:\s*[^;]*\s[789]px\//);
  assert.match(css, /\.converter-pane textarea[^}]*font:\s*500 12px\/1\.8/s);
  assert.match(css, /td code[^}]*500 11px\/1\.5/s);
  assert.match(layout, /IndicatorForge/);
  assert.doesNotMatch(layout, /Starter Project|codex-preview|Your site is taking shape/);
});
