"use client";

import { useEffect, useMemo, useState } from "react";

type Mode = "ip" | "hash";
type View = "analyze" | "cache" | "about";
type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

type AnalysisResult = {
  indicator: string;
  type: Mode;
  valid: boolean;
  verdict: Verdict;
  score: number | null;
  malicious: number | null;
  suspicious: number | null;
  harmless: number | null;
  provider: string;
  providerStatus: "live" | "partial" | "unavailable" | "error";
  country?: string;
  city?: string;
  network?: string;
  organization?: string;
  fileType?: string;
  fileName?: string;
  lastAnalysis?: string;
  note?: string;
  analyzedAt: string;
};

const IP_SAMPLES = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"];
const HASH_SAMPLES = [
  "44d88612fea8a8f36de82e1278abb02f",
  "3395856ce81f2b7382dee72602f798b642f14140",
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
];

function splitIndicators(value: string) {
  return value
    .split(/[\n,;\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function dedupe(values: string[]) {
  return [...new Set(values.map((value) => value.toLowerCase()))];
}

function verdictLabel(verdict: Verdict) {
  return verdict.charAt(0).toUpperCase() + verdict.slice(1);
}

function formatDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat("en", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }).format(date);
}

function escapeCsv(value: unknown) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("ip");
  const [view, setView] = useState<View>("analyze");
  const [input, setInput] = useState("");
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [cache, setCache] = useState<Record<Mode, AnalysisResult[]>>({ ip: [], hash: [] });
  const [filter, setFilter] = useState<"all" | Verdict>("all");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [dark, setDark] = useState(false);
  const [notice, setNotice] = useState("");

  useEffect(() => {
    try {
      const stored = localStorage.getItem("signalscope-cache-v1");
      if (stored) setCache(JSON.parse(stored));
      setDark(localStorage.getItem("signalscope-theme") === "dark");
    } catch {
      // Local storage is an enhancement; analysis remains available without it.
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    try {
      localStorage.setItem("signalscope-theme", dark ? "dark" : "light");
    } catch {}
  }, [dark]);

  const indicatorCount = splitIndicators(input).length;
  const activeResults = view === "cache" ? cache[mode] : results;

  const filteredResults = useMemo(() => {
    return activeResults.filter((result) => {
      const matchesFilter = filter === "all" || result.verdict === filter;
      const haystack = [
        result.indicator,
        result.country,
        result.city,
        result.network,
        result.organization,
        result.fileName,
        result.fileType,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return matchesFilter && haystack.includes(query.toLowerCase());
    });
  }, [activeResults, filter, query]);

  const stats = useMemo(
    () => ({
      total: activeResults.length,
      flagged: activeResults.filter((result) =>
        ["malicious", "suspicious"].includes(result.verdict),
      ).length,
      clean: activeResults.filter((result) => result.verdict === "clean").length,
      unknown: activeResults.filter((result) => result.verdict === "unknown").length,
    }),
    [activeResults],
  );

  function changeMode(next: Mode) {
    setMode(next);
    setInput("");
    setResults([]);
    setError("");
    setFilter("all");
  }

  function showNotice(message: string) {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 2200);
  }

  function addSamples() {
    setInput((mode === "ip" ? IP_SAMPLES : HASH_SAMPLES).join("\n"));
    showNotice("Sample indicators added");
  }

  function removeDuplicates() {
    const unique = dedupe(splitIndicators(input));
    setInput(unique.join("\n"));
    showNotice(`${unique.length} unique indicator${unique.length === 1 ? "" : "s"}`);
  }

  async function analyze() {
    const indicators = dedupe(splitIndicators(input));
    if (!indicators.length) {
      setError(`Add at least one ${mode === "ip" ? "IP address" : "file hash"}.`);
      return;
    }
    if (indicators.length > 50) {
      setError("This project limits each run to 50 indicators to protect provider quotas.");
      return;
    }

    setBusy(true);
    setError("");
    setView("analyze");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: mode, indicators }),
      });
      const payload = (await response.json()) as {
        results?: AnalysisResult[];
        error?: string;
      };
      if (!response.ok || !payload.results) {
        throw new Error(payload.error || "The analysis service is unavailable.");
      }

      setResults(payload.results);
      setCache((current) => {
        const merged = new Map<string, AnalysisResult>();
        [...payload.results!, ...current[mode]].forEach((item) =>
          merged.set(item.indicator.toLowerCase(), item),
        );
        const next = { ...current, [mode]: [...merged.values()].slice(0, 250) };
        try {
          localStorage.setItem("signalscope-cache-v1", JSON.stringify(next));
        } catch {}
        return next;
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  function clearCache(target: Mode | "all") {
    const next =
      target === "all"
        ? { ip: [], hash: [] }
        : { ...cache, [target]: [] };
    setCache(next);
    localStorage.setItem("signalscope-cache-v1", JSON.stringify(next));
    showNotice(target === "all" ? "All local results cleared" : `${target.toUpperCase()} cache cleared`);
  }

  function exportCsv() {
    if (!filteredResults.length) return;
    const headings = [
      "indicator",
      "verdict",
      "score",
      "malicious",
      "suspicious",
      "harmless",
      "country",
      "city",
      "network",
      "organization",
      "file_type",
      "file_name",
      "provider",
      "provider_status",
      "analyzed_at",
    ];
    const rows = filteredResults.map((item) =>
      [
        item.indicator,
        item.verdict,
        item.score,
        item.malicious,
        item.suspicious,
        item.harmless,
        item.country,
        item.city,
        item.network,
        item.organization,
        item.fileType,
        item.fileName,
        item.provider,
        item.providerStatus,
        item.analyzedAt,
      ]
        .map(escapeCsv)
        .join(","),
    );
    const blob = new Blob([[headings.join(","), ...rows].join("\n")], {
      type: "text/csv;charset=utf-8",
    });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `signalscope-${mode}-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  async function copyResults() {
    if (!filteredResults.length) return;
    await navigator.clipboard.writeText(
      filteredResults
        .map((result) => `${result.indicator}\t${result.verdict}\t${result.score ?? "n/a"}`)
        .join("\n"),
    );
    showNotice("Visible results copied");
  }

  const emptyLabel =
    view === "cache"
      ? "No cached lookups on this device yet."
      : "Run an analysis to see reputation signals here.";

  return (
    <div className="site-shell">
      <header className="topbar">
        <button className="brand" onClick={() => setView("analyze")} aria-label="SignalScope home">
          <BrandMark />
          <span>
            <strong>SignalScope</strong>
            <small>Threat intelligence workbench</small>
          </span>
        </button>

        <nav className="primary-nav" aria-label="Primary navigation">
          <button className={view === "analyze" ? "active" : ""} onClick={() => setView("analyze")}>
            Analyze
          </button>
          <button className={view === "cache" ? "active" : ""} onClick={() => setView("cache")}>
            Local cache <span>{cache.ip.length + cache.hash.length}</span>
          </button>
          <button className={view === "about" ? "active" : ""} onClick={() => setView("about")}>
            How it works
          </button>
        </nav>

        <div className="header-actions">
          <span className="privacy-chip"><i /> Keys stay server-side</span>
          <button className="theme-button" onClick={() => setDark((value) => !value)} aria-label="Toggle color theme">
            {dark ? "☀" : "◐"}
          </button>
        </div>
      </header>

      <main>
        {view === "about" ? (
          <section className="about-view">
            <div className="eyebrow"><span /> PRODUCT NOTES</div>
            <h1>From raw indicators to a triage-ready shortlist.</h1>
            <p className="about-lede">
              SignalScope is a portfolio-grade threat intelligence interface inspired by the workflow—not the visual design—of bulk reputation tools. It validates, enriches, filters, caches, and exports indicators without exposing provider credentials in the browser.
            </p>
            <div className="process-grid">
              {[
                ["01", "Normalize", "Split mixed input, remove duplicates, and validate IPv4, IPv6, MD5, SHA-1, and SHA-256 indicators."],
                ["02", "Enrich", "Add public geolocation and, when configured, retrieve live VirusTotal and AbuseIPDB reputation signals."],
                ["03", "Triage", "Rank by verdict, filter noisy datasets, inspect evidence, and export the current view as CSV."],
                ["04", "Recall", "Keep recent results in this browser only, so repeat investigations are quick and easy to clear."],
              ].map(([number, title, copy]) => (
                <article key={number}>
                  <span>{number}</span>
                  <h2>{title}</h2>
                  <p>{copy}</p>
                </article>
              ))}
            </div>
            <div className="provider-note">
              <div>
                <span className="signal-orb" />
                <strong>Provider-aware by design</strong>
              </div>
              <p>
                If a private reputation key is not configured, the app labels reputation as unavailable and still returns validation plus public IP enrichment. It never invents a “clean” verdict from missing data.
              </p>
            </div>
          </section>
        ) : (
          <>
            <section className="hero-workbench">
              <div className="hero-copy">
                <div className="eyebrow"><span /> BULK REPUTATION ANALYSIS</div>
                <h1>Investigate the signal.<br /><em>Lose the noise.</em></h1>
                <p>
                  Turn lists of IP addresses and file hashes into a clear, exportable triage view—without checking indicators one by one.
                </p>
                <div className="hero-proof">
                  <div><strong>50</strong><span>indicators / run</span></div>
                  <div><strong>3</strong><span>enrichment layers</span></div>
                  <div><strong>0</strong><span>keys in the browser</span></div>
                </div>
              </div>

              <div className="input-card" id="workbench">
                <div className="mode-tabs" role="tablist" aria-label="Indicator type">
                  <button role="tab" aria-selected={mode === "ip"} className={mode === "ip" ? "active" : ""} onClick={() => changeMode("ip")}>
                    <span className="tab-icon">⌖</span> IP addresses
                  </button>
                  <button role="tab" aria-selected={mode === "hash"} className={mode === "hash" ? "active" : ""} onClick={() => changeMode("hash")}>
                    <span className="tab-icon">#</span> File hashes
                  </button>
                </div>

                {view === "cache" ? (
                  <div className="cache-intro">
                    <div>
                      <span className="cache-symbol">↺</span>
                      <div>
                        <strong>Device-local investigation cache</strong>
                        <p>Results are stored in this browser, never in a shared account.</p>
                      </div>
                    </div>
                    <div className="cache-actions">
                      <button onClick={() => clearCache(mode)}>Clear {mode.toUpperCase()}</button>
                      <button className="danger" onClick={() => clearCache("all")}>Clear all</button>
                    </div>
                  </div>
                ) : (
                  <>
                    <label htmlFor="indicator-input">
                      {mode === "ip" ? "Paste IP addresses" : "Paste MD5, SHA-1, or SHA-256 hashes"}
                      <span>{indicatorCount}/50</span>
                    </label>
                    <textarea
                      id="indicator-input"
                      value={input}
                      onChange={(event) => setInput(event.target.value)}
                      placeholder={mode === "ip" ? "8.8.8.8\n1.1.1.1\n2001:4860:4860::8888" : "44d88612fea8a8f36de82e1278abb02f\n275a021bbfb6489e..."}
                      spellCheck={false}
                    />
                    <div className="input-tools">
                      <div>
                        <button onClick={addSamples}>Use sample</button>
                        <button onClick={removeDuplicates}>Deduplicate</button>
                        <button onClick={() => setInput("")}>Clear</button>
                      </div>
                      <span>One per line, or separated by commas</span>
                    </div>
                    {error && <div className="error-banner" role="alert">{error}</div>}
                    <button className="analyze-button" onClick={analyze} disabled={busy}>
                      <span>{busy ? "Analyzing indicators…" : `Analyze ${indicatorCount || ""} ${mode === "ip" ? "IPs" : "hashes"}`}</span>
                      <b>{busy ? "···" : "↗"}</b>
                    </button>
                  </>
                )}
              </div>
            </section>

            <section className="results-section" aria-label="Analysis results">
              <div className="results-heading">
                <div>
                  <span className="section-index">02 / RESULTS</span>
                  <h2>{view === "cache" ? "Local intelligence cache" : "Investigation summary"}</h2>
                </div>
                <div className="results-actions">
                  <button onClick={copyResults} disabled={!filteredResults.length}>Copy view</button>
                  <button className="export" onClick={exportCsv} disabled={!filteredResults.length}>Export CSV ↓</button>
                </div>
              </div>

              <div className="metric-strip">
                <div><span>Total analyzed</span><strong>{stats.total}</strong></div>
                <div className="flagged"><span>Needs attention</span><strong>{stats.flagged}</strong></div>
                <div className="clean"><span>Clean</span><strong>{stats.clean}</strong></div>
                <div><span>Unknown</span><strong>{stats.unknown}</strong></div>
              </div>

              <div className="result-toolbar">
                <div className="filter-pills">
                  {(["all", "malicious", "suspicious", "clean", "unknown"] as const).map((item) => (
                    <button key={item} className={filter === item ? "active" : ""} onClick={() => setFilter(item)}>
                      {item === "all" ? "All signals" : verdictLabel(item)}
                    </button>
                  ))}
                </div>
                <label className="search-box">
                  <span>⌕</span>
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter results" aria-label="Filter results" />
                </label>
              </div>

              <div className="result-table-wrap">
                {filteredResults.length ? (
                  <table>
                    <thead>
                      <tr>
                        <th>Indicator</th>
                        <th>Verdict</th>
                        <th>{mode === "ip" ? "Location / network" : "File context"}</th>
                        <th>Detections</th>
                        <th>Source</th>
                        <th>Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredResults.map((result) => (
                        <tr key={`${result.indicator}-${result.analyzedAt}`}>
                          <td>
                            <code>{result.indicator}</code>
                            {!result.valid && <small className="invalid-note">Invalid format</small>}
                          </td>
                          <td>
                            <span className={`verdict ${result.verdict}`}><i />{verdictLabel(result.verdict)}</span>
                            {result.score !== null && <small>{result.score}/100 risk</small>}
                          </td>
                          <td>
                            {mode === "ip" ? (
                              <><strong>{[result.city, result.country].filter(Boolean).join(", ") || "Not available"}</strong><small>{result.organization || result.network || "No public enrichment"}</small></>
                            ) : (
                              <><strong>{result.fileName || result.fileType || "Unknown file"}</strong><small>{result.fileName && result.fileType ? result.fileType : result.note || "No file metadata"}</small></>
                            )}
                          </td>
                          <td>
                            <strong>{result.malicious === null ? "—" : `${result.malicious} malicious`}</strong>
                            <small>{result.harmless === null ? "Reputation unavailable" : `${result.harmless} harmless`}</small>
                          </td>
                          <td>
                            <span className={`provider-status ${result.providerStatus}`}><i />{result.provider}</span>
                            <small>{result.providerStatus === "live" ? "Live response" : result.providerStatus === "partial" ? "Partial enrichment" : "Key not configured"}</small>
                          </td>
                          <td><span>{formatDate(result.lastAnalysis || result.analyzedAt)}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-results">
                    <div className="radar-empty"><span /><span /><i /></div>
                    <strong>{emptyLabel}</strong>
                    <p>{view === "cache" ? "Analyze indicators to build a private, device-local history." : "Paste a list above, use the samples, or switch indicator type."}</p>
                  </div>
                )}
              </div>
            </section>
          </>
        )}
      </main>

      <footer>
        <div><BrandMark /><strong>SignalScope</strong><span>Built as a personal cybersecurity project.</span></div>
        <p>Provider results can change over time. Always verify critical decisions with the original intelligence source.</p>
      </footer>

      {notice && <div className="toast" role="status">✓ {notice}</div>}
    </div>
  );
}
