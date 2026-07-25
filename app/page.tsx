"use client";

import { useEffect, useMemo, useState } from "react";

type Mode = "ip" | "hash" | "url";
type View = "analyze" | "database" | "sanitizer" | "about";
type Verdict = "malicious" | "suspicious" | "clean" | "unknown";
type DbFilter = "all" | Mode;

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
  urlDomain?: string;
  urlProtocol?: string;
  urlSignals?: string[];
  lastAnalysis?: string;
  note?: string;
  cacheHit?: boolean;
  analyzedAt: string;
};

type CacheStore = Record<Mode, AnalysisResult[]>;

const EMPTY_CACHE: CacheStore = { ip: [], hash: [], url: [] };
const EMPTY_INPUTS: Record<Mode, string> = { ip: "", hash: "", url: "" };
const EMPTY_RESULTS: Record<Mode, AnalysisResult[]> = { ip: [], hash: [], url: [] };
const SAMPLES: Record<Mode, string[]> = {
  ip: ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"],
  hash: [
    "44d88612fea8a8f36de82e1278abb02f",
    "3395856ce81f2b7382dee72602f798b642f14140",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  ],
  url: [
    "https://example.com/account/login",
    "http://198.51.100.14/verify",
    "https://xn--paypa1-l2c.example/reset-password",
  ],
};

const MODE_META: Record<Mode, { label: string; short: string; icon: string; input: string; placeholder: string }> = {
  ip: {
    label: "IP addresses",
    short: "IP",
    icon: "⌖",
    input: "Paste IPv4 or IPv6 addresses",
    placeholder: "8.8.8.8\n1.1.1.1\n2001:4860:4860::8888",
  },
  hash: {
    label: "File hashes",
    short: "Hash",
    icon: "#",
    input: "Paste MD5, SHA-1, or SHA-256 hashes",
    placeholder: "44d88612fea8a8f36de82e1278abb02f\n275a021bbfb6489e...",
  },
  url: {
    label: "URLs",
    short: "URL",
    icon: "↗",
    input: "Paste complete URLs or domains",
    placeholder: "https://example.com/login\nhttp://198.51.100.14/verify",
  },
};

function splitIndicators(value: string) {
  return value
    .split(/[\n,;\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function dedupe(values: string[], preserveCase = false) {
  const unique = new Map<string, string>();
  values.forEach((value) => unique.set(preserveCase ? value : value.toLowerCase(), preserveCase ? value : value.toLowerCase()));
  return [...unique.values()];
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

function normalizeCache(value: unknown): CacheStore {
  if (!value || typeof value !== "object") return EMPTY_CACHE;
  const candidate = value as Partial<CacheStore>;
  return {
    ip: Array.isArray(candidate.ip) ? candidate.ip : [],
    hash: Array.isArray(candidate.hash) ? candidate.hash : [],
    url: Array.isArray(candidate.url) ? candidate.url : [],
  };
}

function newestFirst(values: AnalysisResult[]) {
  return [...values].sort((a, b) => +new Date(b.analyzedAt) - +new Date(a.analyzedAt));
}

function defangIocs(value: string) {
  return value
    .replace(/hxxps?:\/\//gi, (match) => match.toLowerCase())
    .replace(/https:\/\//gi, "hxxps://")
    .replace(/http:\/\//gi, "hxxp://")
    .replace(/(?<!\[)\.(?!\])/g, "[.]")
    .replace(/:(?=\d{2,5}(?:\/|\s|$))/g, "[:]");
}

function refangIocs(value: string) {
  return value
    .replace(/hxxps:\/\//gi, "https://")
    .replace(/hxxp:\/\//gi, "http://")
    .replace(/\[(?:\.)\]|\((?:\.)\)|\{(?:\.)\}/g, ".")
    .replace(/\[(?::)\]/g, ":");
}

function classifyIoc(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "empty";
  if (/^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64})$/i.test(trimmed)) return "hash";
  if (/^(?:\d{1,3}\[?\.\]?){3}\d{1,3}(?::|\[:\])?\d*$/i.test(trimmed)) return "ip";
  if (/^(?:hxxps?|https?):\/\//i.test(trimmed)) return "url";
  if (/^[^\s@]+@[^\s@]+$/i.test(trimmed)) return "email";
  if (/^[a-z\d-]+(?:\[?\.\]?[a-z\d-]+)+$/i.test(trimmed)) return "domain";
  return "other";
}

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <i />
    </span>
  );
}

function TypeBadge({ type }: { type: Mode }) {
  return <span className={`type-badge ${type}`}>{MODE_META[type].short}</span>;
}

function ContextCell({ result }: { result: AnalysisResult }) {
  if (result.type === "ip") {
    return (
      <>
        <strong>{[result.city, result.country].filter(Boolean).join(", ") || "Not available"}</strong>
        <small>{result.organization || result.network || result.note || "No public enrichment"}</small>
      </>
    );
  }
  if (result.type === "hash") {
    return (
      <>
        <strong>{result.fileName || result.fileType || "Unknown file"}</strong>
        <small>{result.fileName && result.fileType ? result.fileType : result.note || "No file metadata"}</small>
      </>
    );
  }
  return (
    <>
      <strong>{result.urlDomain || "Unknown host"}</strong>
      <small>{result.urlSignals?.length ? result.urlSignals.join(" · ") : result.note || result.urlProtocol || "No structural alerts"}</small>
    </>
  );
}

function ResultsTable({ results = [], database = false }: { results?: AnalysisResult[]; database?: boolean }) {
  const safeResults = Array.isArray(results) ? results : [];
  return (
    <div className="result-table-wrap">
      {safeResults.length ? (
        <table>
          <thead>
            <tr>
              {database && <th>Type</th>}
              <th>Indicator</th>
              <th>Verdict</th>
              <th>Context</th>
              <th>Detections</th>
              <th>Source</th>
              <th>Updated</th>
            </tr>
          </thead>
          <tbody>
            {safeResults.map((result) => (
              <tr key={`${result.type}-${result.indicator}-${result.analyzedAt}`}>
                {database && <td><TypeBadge type={result.type} /></td>}
                <td>
                  <code>{result.indicator}</code>
                  {!result.valid && <small className="invalid-note">Invalid format</small>}
                </td>
                <td>
                  <span className={`verdict ${result.verdict}`}><i />{verdictLabel(result.verdict)}</span>
                  {result.score !== null && <small>{result.score}/100 risk</small>}
                </td>
                <td><ContextCell result={result} /></td>
                <td>
                  <strong>{result.malicious === null ? "—" : `${result.malicious} malicious`}</strong>
                  <small>{result.harmless === null ? "Reputation unavailable" : `${result.harmless} harmless`}</small>
                </td>
                <td>
                  <span className={`provider-status ${result.providerStatus}`}><i />{result.provider}</span>
                  <small>{result.cacheHit ? "Cached response" : result.providerStatus === "live" ? "Live response" : result.providerStatus === "partial" ? "Partial intelligence" : result.providerStatus === "error" ? "Provider error" : "Key not configured"}</small>
                </td>
                <td><span>{formatDate(result.lastAnalysis || result.analyzedAt)}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <div className="empty-results">
          <div className="radar-empty"><span /><span /><i /></div>
          <strong>{database ? "No records match this database view." : "Run an analysis to see reputation signals here."}</strong>
          <p>{database ? "Change the type or verdict filters, or analyze new indicators." : "Paste a list above, use the samples, or switch indicator type."}</p>
        </div>
      )}
    </div>
  );
}

function FilterToolbar({
  verdict,
  query,
  onVerdictChange,
  onQueryChange,
}: {
  verdict: "all" | Verdict;
  query: string;
  onVerdictChange: (value: "all" | Verdict) => void;
  onQueryChange: (value: string) => void;
}) {
  return (
    <div className="result-toolbar">
      <div className="filter-pills" aria-label="Verdict filter">
        {(["all", "malicious", "suspicious", "clean", "unknown"] as const).map((item) => (
          <button key={item} className={verdict === item ? "active" : ""} onClick={() => onVerdictChange(item)}>
            {item === "all" ? "All verdicts" : verdictLabel(item)}
          </button>
        ))}
      </div>
      <label className="search-box">
        <span>⌕</span>
        <input value={query} onChange={(event) => onQueryChange(event.target.value)} placeholder="Search indicators or context" aria-label="Search results" />
      </label>
    </div>
  );
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("ip");
  const [view, setView] = useState<View>("analyze");
  const [inputs, setInputs] = useState<Record<Mode, string>>(EMPTY_INPUTS);
  const [analysisResults, setAnalysisResults] = useState<Record<Mode, AnalysisResult[]>>(EMPTY_RESULTS);
  const [cache, setCache] = useState<CacheStore>(EMPTY_CACHE);
  const [dbType, setDbType] = useState<DbFilter>("all");
  const [analysisVerdict, setAnalysisVerdict] = useState<"all" | Verdict>("all");
  const [analysisQuery, setAnalysisQuery] = useState("");
  const [dbVerdict, setDbVerdict] = useState<"all" | Verdict>("all");
  const [dbQuery, setDbQuery] = useState("");
  const [busyMode, setBusyMode] = useState<Mode | null>(null);
  const [error, setError] = useState("");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [notice, setNotice] = useState("");
  const [clearIntent, setClearIntent] = useState<DbFilter | null>(null);
  const [dashboardOpen, setDashboardOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [sanitizerInput, setSanitizerInput] = useState("");
  const [sanitizerOutput, setSanitizerOutput] = useState("");
  const [sanitizerMode, setSanitizerMode] = useState<"defang" | "refang">("defang");

  useEffect(() => {
    const hydrationFrame = window.requestAnimationFrame(() => {
      try {
        const current = localStorage.getItem("indicatorforge-db-v1");
        const prior = localStorage.getItem("signalscope-db-v2");
        const legacy = localStorage.getItem("signalscope-cache-v1");
        const stored = current || prior || legacy;
        if (stored) {
          const migrated = normalizeCache(JSON.parse(stored));
          setCache({ ip: newestFirst(migrated.ip), hash: newestFirst(migrated.hash), url: newestFirst(migrated.url) });
        }
        const savedTheme = localStorage.getItem("indicatorforge-theme") || localStorage.getItem("signalscope-theme");
        setTheme(savedTheme === "light" ? "light" : "dark");
      } catch {
        setTheme("dark");
      }
    });
    return () => window.cancelAnimationFrame(hydrationFrame);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("indicatorforge-theme", theme);
    } catch {}
  }, [theme]);

  useEffect(() => {
    if (!mobileMenuOpen) return;

    const closeMenu = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileMenuOpen(false);
    };
    const closeMenuAtDesktopWidth = () => {
      if (window.innerWidth > 1120) setMobileMenuOpen(false);
    };

    window.addEventListener("keydown", closeMenu);
    window.addEventListener("resize", closeMenuAtDesktopWidth);
    return () => {
      window.removeEventListener("keydown", closeMenu);
      window.removeEventListener("resize", closeMenuAtDesktopWidth);
    };
  }, [mobileMenuOpen]);

  const input = inputs[mode];
  const results = useMemo(() => {
    const current = analysisResults?.[mode];
    return Array.isArray(current) ? current : [];
  }, [analysisResults, mode]);
  const databaseResults = useMemo(
    () => newestFirst([...(cache?.ip ?? []), ...(cache?.hash ?? []), ...(cache?.url ?? [])]),
    [cache],
  );
  const databaseScope = useMemo(
    () => (dbType === "all" ? databaseResults : newestFirst(cache?.[dbType] ?? [])),
    [cache, databaseResults, dbType],
  );
  const filterResults = (scope: AnalysisResult[], verdict: "all" | Verdict, query: string) => {
    return scope.filter((result) => {
      const matchesVerdict = verdict === "all" || result.verdict === verdict;
      const haystack = [
        result.indicator,
        result.type,
        result.country,
        result.city,
        result.network,
        result.organization,
        result.fileName,
        result.fileType,
        result.urlDomain,
        ...(result.urlSignals || []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return matchesVerdict && haystack.includes(query.toLowerCase());
    });
  };

  const analysisFilteredResults = useMemo(
    () => filterResults(results, analysisVerdict, analysisQuery),
    [results, analysisVerdict, analysisQuery],
  );
  const databaseFilteredResults = useMemo(
    () => filterResults(databaseScope, dbVerdict, dbQuery),
    [databaseScope, dbVerdict, dbQuery],
  );
  const filteredResults = view === "database" ? databaseFilteredResults : analysisFilteredResults;

  const analysisStats = useMemo(
    () => ({
      total: results.length,
      flagged: results.filter((result) => ["malicious", "suspicious"].includes(result.verdict)).length,
      clean: results.filter((result) => result.verdict === "clean").length,
      unknown: results.filter((result) => result.verdict === "unknown").length,
    }),
    [results],
  );
  const databaseSummaryStats = useMemo(
    () => ({
      total: databaseScope.length,
      flagged: databaseScope.filter((result) => ["malicious", "suspicious"].includes(result.verdict)).length,
      clean: databaseScope.filter((result) => result.verdict === "clean").length,
      unknown: databaseScope.filter((result) => result.verdict === "unknown").length,
    }),
    [databaseScope],
  );

  const databaseStats = useMemo(() => {
    const live = databaseScope.filter((item) => item.providerStatus === "live").length;
    const verdicts = {
      malicious: databaseScope.filter((item) => item.verdict === "malicious").length,
      suspicious: databaseScope.filter((item) => item.verdict === "suspicious").length,
      clean: databaseScope.filter((item) => item.verdict === "clean").length,
      unknown: databaseScope.filter((item) => item.verdict === "unknown").length,
    };
    const total = databaseScope.length || 1;
    const maliciousEnd = (verdicts.malicious / total) * 100;
    const suspiciousEnd = maliciousEnd + (verdicts.suspicious / total) * 100;
    const cleanEnd = suspiciousEnd + (verdicts.clean / total) * 100;
    return {
      live,
      coverage: databaseScope.length ? Math.round((live / databaseScope.length) * 100) : 0,
      byType: {
        ip: databaseScope.filter((item) => item.type === "ip").length,
        hash: databaseScope.filter((item) => item.type === "hash").length,
        url: databaseScope.filter((item) => item.type === "url").length,
      },
      verdicts,
      verdictGradient: `conic-gradient(var(--accent) 0 ${maliciousEnd}%, var(--warning) ${maliciousEnd}% ${suspiciousEnd}%, var(--safe) ${suspiciousEnd}% ${cleanEnd}%, var(--text-faint) ${cleanEnd}% 100%)`,
    };
  }, [databaseScope]);

  const indicatorCount = splitIndicators(input).length;
  const sanitizerLines = useMemo(() => sanitizerInput.split(/\r?\n/).map((item) => item.trim()).filter(Boolean), [sanitizerInput]);
  const sanitizerTypes = useMemo(() => {
    const counts = { ip: 0, domain: 0, url: 0, email: 0, hash: 0, other: 0 };
    sanitizerLines.forEach((item) => {
      const kind = classifyIoc(item);
      if (kind !== "empty") counts[kind as keyof typeof counts] += 1;
    });
    return counts;
  }, [sanitizerLines]);

  function changeMode(next: Mode) {
    setMode(next);
    setError("");
    setAnalysisVerdict("all");
    setAnalysisQuery("");
  }

  function navigate(next: View) {
    setMobileMenuOpen(false);
    if (next === view) return;
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
    setView(next);
    setError("");
    setClearIntent(null);
  }

  function showNotice(message: string) {
    setNotice(message);
    window.setTimeout(() => setNotice(""), 2200);
  }

  function addSamples() {
    setInputs((current) => ({ ...current, [mode]: SAMPLES[mode].join("\n") }));
    showNotice("Sample indicators added");
  }

  function removeDuplicates() {
    const unique = dedupe(splitIndicators(input), mode === "url");
    setInputs((current) => ({ ...current, [mode]: unique.join("\n") }));
    showNotice(`${unique.length} unique indicator${unique.length === 1 ? "" : "s"}`);
  }

  async function analyze() {
    const requestedMode = mode;
    const indicators = dedupe(splitIndicators(inputs[requestedMode]), requestedMode === "url");
    if (!indicators.length) {
      setError(`Add at least one ${requestedMode === "ip" ? "IP address" : requestedMode === "hash" ? "file hash" : "URL"}.`);
      return;
    }
    if (indicators.length > 50) {
      setError("This project limits each run to 50 indicators to protect provider quotas.");
      return;
    }

    setBusyMode(requestedMode);
    setError("");
    navigate("analyze");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: requestedMode, indicators }),
      });
      const payload = (await response.json()) as { results?: AnalysisResult[]; error?: string };
      if (!response.ok || !payload.results) throw new Error(payload.error || "The analysis service is unavailable.");

      setAnalysisResults((current) => ({ ...current, [requestedMode]: newestFirst(payload.results!) }));
      setCache((current) => {
        const merged = new Map<string, AnalysisResult>();
        [...(current?.[requestedMode] ?? []), ...payload.results!].forEach((item) => merged.set(item.indicator.toLowerCase(), item));
        const next = { ...current, [requestedMode]: newestFirst([...merged.values()]).slice(0, 250) };
        try {
          localStorage.setItem("indicatorforge-db-v1", JSON.stringify(next));
        } catch {}
        return next;
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed. Please try again.");
    } finally {
      setBusyMode(null);
    }
  }

  function requestClear(target: DbFilter) {
    if (clearIntent !== target) {
      setClearIntent(target);
      window.setTimeout(() => setClearIntent(null), 3500);
      return;
    }
    const next = target === "all" ? EMPTY_CACHE : { ...normalizeCache(cache), [target]: [] };
    setCache(next);
    localStorage.setItem("indicatorforge-db-v1", JSON.stringify(next));
    setClearIntent(null);
    showNotice(target === "all" ? "Local database cleared" : `${MODE_META[target].short} records cleared`);
  }

  function exportCsv() {
    if (!filteredResults.length) return;
    const headings = [
      "type", "indicator", "verdict", "score", "malicious", "suspicious", "harmless", "context",
      "provider", "provider_status", "analyzed_at",
    ];
    const rows = filteredResults.map((item) =>
      [
        item.type,
        item.indicator,
        item.verdict,
        item.score,
        item.malicious,
        item.suspicious,
        item.harmless,
        item.type === "ip"
          ? [item.city, item.country, item.organization].filter(Boolean).join(" / ")
          : item.type === "hash"
            ? [item.fileName, item.fileType].filter(Boolean).join(" / ")
            : [item.urlDomain, ...(item.urlSignals || [])].filter(Boolean).join(" / "),
        item.provider,
        item.providerStatus,
        item.analyzedAt,
      ].map(escapeCsv).join(","),
    );
    const blob = new Blob([[headings.join(","), ...rows].join("\n")], { type: "text/csv;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `indicatorforge-${view === "database" ? `database-${dbType}` : mode}-${new Date().toISOString().slice(0, 10)}.csv`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  async function copyResults() {
    if (!filteredResults.length) return;
    await navigator.clipboard.writeText(
      filteredResults.map((result) => `${result.type}\t${result.indicator}\t${result.verdict}\t${result.score ?? "n/a"}`).join("\n"),
    );
    showNotice("Visible results copied");
  }

  function runSanitizer(nextMode = sanitizerMode) {
    setSanitizerMode(nextMode);
    setSanitizerOutput(nextMode === "defang" ? defangIocs(sanitizerInput) : refangIocs(sanitizerInput));
  }

  function swapSanitizer() {
    setSanitizerInput(sanitizerOutput);
    setSanitizerOutput(sanitizerInput);
    setSanitizerMode((current) => (current === "defang" ? "refang" : "defang"));
  }

  async function copySanitizer() {
    if (!sanitizerOutput) return;
    await navigator.clipboard.writeText(sanitizerOutput);
    showNotice("Converted indicators copied");
  }

  return (
    <div className="site-shell">
      <header className="topbar">
        <button className="brand" onClick={() => navigate("analyze")} aria-label="IndicatorForge home">
          <BrandMark />
          <span><strong>IndicatorForge</strong><small>IOC analysis toolkit</small></span>
        </button>
        <nav className="primary-nav" aria-label="Primary navigation">
          <button className={view === "analyze" ? "active" : ""} aria-current={view === "analyze" ? "page" : undefined} onClick={() => navigate("analyze")}>Analyze</button>
          <button className={view === "database" ? "active" : ""} aria-current={view === "database" ? "page" : undefined} onClick={() => navigate("database")}>
            Local Database <span>{databaseResults.length}</span>
          </button>
          <button className={view === "sanitizer" ? "active" : ""} aria-current={view === "sanitizer" ? "page" : undefined} onClick={() => navigate("sanitizer")}>IOC Converter</button>
          <button className={view === "about" ? "active" : ""} aria-current={view === "about" ? "page" : undefined} onClick={() => navigate("about")}>Methodology</button>
        </nav>
        <div className="header-actions">
          <span className="privacy-chip"><i /> Local-first storage</span>
          <button className="theme-button" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
            <span>{theme === "dark" ? "☀" : "◐"}</span>
          </button>
          <button
            className={`mobile-menu-button ${mobileMenuOpen ? "open" : ""}`}
            type="button"
            aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-navigation"
            onClick={() => setMobileMenuOpen((current) => !current)}
          >
            <span /><span /><span />
          </button>
        </div>
        {mobileMenuOpen && <button className="mobile-menu-backdrop" type="button" tabIndex={-1} aria-label="Close navigation menu" onClick={() => setMobileMenuOpen(false)} />}
        <nav id="mobile-navigation" className="mobile-navigation" aria-label="Mobile navigation" hidden={!mobileMenuOpen}>
          <button className={view === "analyze" ? "active" : ""} aria-current={view === "analyze" ? "page" : undefined} onClick={() => navigate("analyze")}><span>Analyze</span><b>01</b></button>
          <button className={view === "database" ? "active" : ""} aria-current={view === "database" ? "page" : undefined} onClick={() => navigate("database")}><span>Local Database</span><b>{databaseResults.length}</b></button>
          <button className={view === "sanitizer" ? "active" : ""} aria-current={view === "sanitizer" ? "page" : undefined} onClick={() => navigate("sanitizer")}><span>IOC Converter</span><b>03</b></button>
          <button className={view === "about" ? "active" : ""} aria-current={view === "about" ? "page" : undefined} onClick={() => navigate("about")}><span>Methodology</span><b>04</b></button>
        </nav>
      </header>

      <main>
        <section className="view-panel about-view" hidden={view !== "about"}>
            <div className="eyebrow"><span /> ANALYSIS PIPELINE</div>
            <h1>From raw indicators to a triage-ready shortlist.</h1>
            <p className="about-lede">
              IndicatorForge validates and enriches IP addresses, file hashes, and URLs in bulk. Provider credentials stay server-side while recent intelligence remains in a database local to this browser.
            </p>
            <div className="process-grid">
              {[
                ["01", "Normalize", "Split mixed input, remove duplicates, and validate IP, MD5, SHA-1, SHA-256, and URL indicators."],
                ["02", "Enrich", "Combine structural URL checks and public IP context with optional live VirusTotal and AbuseIPDB intelligence."],
                ["03", "Triage", "Rank by verdict, filter noisy datasets, inspect evidence, and export the current view as CSV."],
                ["04", "Recall", "Keep recent results in this browser only, with type and verdict filters, scoped export, and explicit cleanup."],
              ].map(([number, title, copy]) => (
                <article key={number}><span>{number}</span><h2>{title}</h2><p>{copy}</p></article>
              ))}
            </div>
            <div className="provider-note">
              <div><span className="signal-orb" /><strong>Missing-provider behavior</strong></div>
              <p>When a private reputation key is unavailable, the interface clearly labels partial intelligence. It never turns missing provider data into a false clean verdict.</p>
            </div>
        </section>

        <div className="view-panel analyze-view" hidden={view !== "analyze"}>
            <section className="hero-workbench">
              <div className="hero-copy">
                <div className="eyebrow"><span /> BULK REPUTATION ANALYSIS</div>
                <h1>Investigate the signal.<br /><em>Lose the noise.</em></h1>
                <p>Turn IP addresses, file hashes, and URLs into a focused, exportable triage view—without checking indicators one by one.</p>
                <div className="hero-proof">
                  <div><strong>50</strong><span>indicators / run</span></div>
                  <div><strong>03</strong><span>indicator types</span></div>
                  <div><strong>00</strong><span>keys in browser</span></div>
                </div>
              </div>

              <div className="input-card" id="workbench">
                <div className="mode-tabs" role="tablist" aria-label="Indicator type">
                  {(Object.keys(MODE_META) as Mode[]).map((item) => (
                    <button key={item} role="tab" aria-selected={mode === item} className={mode === item ? "active" : ""} onClick={() => changeMode(item)} disabled={busyMode !== null}>
                      <span className="tab-icon">{MODE_META[item].icon}</span>{MODE_META[item].label}
                    </button>
                  ))}
                </div>
                <label htmlFor="indicator-input">{MODE_META[mode].input}<span>{indicatorCount}/50</span></label>
                <textarea id="indicator-input" value={input} onChange={(event) => setInputs((current) => ({ ...current, [mode]: event.target.value }))} placeholder={MODE_META[mode].placeholder} spellCheck={false} />
                <div className="input-tools">
                  <div>
                    <button onClick={addSamples}>Use sample</button>
                    <button onClick={removeDuplicates}>Deduplicate</button>
                    <button onClick={() => setInputs((current) => ({ ...current, [mode]: "" }))}>Clear</button>
                  </div>
                  <span>One per line, or separated by commas</span>
                </div>
                {error && <div className="error-banner" role="alert">{error}</div>}
                <button className="analyze-button" onClick={analyze} disabled={busyMode !== null}>
                  <span>{busyMode === mode ? "Analyzing indicators…" : `Analyze ${indicatorCount || ""} ${MODE_META[mode].short}${indicatorCount === 1 ? "" : mode === "url" ? "s" : mode === "ip" ? "s" : "es"}`}</span>
                  <b>{busyMode === mode ? "···" : "↗"}</b>
                </button>
              </div>
            </section>

            <section className="results-section" aria-label="Analysis results">
              <div className="results-heading">
                <div><span className="section-index">02 / RESULTS</span><h2>Investigation summary</h2></div>
                <div className="results-actions">
                  <button onClick={copyResults} disabled={!analysisFilteredResults.length}>Copy view</button>
                  <button className="export" onClick={exportCsv} disabled={!analysisFilteredResults.length}>Export CSV ↓</button>
                </div>
              </div>
              <div className="metric-strip">
                  <div><span>Total analyzed</span><strong>{analysisStats.total}</strong></div>
                  <div className="flagged"><span>Needs attention</span><strong>{analysisStats.flagged}</strong></div>
                  <div className="clean"><span>Clean</span><strong>{analysisStats.clean}</strong></div>
                  <div><span>Unknown</span><strong>{analysisStats.unknown}</strong></div>
              </div>
              <FilterToolbar verdict={analysisVerdict} query={analysisQuery} onVerdictChange={setAnalysisVerdict} onQueryChange={setAnalysisQuery} />
              <ResultsTable results={analysisFilteredResults} />
            </section>
        </div>

        <section className="view-panel database-view" hidden={view !== "database"}>
            <div className="database-hero">
              <div>
                <div className="eyebrow"><span /> LOCAL INTELLIGENCE STORE</div>
                <h1>Local Database</h1>
                <p>
                  A private, device-local record of your recent investigations. Use it to compare indicator types, revisit evidence without repeating provider requests, and export a scoped dataset for reporting or further analysis.
                </p>
              </div>
              <div className="database-policy">
                <span>STORAGE POLICY</span>
                <strong>Browser-local. Clearable. No account sync.</strong>
                <p>Up to 250 recent records per indicator type are retained on this device.</p>
              </div>
            </div>

            <div className="db-filter-row">
              <span>Filter by type</span>
              <div className="db-type-filter" aria-label="Database type filter">
                {(["all", "ip", "hash", "url"] as const).map((item) => (
                  <button key={item} className={dbType === item ? "active" : ""} onClick={() => { setDbType(item); setDbVerdict("all"); setDbQuery(""); }}>
                    {item === "all" ? "All" : MODE_META[item].short}<b>{item === "all" ? databaseResults.length : (cache?.[item] ?? []).length}</b>
                  </button>
                ))}
              </div>
            </div>

            <details className="intel-dashboard" open={dashboardOpen} onToggle={(event) => setDashboardOpen(event.currentTarget.open)}>
              <summary>
                <div><span className="dashboard-icon">⌁</span><strong>Executive dashboard</strong><small>Verdict, source, and indicator distribution for the selected view</small></div>
                <span className="expand-label">Toggle <i>+</i></span>
              </summary>
              <div className="dashboard-body">
                <div className="metric-strip dashboard-metrics">
                  <div><span>Records in view</span><strong>{databaseSummaryStats.total}</strong></div>
                  <div className="flagged"><span>Needs attention</span><strong>{databaseSummaryStats.flagged}</strong></div>
                  <div className="clean"><span>Clean</span><strong>{databaseSummaryStats.clean}</strong></div>
                  <div><span>Unknown</span><strong>{databaseSummaryStats.unknown}</strong></div>
                </div>
                <div className="dashboard-content">
                  <div className="dashboard-card verdict-chart-card">
                    <span>VERDICT DISTRIBUTION</span>
                    <div className="donut-layout">
                      <div className="donut-chart" style={{ background: databaseStats.verdictGradient }}><i><strong>{databaseScope.length}</strong><small>records</small></i></div>
                      <ul className="chart-legend">
                        {(Object.keys(databaseStats.verdicts) as Verdict[]).map((item) => <li key={item} className={item}><i /><span>{verdictLabel(item)}</span><b>{databaseStats.verdicts[item]}</b></li>)}
                      </ul>
                    </div>
                  </div>
                  <div className="dashboard-card distribution-card">
                    <span>INDICATOR COMPOSITION</span>
                    <div className="distribution-bars">
                      {(Object.keys(databaseStats.byType) as Mode[]).map((item) => {
                        const percent = databaseScope.length ? Math.round((databaseStats.byType[item] / databaseScope.length) * 100) : 0;
                        return <div key={item}><label><b>{MODE_META[item].short}</b><em>{databaseStats.byType[item]} · {percent}%</em></label><span><i className={item} style={{ width: `${percent}%` }} /></span></div>;
                      })}
                    </div>
                  </div>
                  <div className="dashboard-card coverage-card">
                    <span>LIVE PROVIDER COVERAGE</span>
                    <div className="coverage-ring" style={{ background: `conic-gradient(var(--safe) 0 ${databaseStats.coverage}%, var(--panel-3) ${databaseStats.coverage}% 100%)` }}>
                      <i><strong>{databaseStats.coverage}%</strong><small>{databaseStats.live} live</small></i>
                    </div>
                    <div className="coverage-key"><span><i className="live" />Live enrichment</span><span><i />Partial / local</span></div>
                  </div>
                </div>
              </div>
            </details>

            <div className="database-panel">
              <div className="database-panel-heading">
                <div><span className="section-index">DB / {dbType.toUpperCase()}</span><h2>{dbType === "all" ? "All intelligence records" : `${MODE_META[dbType].label} database`}</h2></div>
                <div className="results-actions">
                  <button onClick={copyResults} disabled={!databaseFilteredResults.length}>Copy view</button>
                  <button onClick={exportCsv} disabled={!databaseFilteredResults.length}>Export CSV ↓</button>
                  <button className="danger" onClick={() => requestClear(dbType)} disabled={!databaseScope.length}>
                    {clearIntent === dbType ? "Confirm clear" : `Clear ${dbType === "all" ? "database" : "filtered"}`}
                  </button>
                </div>
              </div>
              <FilterToolbar verdict={dbVerdict} query={dbQuery} onVerdictChange={setDbVerdict} onQueryChange={setDbQuery} />
              <ResultsTable results={databaseFilteredResults} database />
              <div className="database-footnote">
                <span><i /> Local-only storage</span>
                <p>Reputation changes over time. Refresh critical indicators before making a security decision.</p>
              </div>
            </div>
        </section>

        <section className="view-panel sanitizer-view" hidden={view !== "sanitizer"}>
            <div className="sanitizer-heading">
              <div>
                <div className="eyebrow"><span /> IOC TRANSFORMATION</div>
                <h1>IOC Converter</h1>
                <p>Defang indicators before sharing them in tickets, chat, or reports. Refang sanitized values when they need to be copied into an approved investigation tool.</p>
              </div>
              <div className="conversion-reference">
                <span>TRANSFORM EXAMPLES</span>
                <code>https:// → hxxps://</code>
                <code>example.com → example[.]com</code>
                <code>:8080 → [:]8080</code>
              </div>
            </div>

            <div className="sanitizer-shell">
              <div className="converter-toolbar">
                <div className="converter-mode" role="tablist" aria-label="Conversion direction">
                  <button role="tab" aria-selected={sanitizerMode === "defang"} className={sanitizerMode === "defang" ? "active" : ""} onClick={() => runSanitizer("defang")}>Defang</button>
                  <button role="tab" aria-selected={sanitizerMode === "refang"} className={sanitizerMode === "refang" ? "active" : ""} onClick={() => runSanitizer("refang")}>Refang</button>
                </div>
                <span>{sanitizerLines.length} IOC{sanitizerLines.length === 1 ? "" : "s"} detected</span>
              </div>

              <div className="converter-grid">
                <div className="converter-pane">
                  <label htmlFor="sanitizer-input"><span>INPUT</span><button onClick={() => setSanitizerInput("https://login.example.com:8080/verify\n198.51.100.14\nalerts@example.com")}>Load example</button></label>
                  <textarea id="sanitizer-input" value={sanitizerInput} onChange={(event) => setSanitizerInput(event.target.value)} placeholder="Paste IPs, domains, URLs, emails, or hashes—one per line" spellCheck={false} />
                </div>
                <div className="converter-switch">
                  <button onClick={swapSanitizer} disabled={!sanitizerInput && !sanitizerOutput} aria-label="Swap input and output">⇄</button>
                </div>
                <div className="converter-pane output-pane">
                  <label htmlFor="sanitizer-output"><span>OUTPUT</span><button onClick={copySanitizer} disabled={!sanitizerOutput}>Copy</button></label>
                  <textarea id="sanitizer-output" value={sanitizerOutput} readOnly placeholder="Converted indicators appear here" spellCheck={false} />
                </div>
              </div>

              <div className="converter-footer">
                <div className="ioc-type-summary">
                  {(Object.keys(sanitizerTypes) as (keyof typeof sanitizerTypes)[]).map((item) => sanitizerTypes[item] > 0 && <span key={item}><b>{sanitizerTypes[item]}</b>{item}</span>)}
                  {!sanitizerLines.length && <span className="empty-count">No input</span>}
                </div>
                <div className="converter-actions">
                  <button onClick={() => { setSanitizerInput(""); setSanitizerOutput(""); }}>Clear</button>
                  <button className="convert-button" onClick={() => runSanitizer()} disabled={!sanitizerInput}>{sanitizerMode === "defang" ? "Defang indicators" : "Refang indicators"} <b>↗</b></button>
                </div>
              </div>
            </div>

            <div className="sanitizer-notes">
              <div><strong>Local transformation</strong><span>No values are sent to the analysis API or saved in Local Database.</span></div>
              <div><strong>Supported replacements</strong><span>HTTP/S schemes, dots, and explicit ports. Hashes remain unchanged.</span></div>
              <div><strong>Safe workflow</strong><span>Refanging does not visit, resolve, or validate the resulting indicator.</span></div>
            </div>
        </section>
      </main>

      <footer>
        <div><BrandMark /><strong>IndicatorForge</strong><span>Analyze · Store · Transform</span></div>
        <p>Local database enabled · Provider credentials remain server-side</p>
      </footer>
      {notice && <div className="toast" role="status">✓ {notice}</div>}
    </div>
  );
}
