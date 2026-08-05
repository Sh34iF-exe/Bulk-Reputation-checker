type AnalysisType = "ip" | "hash" | "url";
type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

type Result = {
  indicator: string;
  type: AnalysisType;
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

type RuntimeEnv = {
  VIRUSTOTAL_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
};

type CacheEntry = {
  result: Result;
  expiresAt: number;
};

const RESULT_CACHE_TTL_MS = 15 * 60 * 1000;
const ERROR_CACHE_TTL_MS = 60 * 1000;
const MAX_CACHE_ENTRIES = 1_500;
const resultCache = new Map<string, CacheEntry>();
const inFlightAnalyses = new Map<string, Promise<Result>>();

function resultCacheKey(type: AnalysisType, indicator: string, runtime: RuntimeEnv) {
  const providerProfile = `${runtime.VIRUSTOTAL_API_KEY ? "vt" : "no-vt"}:${runtime.ABUSEIPDB_API_KEY ? "abuse" : "no-abuse"}`;
  return `${providerProfile}:${type}:${indicator.trim().toLowerCase()}`;
}

function readCachedResult(key: string) {
  const entry = resultCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    resultCache.delete(key);
    return null;
  }
  resultCache.delete(key);
  resultCache.set(key, entry);
  return { ...entry.result, analyzedAt: new Date().toISOString(), cacheHit: true };
}

function storeCachedResult(key: string, result: Result) {
  for (const [cachedKey, entry] of resultCache) {
    if (entry.expiresAt <= Date.now()) resultCache.delete(cachedKey);
  }
  while (resultCache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = resultCache.keys().next().value as string | undefined;
    if (!oldestKey) break;
    resultCache.delete(oldestKey);
  }
  const ttl = result.providerStatus === "error" ? ERROR_CACHE_TTL_MS : RESULT_CACHE_TTL_MS;
  resultCache.set(key, { result: { ...result, cacheHit: false }, expiresAt: Date.now() + ttl });
}

function isIp(value: string) {
  const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  const ipv6 = /^(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{0,4}$/i;
  return ipv4.test(value) || ipv6.test(value);
}

function isHash(value: string) {
  return /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(value);
}

function hashType(value: string) {
  return value.length === 32 ? "MD5" : value.length === 40 ? "SHA-1" : "SHA-256";
}

function parseUrl(value: string) {
  try {
    const normalized = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`;
    const parsed = new URL(normalized);
    if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || !parsed.hostname.includes(".")) return null;
    return parsed;
  } catch {
    return null;
  }
}

function urlId(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function urlHeuristics(parsed: URL) {
  const signals: string[] = [];
  let score = 0;
  if (parsed.protocol === "http:") { signals.push("Unencrypted HTTP"); score += 16; }
  if (isIp(parsed.hostname)) { signals.push("IP-literal host"); score += 24; }
  if (parsed.hostname.includes("xn--")) { signals.push("Punycode domain"); score += 22; }
  if (parsed.username || parsed.password || parsed.href.includes("@")) { signals.push("Embedded credentials"); score += 28; }
  if (parsed.hostname.split(".").length > 4) { signals.push("Deep subdomain chain"); score += 12; }
  if (parsed.href.length > 140) { signals.push("Unusually long URL"); score += 10; }
  if (/%[0-9a-f]{2}/i.test(parsed.pathname)) { signals.push("Encoded path"); score += 9; }
  if (parsed.port && !["80", "443"].includes(parsed.port)) { signals.push("Non-standard port"); score += 12; }
  const bait = `${parsed.hostname}${parsed.pathname}`.toLowerCase();
  if (/(login|verify|secure|account|wallet|password|update|signin)/.test(bait)) { signals.push("Credential-themed path"); score += 8; }
  return { signals, score: Math.min(score, 100) };
}

function verdictFromStats(malicious: number, suspicious: number, total: number): { verdict: Verdict; score: number } {
  const weighted = malicious + suspicious * 0.55;
  const score = total ? Math.min(100, Math.round((weighted / total) * 240)) : 0;
  if (malicious >= 3 || score >= 35) return { verdict: "malicious", score };
  if (malicious > 0 || suspicious > 0 || score >= 10) return { verdict: "suspicious", score };
  return { verdict: "clean", score };
}

async function fetchJson(url: string, init?: RequestInit) {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(9000) });
  if (!response.ok) throw new Error(`Provider returned ${response.status}`);
  return response.json() as Promise<Record<string, unknown>>;
}

async function analyzeIndicator(type: AnalysisType, indicator: string, runtime: RuntimeEnv): Promise<Result> {
  const now = new Date().toISOString();
  const parsedUrl = type === "url" ? parseUrl(indicator) : null;
  const valid = type === "ip" ? isIp(indicator) : type === "hash" ? isHash(indicator) : Boolean(parsedUrl);
  const normalizedIndicator = parsedUrl?.href || indicator;
  const base: Result = {
    indicator: normalizedIndicator,
    type,
    valid,
    verdict: "unknown",
    score: null,
    malicious: null,
    suspicious: null,
    harmless: null,
    provider: "Validation only",
    providerStatus: "unavailable",
    analyzedAt: now,
  };

  if (!valid) return { ...base, provider: "Local validation", providerStatus: "error", note: "Invalid indicator format" };

  if (type === "hash") base.fileType = hashType(indicator);

  if (type === "url" && parsedUrl) {
    const heuristic = urlHeuristics(parsedUrl);
    base.urlDomain = parsedUrl.hostname;
    base.urlProtocol = parsedUrl.protocol.replace(":", "").toUpperCase();
    base.urlSignals = heuristic.signals;
    base.score = heuristic.score;
    base.verdict = heuristic.score >= 20 ? "suspicious" : "unknown";
    base.provider = "Local URL heuristics";
    base.providerStatus = "partial";
    base.note = heuristic.signals.length ? "Structural risk signals detected" : "No structural alerts; live reputation still required";
  }

  if (type === "ip") {
    try {
      const geo = await fetchJson(`https://ipwho.is/${encodeURIComponent(indicator)}`);
      if (geo.success !== false) {
        const connection = (geo.connection || {}) as Record<string, unknown>;
        base.country = typeof geo.country_code === "string" ? geo.country_code : undefined;
        base.city = typeof geo.city === "string" ? geo.city : undefined;
        base.organization = typeof connection.org === "string" ? connection.org : undefined;
        base.network = typeof connection.isp === "string" ? connection.isp : undefined;
        base.provider = "Public enrichment";
        base.providerStatus = "partial";
      }
    } catch {
      base.note = "Public IP enrichment was unavailable";
    }
  }

  let abuseScore: number | null = null;
  if (type === "ip" && runtime.ABUSEIPDB_API_KEY) {
    try {
      const abuse = await fetchJson(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90&verbose=true`,
        { headers: { Key: runtime.ABUSEIPDB_API_KEY, Accept: "application/json" } },
      );
      const abuseData = (abuse.data || {}) as Record<string, unknown>;
      if (typeof abuseData.abuseConfidenceScore === "number") abuseScore = abuseData.abuseConfidenceScore;
      if (!base.country && typeof abuseData.countryCode === "string") base.country = abuseData.countryCode;
      if (!base.organization && typeof abuseData.isp === "string") base.organization = abuseData.isp;
    } catch {
      // Other enrichment sources can still provide a useful partial result.
    }
  }

  if (!runtime.VIRUSTOTAL_API_KEY) {
    if (abuseScore !== null) {
      base.score = abuseScore;
      base.verdict = abuseScore >= 65 ? "malicious" : abuseScore >= 15 ? "suspicious" : "clean";
      base.provider = "AbuseIPDB + public enrichment";
      base.providerStatus = "live";
    } else if (type !== "url") {
      base.note = "Configure a reputation provider key for a live verdict";
    }
    return base;
  }

  try {
    const endpoint = type === "ip" ? `ip_addresses/${encodeURIComponent(indicator)}` : type === "hash" ? `files/${encodeURIComponent(indicator)}` : `urls/${urlId(normalizedIndicator)}`;
    const vt = await fetchJson(`https://www.virustotal.com/api/v3/${endpoint}`, {
      headers: { "x-apikey": runtime.VIRUSTOTAL_API_KEY },
    });
    const data = (vt.data || {}) as Record<string, unknown>;
    const attributes = (data.attributes || {}) as Record<string, unknown>;
    const analysisStats = (attributes.last_analysis_stats || {}) as Record<string, number>;
    const malicious = Number(analysisStats.malicious || 0);
    const suspicious = Number(analysisStats.suspicious || 0);
    const harmless = Number(analysisStats.harmless || 0);
    const undetected = Number(analysisStats.undetected || 0);
    const total = malicious + suspicious + harmless + undetected;
    const scored = verdictFromStats(malicious, suspicious, total);

    base.malicious = malicious;
    base.suspicious = suspicious;
    base.harmless = harmless;
    base.score = abuseScore === null ? Math.max(base.score || 0, scored.score) : Math.round(scored.score * 0.7 + abuseScore * 0.3);
    base.verdict = abuseScore !== null && abuseScore >= 65 && scored.verdict === "clean" ? "suspicious" : scored.verdict;
    base.provider = abuseScore === null ? "VirusTotal" : "VirusTotal + AbuseIPDB";
    base.providerStatus = "live";

    if (typeof attributes.last_analysis_date === "number") base.lastAnalysis = new Date(attributes.last_analysis_date * 1000).toISOString();
    if (type === "hash") {
      base.fileType = typeof attributes.type_description === "string" ? attributes.type_description : base.fileType;
      base.fileName = typeof attributes.meaningful_name === "string" ? attributes.meaningful_name : undefined;
    }
    if (type === "ip") {
      base.country = typeof attributes.country === "string" ? attributes.country : base.country;
      base.organization = typeof attributes.as_owner === "string" ? attributes.as_owner : base.organization;
      base.network = typeof attributes.network === "string" ? attributes.network : base.network;
    }
    if (type === "url") {
      base.urlDomain = typeof attributes.url === "string" ? new URL(attributes.url).hostname : base.urlDomain;
    }
    return base;
  } catch (error) {
    return {
      ...base,
      provider: base.providerStatus === "partial" ? base.provider : "VirusTotal",
      providerStatus: base.providerStatus === "partial" ? "partial" : "error",
      note: error instanceof Error ? error.message : "Provider request failed",
    };
  }
}

async function analyzeIndicatorCached(type: AnalysisType, indicator: string, runtime: RuntimeEnv): Promise<Result> {
  const key = resultCacheKey(type, indicator, runtime);
  const cached = readCachedResult(key);
  if (cached) return cached;

  const pending = inFlightAnalyses.get(key);
  if (pending) {
    const result = await pending;
    return { ...result, analyzedAt: new Date().toISOString(), cacheHit: true };
  }

  const analysis = analyzeIndicator(type, indicator, runtime);
  inFlightAnalyses.set(key, analysis);
  try {
    const result = await analysis;
    storeCachedResult(key, result);
    return { ...result, cacheHit: false };
  } finally {
    inFlightAnalyses.delete(key);
  }
}

export async function POST(request: Request) {
  try {
    const payload = (await request.json()) as { type?: AnalysisType; indicators?: unknown };
    if (payload.type !== "ip" && payload.type !== "hash" && payload.type !== "url") {
      return Response.json({ error: "type must be ip, hash, or url" }, { status: 400 });
    }
    if (!Array.isArray(payload.indicators)) return Response.json({ error: "indicators must be an array" }, { status: 400 });

    const seen = new Set<string>();
    const indicators = payload.indicators
      .map((value) => String(value).trim())
      .filter((value) => {
        if (!value) return false;
        const key = value.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .slice(0, 50);
    if (!indicators.length) return Response.json({ error: "At least one indicator is required" }, { status: 400 });

    const runtime: RuntimeEnv = {
      VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY,
      ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY,
    };
    const results: Result[] = [];
    for (let index = 0; index < indicators.length; index += 5) {
      const batch = indicators.slice(index, index + 5);
      results.push(...(await Promise.all(batch.map((indicator) => analyzeIndicatorCached(payload.type!, indicator, runtime)))));
    }
    return Response.json({
      results,
      providers: { virusTotal: Boolean(runtime.VIRUSTOTAL_API_KEY), abuseIpDb: Boolean(runtime.ABUSEIPDB_API_KEY) },
      cache: {
        hits: results.filter((result) => result.cacheHit).length,
        misses: results.filter((result) => !result.cacheHit).length,
        ttlSeconds: RESULT_CACHE_TTL_MS / 1000,
      },
    });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Unable to process request" }, { status: 500 });
  }
}
