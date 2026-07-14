import { env } from "cloudflare:workers";

type AnalysisType = "ip" | "hash";
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
  lastAnalysis?: string;
  note?: string;
  analyzedAt: string;
};

type RuntimeEnv = {
  VIRUSTOTAL_API_KEY?: string;
  ABUSEIPDB_API_KEY?: string;
};

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
  const valid = type === "ip" ? isIp(indicator) : isHash(indicator);
  const base: Result = {
    indicator,
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
      // VirusTotal or public enrichment can still provide a useful partial result.
    }
  }

  if (!runtime.VIRUSTOTAL_API_KEY) {
    if (abuseScore !== null) {
      base.score = abuseScore;
      base.verdict = abuseScore >= 65 ? "malicious" : abuseScore >= 15 ? "suspicious" : "clean";
      base.provider = "AbuseIPDB + public enrichment";
      base.providerStatus = "live";
    } else {
      base.note = "Configure a reputation provider key for a live verdict";
    }
    return base;
  }

  try {
    const endpoint = type === "ip" ? "ip_addresses" : "files";
    const vt = await fetchJson(`https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(indicator)}`, {
      headers: { "x-apikey": runtime.VIRUSTOTAL_API_KEY },
    });
    const data = (vt.data || {}) as Record<string, unknown>;
    const attributes = (data.attributes || {}) as Record<string, unknown>;
    const stats = (attributes.last_analysis_stats || {}) as Record<string, number>;
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const total = malicious + suspicious + harmless + undetected;
    const scored = verdictFromStats(malicious, suspicious, total);

    base.malicious = malicious;
    base.suspicious = suspicious;
    base.harmless = harmless;
    base.score = abuseScore === null ? scored.score : Math.round(scored.score * 0.7 + abuseScore * 0.3);
    base.verdict = abuseScore !== null && abuseScore >= 65 && scored.verdict === "clean" ? "suspicious" : scored.verdict;
    base.provider = abuseScore === null ? "VirusTotal" : "VirusTotal + AbuseIPDB";
    base.providerStatus = "live";

    if (typeof attributes.last_analysis_date === "number") {
      base.lastAnalysis = new Date(attributes.last_analysis_date * 1000).toISOString();
    }
    if (type === "hash") {
      base.fileType = typeof attributes.type_description === "string" ? attributes.type_description : base.fileType;
      base.fileName = typeof attributes.meaningful_name === "string" ? attributes.meaningful_name : undefined;
    }
    if (type === "ip") {
      base.country = typeof attributes.country === "string" ? attributes.country : base.country;
      base.organization = typeof attributes.as_owner === "string" ? attributes.as_owner : base.organization;
      base.network = typeof attributes.network === "string" ? attributes.network : base.network;
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

export async function POST(request: Request) {
  try {
    const payload = (await request.json()) as { type?: AnalysisType; indicators?: unknown };
    if (payload.type !== "ip" && payload.type !== "hash") {
      return Response.json({ error: "type must be ip or hash" }, { status: 400 });
    }
    if (!Array.isArray(payload.indicators)) {
      return Response.json({ error: "indicators must be an array" }, { status: 400 });
    }

    const indicators = [
      ...new Set(payload.indicators.map((value) => String(value).trim().toLowerCase()).filter(Boolean)),
    ].slice(0, 50);
    if (!indicators.length) return Response.json({ error: "At least one indicator is required" }, { status: 400 });

    const runtime = env as RuntimeEnv;
    const results: Result[] = [];
    for (let index = 0; index < indicators.length; index += 5) {
      const batch = indicators.slice(index, index + 5);
      results.push(...(await Promise.all(batch.map((indicator) => analyzeIndicator(payload.type!, indicator, runtime)))));
    }
    return Response.json({ results, providers: { virusTotal: Boolean(runtime.VIRUSTOTAL_API_KEY), abuseIpDb: Boolean(runtime.ABUSEIPDB_API_KEY) } });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "Unable to process request" }, { status: 500 });
  }
}
