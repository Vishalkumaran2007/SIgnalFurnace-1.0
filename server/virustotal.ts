import { isPublicIpv4 } from "./geolocation";

export type VirusTotalReputation = {
  ip: string;
  provider: "VirusTotal";
  abuseConfidenceScore: number;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: Date | null;
  countryCode: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  isWhitelisted: number;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputationScore: number | null;
  asn: number | null;
  asOwner: string | null;
  network: string | null;
  lastAnalysisAt: Date | null;
  rawJson: string;
};

type VirusTotalAttributes = {
  last_analysis_stats?: Record<string, unknown>;
  reputation?: unknown;
  country?: unknown;
  asn?: unknown;
  as_owner?: unknown;
  network?: unknown;
  last_analysis_date?: unknown;
};

function numberOrZero(value: unknown) { return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0; }
function optionalNumber(value: unknown) { return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : null; }
function optionalString(value: unknown) { return typeof value === "string" && value.trim() ? value.trim() : null; }

export async function lookupVirusTotalIp(ip: string): Promise<VirusTotalReputation> {
  if (!isPublicIpv4(ip)) throw new Error("Only a public IPv4 source address can be checked with VirusTotal.");
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) throw new Error("VirusTotal is not configured.");
  const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, { headers: { "x-apikey": key, Accept: "application/json" }, signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? "VirusTotal authorization was rejected." : "VirusTotal could not complete this reputation check.");
  const payload = await response.json() as { data?: { id?: string; attributes?: VirusTotalAttributes } };
  const data = payload.data;
  if (!data || data.id !== ip) throw new Error("VirusTotal returned an unexpected reputation response.");
  const attributes = data.attributes || {};
  const stats = attributes.last_analysis_stats || {};
  const timestamp = optionalNumber(attributes.last_analysis_date);
  return { ip, provider: "VirusTotal", abuseConfidenceScore: 0, totalReports: 0, numDistinctUsers: 0, lastReportedAt: null, countryCode: optionalString(attributes.country), usageType: null, isp: null, domain: null, isWhitelisted: 0, malicious: numberOrZero(stats.malicious), suspicious: numberOrZero(stats.suspicious), harmless: numberOrZero(stats.harmless), undetected: numberOrZero(stats.undetected), reputationScore: optionalNumber(attributes.reputation), asn: optionalNumber(attributes.asn), asOwner: optionalString(attributes.as_owner), network: optionalString(attributes.network), lastAnalysisAt: timestamp ? new Date(timestamp * 1000) : null, rawJson: JSON.stringify(attributes) };
}
