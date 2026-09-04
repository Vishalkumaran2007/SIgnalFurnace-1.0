import { isPublicIpv4 } from "./geolocation";

export type AbuseIpdbReputation = {
  ip: string;
  provider: "AbuseIPDB";
  abuseConfidenceScore: number;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: Date | null;
  countryCode: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  isWhitelisted: number;
  rawJson: string;
};

type AbuseIpdbData = {
  ipAddress?: string;
  abuseConfidenceScore?: number;
  totalReports?: number;
  numDistinctUsers?: number;
  lastReportedAt?: string | null;
  countryCode?: string | null;
  usageType?: string | null;
  isp?: string | null;
  domain?: string | null;
  isWhitelisted?: boolean;
};

function asNumber(value: unknown) { return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.round(value)) : 0; }
function asString(value: unknown) { return typeof value === "string" && value.trim() ? value.trim() : null; }

export async function lookupAbuseIpdb(ip: string): Promise<AbuseIpdbReputation> {
  if (!isPublicIpv4(ip)) throw new Error("Only a public IPv4 source address can be checked with AbuseIPDB.");
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) throw new Error("AbuseIPDB is not configured.");
  const url = new URL("https://api.abuseipdb.com/api/v2/check");
  url.searchParams.set("ipAddress", ip);
  url.searchParams.set("maxAgeInDays", "90");
  const response = await fetch(url, { headers: { Key: key, Accept: "application/json" }, signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? "AbuseIPDB authorization was rejected." : "AbuseIPDB could not complete this reputation check.");
  const payload = await response.json() as { data?: AbuseIpdbData };
  const data = payload.data;
  if (!data || data.ipAddress !== ip) throw new Error("AbuseIPDB returned an unexpected reputation response.");
  const reportedAt = asString(data.lastReportedAt);
  const lastReportedAt = reportedAt && !Number.isNaN(new Date(reportedAt).getTime()) ? new Date(reportedAt) : null;
  return { ip, provider: "AbuseIPDB", abuseConfidenceScore: asNumber(data.abuseConfidenceScore), totalReports: asNumber(data.totalReports), numDistinctUsers: asNumber(data.numDistinctUsers), lastReportedAt, countryCode: asString(data.countryCode), usageType: asString(data.usageType), isp: asString(data.isp), domain: asString(data.domain), isWhitelisted: data.isWhitelisted ? 1 : 0, rawJson: JSON.stringify(data) };
}
