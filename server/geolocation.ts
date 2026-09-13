import { ENV } from "./_core/env";
import { lookupAbuseIpdb } from "./threatIntel";

export type InfrastructureLabel = "RESIDENTIAL_ISP" | "CLOUD_HOSTING" | "VPN_ANONYMIZER" | "TOR_EXIT_NODE" | "MOBILE_NETWORK" | "INTERNAL_NETWORK" | "UNKNOWN_NETWORK";
export type GeolocationLookup = {
  ip: string; country: string | null; countryCode: string | null; region: string | null; city: string | null;
  latitude: number | null; longitude: number | null; provider: string; postal: string | null; timezone: string | null;
  asn: string | null; ispName: string | null; organization: string | null; isVpn: number; isTor: number;
  isHosting: number; isMobile: number; isSuspicious: number; infrastructureLabel: InfrastructureLabel;
  abuseScore: number; abuseReports: number; lastReportedAt: Date | null; precisionConfidence: number; sourcesUsedJson: string; sourcesAgreed: number;
};
type IpinfoResponse = { ip?: string; city?: string; region?: string; country?: string; loc?: string; org?: string; timezone?: string; postal?: string };
type IpGeolocationResponse = { ip?: string; country_name?: string; country_code2?: string; state_prov?: string; city?: string; latitude?: string | number; longitude?: string | number; zipcode?: string; time_zone?: { name?: string }; organization?: string; asn?: string; isp?: string; message?: string };

export function isPublicIpv4(ip: string) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  if (first === 0 || first === 10 || first === 127 || first >= 224 || (first === 169 && second === 254) || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168)) return false;
  return !((first === 192 && second === 0 && parts[2] === 2) || (first === 198 && second === 51 && parts[2] === 100) || (first === 203 && second === 0 && parts[2] === 113));
}
function finite(value: unknown, min: number, max: number) { const number = typeof value === "number" ? value : Number(value); return Number.isFinite(number) && number >= min && number <= max ? number : null; }
function string(value: unknown) { return typeof value === "string" && value.trim() ? value.trim() : null; }
function coordinates(loc: string | undefined) { const [lat, lng] = (loc || "").split(","); return { latitude: finite(lat, -90, 90), longitude: finite(lng, -180, 180) }; }
function asn(value: string | null | undefined) { return value?.match(/AS\d+/i)?.[0]?.toUpperCase() || null; }
function agreed(values: Array<string | null | undefined>) { const usable = values.filter((value): value is string => Boolean(value && value.trim())); return usable.find((value, index) => usable.some((candidate, candidateIndex) => candidateIndex !== index && candidate.toLowerCase() === value.toLowerCase())) || usable[0] || null; }

async function ipinfo(ip: string) {
  if (!ENV.ipinfoToken) throw new Error("IPinfo is not configured.");
  const response = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${encodeURIComponent(ENV.ipinfoToken)}`, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(8_000) });
  if (!response.ok) throw new Error("IPinfo could not complete the lookup.");
  const data = await response.json() as IpinfoResponse;
  if (data.ip !== ip) throw new Error("IPinfo returned an unexpected IP.");
  return { ...data, ...coordinates(data.loc), asn: asn(data.org), ispName: string(data.org?.replace(/^AS\d+\s*/i, "")) };
}
async function ipgeolocation(ip: string) {
  if (!ENV.ipGeolocationApiKey) throw new Error("IPGeolocation.io is not configured.");
  const url = new URL("https://api.ipgeolocation.io/ipgeo"); url.searchParams.set("apiKey", ENV.ipGeolocationApiKey); url.searchParams.set("ip", ip); url.searchParams.set("fields", "geo,organization,time_zone");
  const response = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(8_000) });
  if (!response.ok) throw new Error("IPGeolocation.io could not complete the lookup.");
  const data = await response.json() as IpGeolocationResponse;
  if (data.message || data.ip !== ip) throw new Error("IPGeolocation.io returned an unexpected result.");
  return data;
}

/** Runs only after analyst approval. The free IP-API plan is intentionally excluded because it requires HTTP. */
export async function lookupPublicIpLocation(ip: string): Promise<GeolocationLookup> {
  if (!isPublicIpv4(ip)) throw new Error("Only a public IPv4 source address can be enriched.");
  const [ipinfoResult, ipgeoResult, abuseResult] = await Promise.allSettled([ipinfo(ip), ipgeolocation(ip), lookupAbuseIpdb(ip)]);
  const info = ipinfoResult.status === "fulfilled" ? ipinfoResult.value : null;
  const geo = ipgeoResult.status === "fulfilled" ? ipgeoResult.value : null;
  const abuse = abuseResult.status === "fulfilled" ? abuseResult.value : null;
  const sources = [info && "ipinfo", geo && "ipgeolocation", abuse && "abuseipdb"].filter((value): value is string => Boolean(value));
  if (!sources.length) throw new Error("Configured IP intelligence sources are unavailable. No location was saved.");
  const infoCoordinates = info ? coordinates(info.loc) : { latitude: null, longitude: null };
  const latitude = infoCoordinates.latitude ?? finite(geo?.latitude, -90, 90);
  const longitude = infoCoordinates.longitude ?? finite(geo?.longitude, -180, 180);
  const sourceCount = [info, geo, abuse].filter(Boolean).length;
  const isTor = abuse?.usageType?.toLowerCase().includes("tor") ? 1 : 0;
  const isHosting = abuse?.usageType?.toLowerCase().includes("data center") || abuse?.usageType?.toLowerCase().includes("content delivery") ? 1 : 0;
  const isMobile = abuse?.usageType?.toLowerCase().includes("mobile") ? 1 : 0;
  const isVpn = 0;
  const infrastructureLabel: InfrastructureLabel = isTor ? "TOR_EXIT_NODE" : isHosting ? "CLOUD_HOSTING" : isMobile ? "MOBILE_NETWORK" : "RESIDENTIAL_ISP";
  const city = agreed([info?.city, geo?.city]);
  return { ip, country: string(geo?.country_name) || agreed([info?.country, geo?.country_code2, abuse?.countryCode]), countryCode: agreed([info?.country, geo?.country_code2, abuse?.countryCode]), region: string(info?.region) || string(geo?.state_prov), city, latitude, longitude, provider: sources.join(" + "), postal: string(info?.postal) || string(geo?.zipcode), timezone: string(info?.timezone) || string(geo?.time_zone?.name), asn: info?.asn || asn(geo?.asn), ispName: info?.ispName || string(geo?.isp) || abuse?.isp || null, organization: string(geo?.organization) || string(info?.org), isVpn, isTor, isHosting: isHosting ? 1 : 0, isMobile: isMobile ? 1 : 0, isSuspicious: isTor || isHosting ? 1 : 0, infrastructureLabel, abuseScore: abuse?.abuseConfidenceScore || 0, abuseReports: abuse?.totalReports || 0, lastReportedAt: abuse?.lastReportedAt || null, precisionConfidence: Math.min(100, (latitude !== null && longitude !== null ? 40 : 0) + (sourceCount >= 2 ? 30 : 0) + (sourceCount === 3 ? 20 : 0) + (city ? 10 : 0)), sourcesUsedJson: JSON.stringify(sources), sourcesAgreed: sourceCount };
}
