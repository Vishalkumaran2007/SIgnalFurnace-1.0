import { ENV } from "./_core/env";

export type GeolocationLookup = {
  ip: string;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  latitude: number;
  longitude: number;
  provider: "IPGeolocation.io";
};

export function isPublicIpv4(ip: string) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [first, second] = parts;
  if (first === 0 || first === 10 || first === 127 || first >= 224) return false;
  if (first === 169 && second === 254) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && second === 168) return false;
  if ((first === 192 && second === 0 && parts[2] === 2) || (first === 198 && second === 51 && parts[2] === 100) || (first === 203 && second === 0 && parts[2] === 113)) return false;
  return true;
}

function finiteCoordinate(value: unknown, min: number, max: number) {
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}

export async function lookupPublicIpLocation(ip: string): Promise<GeolocationLookup> {
  if (!isPublicIpv4(ip)) throw new Error("Only a public IPv4 source address can be enriched.");
  if (!ENV.ipGeolocationApiKey) throw new Error("IP geolocation is not configured for this environment.");
  const url = new URL("https://api.ipgeolocation.io/ipgeo");
  url.searchParams.set("apiKey", ENV.ipGeolocationApiKey);
  url.searchParams.set("ip", ip);
  url.searchParams.set("fields", "geo");
  const response = await fetch(url, { signal: AbortSignal.timeout(8_000), headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("The IP geolocation provider could not be reached.");
  const data = await response.json() as Record<string, unknown>;
  if (typeof data.message === "string" && data.message.trim()) throw new Error("The IP geolocation provider rejected the lookup.");
  const latitude = finiteCoordinate(data.latitude, -90, 90);
  const longitude = finiteCoordinate(data.longitude, -180, 180);
  if (latitude === null || longitude === null) throw new Error("The IP geolocation provider did not return usable coordinates.");
  return { ip, country: typeof data.country_name === "string" ? data.country_name : null, countryCode: typeof data.country_code2 === "string" ? data.country_code2 : null, region: typeof data.state_prov === "string" ? data.state_prov : null, city: typeof data.city === "string" ? data.city : null, latitude, longitude, provider: "IPGeolocation.io" };
}
