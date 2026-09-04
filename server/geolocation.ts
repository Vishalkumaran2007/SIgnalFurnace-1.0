export type GeolocationLookup = {
  ip: string;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  latitude: number;
  longitude: number;
  provider: "ipwho.is";
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

export async function lookupPublicIpLocation(ip: string): Promise<GeolocationLookup> {
  if (!isPublicIpv4(ip)) throw new Error("Only a public IPv4 source address can be enriched.");
  const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(8_000), headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("The location provider could not be reached.");
  const data = await response.json() as Record<string, unknown>;
  if (data.success !== true || typeof data.latitude !== "number" || typeof data.longitude !== "number") throw new Error("The location provider did not return usable coordinates.");
  return { ip, country: typeof data.country === "string" ? data.country : null, countryCode: typeof data.country_code === "string" ? data.country_code : null, region: typeof data.region === "string" ? data.region : null, city: typeof data.city === "string" ? data.city : null, latitude: data.latitude, longitude: data.longitude, provider: "ipwho.is" };
}
