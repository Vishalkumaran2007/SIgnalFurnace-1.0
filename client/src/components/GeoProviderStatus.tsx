import { Database, MapPin, ShieldCheck } from "lucide-react";

type Location = { id: number; ip: string; provider: string; sourcesUsedJson?: string | null; sourcesAgreed?: number | null; precisionConfidence?: number | null; infrastructureLabel?: string | null; enrichedAt: Date | string; city?: string | null; region?: string | null; country?: string | null };

function sources(value: string | null | undefined) { try { const parsed = JSON.parse(value || "[]"); return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : []; } catch { return []; } }

export function GeoProviderStatus({ locations }: { locations: Location[] }) {
  const latest = locations[0];
  if (!latest) return null;
  const used = sources(latest.sourcesUsedJson);
  return <section className="geo-provider-status" aria-label="Geolocation source status"><div><ShieldCheck size={18} /><span><strong>Approximate network location</strong><small>Saved after analyst approval. It may identify an ISP, mail relay, or network point—not a device or person.</small></span></div><div><Database size={18} /><span><strong>{used.length ? `${used.length} encrypted source${used.length === 1 ? "" : "s"} used` : latest.provider}</strong><small>{used.length ? used.join(" · ") : "Provider details were not recorded for this older result"} · cached results may be reused for 24 hours.</small></span></div><div><MapPin size={18} /><span><strong>{latest.precisionConfidence ?? 0}% corroboration confidence</strong><small>{latest.infrastructureLabel ? latest.infrastructureLabel.replace(/_/g, " ") : "Network type not classified"} · IP-API free HTTP is intentionally disabled.</small></span></div></section>;
}
