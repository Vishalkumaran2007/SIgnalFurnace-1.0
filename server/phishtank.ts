import { Readable } from "node:stream";
import unbzip2stream from "unbzip2-stream";

type PhishTankEntry = { url?: unknown; phish_id?: unknown; verified?: unknown; online?: unknown; target?: unknown; verification_time?: unknown; };
type FeedCache = { fetchedAt: Date; entries: Map<string, PhishTankEntry> };
let cache: FeedCache | null = null;
let pendingFeed: Promise<FeedCache> | null = null;
const FEED_TTL_MS = 4 * 60 * 60 * 1000;
const FEED_URL = "https://data.phishtank.com/data/online-valid.json.bz2";
const USER_AGENT = "OriginTracker-SIH26106/1.0 contact: project-owner";

function normalizeUrl(value: string) { const url = new URL(value); url.hash = ""; return url.toString(); }
function dateOrNull(value: unknown) { const date = typeof value === "string" ? new Date(value) : null; return date && !Number.isNaN(date.getTime()) ? date : null; }

async function decompressBzip2(buffer: Buffer) {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    const decoder = unbzip2stream();
    decoder.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
    decoder.on("error", reject);
    decoder.on("end", () => resolve(Buffer.concat(chunks)));
    Readable.from(buffer).on("error", reject).pipe(decoder);
  });
}

async function loadFeed(): Promise<FeedCache> {
  if (cache && Date.now() - cache.fetchedAt.getTime() < FEED_TTL_MS) return cache;
  if (pendingFeed) return pendingFeed;
  pendingFeed = (async () => {
    const response = await fetch(FEED_URL, { headers: { "User-Agent": USER_AGENT, Accept: "application/x-bzip2" }, signal: AbortSignal.timeout(30_000) });
    if (!response.ok) throw new Error("PhishTank's public feed is unavailable right now.");
    const compressed = Buffer.from(await response.arrayBuffer());
    if (!compressed.length || compressed.length > 6 * 1024 * 1024) throw new Error("PhishTank's feed exceeded the safe download size.");
    const decoded = await decompressBzip2(compressed);
    if (decoded.length > 80 * 1024 * 1024) throw new Error("PhishTank's feed exceeded the safe decompressed size.");
    const parsed = JSON.parse(decoded.toString("utf8")) as PhishTankEntry[];
    if (!Array.isArray(parsed) || parsed.length > 500_000) throw new Error("PhishTank returned an unexpected feed.");
    const entries = new Map<string, PhishTankEntry>();
    parsed.forEach((entry) => { if (typeof entry.url !== "string") return; try { entries.set(normalizeUrl(entry.url), entry); } catch { /* Ignore malformed feed entry. */ } });
    cache = { fetchedAt: new Date(), entries };
    return cache;
  })();
  try { return await pendingFeed; } finally { pendingFeed = null; }
}

export type PhishTankReputation = { url: string; provider: "PhishTank"; inDatabase: number; phishId: number | null; verified: number; online: number; target: string | null; verifiedAt: Date | null; feedUpdatedAt: Date; rawJson: string; };

export async function lookupPhishTankUrl(url: string): Promise<PhishTankReputation> {
  const normalizedUrl = normalizeUrl(url);
  const feed = await loadFeed();
  const entry = feed.entries.get(normalizedUrl);
  const phishId = typeof entry?.phish_id === "number" ? Math.trunc(entry.phish_id) : null;
  return { url: normalizedUrl, provider: "PhishTank", inDatabase: entry ? 1 : 0, phishId, verified: entry?.verified === "yes" ? 1 : 0, online: entry?.online === "yes" ? 1 : 0, target: typeof entry?.target === "string" && entry.target.trim() ? entry.target.slice(0, 512) : null, verifiedAt: dateOrNull(entry?.verification_time), feedUpdatedAt: feed.fetchedAt, rawJson: JSON.stringify(entry || { normalizedUrl, matched: false }) };
}

export function __resetPhishTankCacheForTests() { cache = null; pendingFeed = null; }
