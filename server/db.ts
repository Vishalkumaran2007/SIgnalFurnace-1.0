import { desc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { EmailArtifact, InsertUser, Investigation, emailArtifacts, indicators, investigationEvents, investigationNotes, investigations, ipGeolocations, ipReputations, urlReputations, users } from "../drizzle/schema";
import { ENV } from "./_core/env";
import { analyzeEmailContentWithAi, applyAiContentAssessment, type ParsedEmailAnalysis } from "./emailAnalysis";
import { lookupPublicIpLocation } from "./geolocation";
import { lookupAbuseIpdb } from "./threatIntel";
import { lookupVirusTotalIp } from "./virustotal";
import { lookupPhishTankUrl } from "./phishtank";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try { _db = drizzle(process.env.DATABASE_URL); } catch (error) { console.warn("[Database] Failed to connect:", error); _db = null; }
  }
  return _db;
}

async function requireDb() { const db = await getDb(); if (!db) throw new Error("Database is not available."); return db; }

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;
  const values: InsertUser = { openId: user.openId, lastSignedIn: user.lastSignedIn || new Date() };
  const updateSet: Record<string, unknown> = { lastSignedIn: values.lastSignedIn };
  (["name", "email", "loginMethod"] as const).forEach((field) => { if (user[field] !== undefined) { values[field] = user[field]; updateSet[field] = user[field]; } });
  values.role = user.role || (user.openId === ENV.ownerOpenId ? "admin" : "user");
  updateSet.role = values.role;
  await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
}

export async function getUserByOpenId(openId: string) { const db = await getDb(); if (!db) return undefined; return (await db.select().from(users).where(eq(users.openId, openId)).limit(1))[0]; }
export async function listAdministrativeUsers() { const db = await requireDb(); return db.select({ id: users.id, name: users.name, email: users.email, role: users.role, createdAt: users.createdAt, lastSignedIn: users.lastSignedIn }).from(users).orderBy(desc(users.lastSignedIn)); }
export async function setAdministrativeUserRole(userId: number, role: "user" | "admin") { const db = await requireDb(); await db.update(users).set({ role }).where(eq(users.id, userId)); }

type SaveAnalysis = { userId: number; filename: string; mimeType: string; storageKey: string; storageUrl: string; parsed: ParsedEmailAnalysis; };

export async function saveAnalysis(input: SaveAnalysis) {
  const db = await requireDb();
  const timestamp = Date.now().toString(36).toUpperCase();
  const caseNumber = `INV-${new Date().getFullYear()}-${timestamp}`;
  const investigationResult = await db.insert(investigations).values({ userId: input.userId, caseNumber, title: input.parsed.subject || input.filename, severity: input.parsed.severity, threatScore: input.parsed.threatScore, confidence: input.parsed.confidence, summary: input.parsed.summary });
  const investigationId = Number(investigationResult[0].insertId);
  const artifactResult = await db.insert(emailArtifacts).values({ investigationId, userId: input.userId, originalFilename: input.filename, storageKey: input.storageKey, storageUrl: input.storageUrl, mimeType: input.mimeType, sha256: input.parsed.sha256, sender: input.parsed.sender, recipient: input.parsed.recipient, subject: input.parsed.subject, messageId: input.parsed.messageId, sentAt: input.parsed.sentAt, bodyText: input.parsed.bodyText, rawHeaders: input.parsed.rawHeaders, spf: input.parsed.spf, dkim: input.parsed.dkim, dmarc: input.parsed.dmarc, replyTo: input.parsed.replyTo, returnPath: input.parsed.returnPath, originatingIp: input.parsed.originatingIp, urlsJson: JSON.stringify(input.parsed.urls), attachmentNamesJson: JSON.stringify(input.parsed.attachmentNames), findingsJson: JSON.stringify(input.parsed.findings), aiCategory: input.parsed.ai?.category, aiSummary: input.parsed.ai?.summary, aiSocialEngineering: input.parsed.ai?.socialEngineering, aiRecommendationsJson: input.parsed.ai ? JSON.stringify(input.parsed.ai.recommendations) : null, aiModel: input.parsed.ai?.model });
  await db.insert(indicators).values([...input.parsed.indicators, { type: "hash" as const, value: input.parsed.sha256, source: "evidence SHA-256" }].map((indicator) => ({ investigationId, userId: input.userId, ...indicator })));
  await db.insert(investigationEvents).values([{ investigationId, userId: input.userId, eventType: "email_uploaded", detail: `${input.filename} was uploaded and stored as evidence.` }, { investigationId, userId: input.userId, eventType: "structural_analysis", detail: input.parsed.summary }, ...(input.parsed.ai ? [{ investigationId, userId: input.userId, eventType: "ai_content_analysis", detail: `A bounded content assessment was completed with ${input.parsed.ai.model}.` }] : [])]);
  return { investigationId, artifactId: Number(artifactResult[0].insertId), caseNumber };
}

export async function listInvestigations(userId: number) { const db = await requireDb(); return db.select().from(investigations).where(eq(investigations.userId, userId)).orderBy(desc(investigations.createdAt)); }
export async function listIndicators(userId: number) { const db = await requireDb(); return db.select().from(indicators).where(eq(indicators.userId, userId)).orderBy(desc(indicators.createdAt)); }
export async function findSimilarInvestigations(userId: number, investigationId: number) {
  const target = await getInvestigation(userId, investigationId);
  if (!target) return null;
  const baseline = new Set(target.iocs.filter((ioc) => ioc.type !== "hash").map((ioc) => `${ioc.type}:${ioc.value.toLowerCase()}`));
  const findingKeys = (value: string | null | undefined) => {
    try { const findings = JSON.parse(value || "[]"); return new Set(Array.isArray(findings) ? findings.map((finding) => `${finding.kind}:${finding.severity}:${finding.detail}`) : []); } catch { return new Set<string>(); }
  };
  const targetFindings = findingKeys(target.artifact?.findingsJson);
  const targetAuthFailures = ["spf", "dkim", "dmarc"].filter((name) => target.artifact?.[name as "spf" | "dkim" | "dmarc"] === "fail");
  const all = await listIndicators(userId);
  const db = await requireDb();
  const artifacts = await db.select().from(emailArtifacts).where(eq(emailArtifacts.userId, userId));
  const matches = new Map<number, Array<{ type: string; value: string }>>();
  const addMatch = (id: number, match: { type: string; value: string }) => { const current = matches.get(id) || []; if (!current.some((item) => item.type === match.type && item.value === match.value)) current.push(match); matches.set(id, current); };
  all.forEach((indicator) => { if (indicator.investigationId !== investigationId && indicator.type !== "hash" && baseline.has(`${indicator.type}:${indicator.value.toLowerCase()}`)) addMatch(indicator.investigationId, { type: indicator.type, value: indicator.value }); });
  artifacts.filter((artifact) => artifact.investigationId !== investigationId).forEach((artifact) => {
    const candidateFindings = findingKeys(artifact.findingsJson);
    targetFindings.forEach((finding) => { if (candidateFindings.has(finding)) addMatch(artifact.investigationId, { type: "local finding", value: finding.replace(/:/g, " · ") }); });
    targetAuthFailures.forEach((header) => { if (artifact[header as "spf" | "dkim" | "dmarc"] === "fail") addMatch(artifact.investigationId, { type: "header signal", value: `${header.toUpperCase()} failed` }); });
  });
  const cases = await listInvestigations(userId);
  return cases.filter((item) => matches.has(item.id)).map((item) => ({ ...item, matches: matches.get(item.id) || [] })).sort((a, b) => b.matches.length - a.matches.length);
}
export async function getInvestigation(userId: number, id: number) { const db = await requireDb(); const investigation = (await db.select().from(investigations).where(eq(investigations.id, id)).limit(1))[0]; if (!investigation || investigation.userId !== userId) return null; const artifact = (await db.select().from(emailArtifacts).where(eq(emailArtifacts.investigationId, id)).limit(1))[0]; const iocs = await db.select().from(indicators).where(eq(indicators.investigationId, id)); const events = await db.select().from(investigationEvents).where(eq(investigationEvents.investigationId, id)).orderBy(desc(investigationEvents.createdAt)); const notes = await db.select().from(investigationNotes).where(eq(investigationNotes.investigationId, id)).orderBy(desc(investigationNotes.createdAt)); const reputations = await db.select().from(ipReputations).where(eq(ipReputations.investigationId, id)).orderBy(desc(ipReputations.enrichedAt)); const urlReputationsForCase = await db.select().from(urlReputations).where(eq(urlReputations.investigationId, id)).orderBy(desc(urlReputations.enrichedAt)); return { investigation, artifact, iocs, events, notes, reputations, urlReputations: urlReputationsForCase }; }
export async function addInvestigationNote(userId: number, investigationId: number, content: string) { const detail = await getInvestigation(userId, investigationId); if (!detail) throw new Error("Investigation not found."); const db = await requireDb(); await db.insert(investigationNotes).values({ investigationId, userId, content }); await db.insert(investigationEvents).values({ investigationId, userId, eventType: "analyst_note", detail: "An analyst note was added." }); }
export async function updateInvestigationStatus(userId: number, investigationId: number, status: "open" | "in_progress" | "resolved" | "closed") { const detail = await getInvestigation(userId, investigationId); if (!detail) throw new Error("Investigation not found."); const db = await requireDb(); await db.update(investigations).set({ status }).where(eq(investigations.id, investigationId)); await db.insert(investigationEvents).values({ investigationId, userId, eventType: "case_status", detail: `Case status changed to ${status.replace(/_/g, " ")}.` }); }
export async function rerunInvestigationAiReview(userId: number, investigationId: number) {
  const detail = await getInvestigation(userId, investigationId);
  if (!detail?.artifact) throw new Error("Email evidence was not found for this case.");
  const safeArray = (value: string | null) => { try { const parsed = JSON.parse(value || "[]"); return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : []; } catch { return []; } };
  const assessment = await analyzeEmailContentWithAi({ sender: detail.artifact.sender, recipient: detail.artifact.recipient, subject: detail.artifact.subject, bodyText: detail.artifact.bodyText || "", urls: safeArray(detail.artifact.urlsJson), attachmentNames: safeArray(detail.artifact.attachmentNamesJson), reasons: [] });
  if (!assessment) throw new Error("The bounded AI service did not return a complete structured assessment. Please try again later.");
  const scored = applyAiContentAssessment({ threatScore: detail.investigation.threatScore, confidence: detail.investigation.confidence, severity: detail.investigation.severity, summary: detail.investigation.summary, reasons: [], ai: null } as unknown as ParsedEmailAnalysis, assessment);
  const db = await requireDb();
  await db.update(investigations).set({ threatScore: scored.threatScore, confidence: scored.confidence, severity: scored.severity, summary: scored.summary }).where(eq(investigations.id, investigationId));
  await db.update(emailArtifacts).set({ aiCategory: assessment.category, aiSummary: assessment.summary, aiSocialEngineering: assessment.socialEngineering, aiRecommendationsJson: JSON.stringify(assessment.recommendations), aiModel: assessment.model }).where(eq(emailArtifacts.id, detail.artifact.id));
  await db.insert(investigationEvents).values({ investigationId, userId, eventType: "ai_content_analysis", detail: `A bounded content assessment was completed with ${assessment.model}.` });
  return getInvestigation(userId, investigationId);
}
export async function recordInvestigationEvent(userId: number, investigationId: number, eventType: string, detail: string) { const investigation = await getInvestigation(userId, investigationId); if (!investigation) throw new Error("Investigation not found."); const db = await requireDb(); await db.insert(investigationEvents).values({ investigationId, userId, eventType, detail }); }
export async function getDashboardSummary(userId: number) { const cases = await listInvestigations(userId); return { cases, total: cases.length, highRisk: cases.filter((item) => item.severity === "high" || item.severity === "critical").length, open: cases.filter((item) => item.status === "open" || item.status === "in_progress").length }; }
export async function listGeolocations(userId: number) { const db = await requireDb(); return db.select().from(ipGeolocations).where(eq(ipGeolocations.userId, userId)).orderBy(desc(ipGeolocations.enrichedAt)); }
export async function enrichInvestigationGeolocation(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const ip = detail.artifact.originatingIp; if (!ip) throw new Error("No source IP was extracted from this email."); const db = await requireDb(); const existing = (await db.select().from(ipGeolocations).where(eq(ipGeolocations.investigationId, investigationId)).limit(1))[0]; if (existing) return existing; const location = await lookupPublicIpLocation(ip); const result = await db.insert(ipGeolocations).values({ investigationId, artifactId: detail.artifact.id, userId, ...location }); const saved = (await db.select().from(ipGeolocations).where(eq(ipGeolocations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "ip_geolocation", detail: `An analyst approved an approximate ${location.provider} location lookup for the extracted source IP.` }); return saved; }
export async function listIpReputations(userId: number) { const db = await requireDb(); return db.select().from(ipReputations).where(eq(ipReputations.userId, userId)).orderBy(desc(ipReputations.enrichedAt)); }
export async function enrichInvestigationReputation(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const ip = detail.artifact.originatingIp; if (!ip) throw new Error("No source IP was extracted from this email."); const db = await requireDb(); const existing = (await db.select().from(ipReputations).where(eq(ipReputations.investigationId, investigationId))).find((item) => item.provider === "AbuseIPDB"); if (existing) return existing; const reputation = await lookupAbuseIpdb(ip); const result = await db.insert(ipReputations).values({ investigationId, artifactId: detail.artifact.id, userId, ...reputation }); const saved = (await db.select().from(ipReputations).where(eq(ipReputations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "abuseipdb_reputation", detail: `An analyst approved an AbuseIPDB reputation lookup for the extracted source IP. Confidence score: ${reputation.abuseConfidenceScore}/100.` }); return saved; }
export async function enrichInvestigationVirusTotal(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const ip = detail.artifact.originatingIp; if (!ip) throw new Error("No source IP was extracted from this email."); const db = await requireDb(); const existing = (await db.select().from(ipReputations).where(eq(ipReputations.investigationId, investigationId))).find((item) => item.provider === "VirusTotal"); if (existing) return existing; const reputation = await lookupVirusTotalIp(ip); const result = await db.insert(ipReputations).values({ investigationId, artifactId: detail.artifact.id, userId, ...reputation }); const saved = (await db.select().from(ipReputations).where(eq(ipReputations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "virustotal_reputation", detail: `An analyst approved a VirusTotal reputation lookup for the extracted source IP. Malicious: ${reputation.malicious}; suspicious: ${reputation.suspicious}.` }); return saved; }
export async function enrichInvestigationPhishTank(userId: number, investigationId: number, url: string) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); if (!detail.iocs.some((indicator) => indicator.type === "url" && indicator.value === url)) throw new Error("Select a URL extracted from this private case."); const db = await requireDb(); const existing = (await db.select().from(urlReputations).where(eq(urlReputations.investigationId, investigationId))).find((item) => item.provider === "PhishTank" && item.url === url); if (existing) return existing; const reputation = await lookupPhishTankUrl(url); const result = await db.insert(urlReputations).values({ investigationId, artifactId: detail.artifact.id, userId, ...reputation }); const saved = (await db.select().from(urlReputations).where(eq(urlReputations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "phishtank_reputation", detail: `An analyst approved a PhishTank public-feed lookup for ${reputation.url}. ${reputation.inDatabase ? `Matched verified phish ID ${reputation.phishId || "unknown"}.` : "No verified online match was found in the current feed."}` }); return saved; }
export type { Investigation, EmailArtifact };
