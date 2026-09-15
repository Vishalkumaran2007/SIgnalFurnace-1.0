import { and, desc, eq, gt } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { createHash } from "node:crypto";
import { EmailArtifact, InsertUser, Investigation, assistantChatMessages, campaigns, emailArtifacts, evidenceChain, indicators, investigationEvents, investigationNotes, investigations, iocRecords, ipGeoCache, ipGeolocations, ipReputations, securityAuditEvents, urlReputations, users } from "../drizzle/schema";
import { ENV } from "./_core/env";
import { analyzeEmailContentWithAi, applyAiContentAssessment, type ParsedEmailAnalysis } from "./emailAnalysis";
import { lookupPublicIpLocation, type GeolocationLookup } from "./geolocation";
import { lookupAbuseIpdb } from "./threatIntel";
import { lookupVirusTotalFileHash, lookupVirusTotalIp } from "./virustotal";
import { lookupPhishTankUrl } from "./phishtank";
import { withVirusTotalAttachmentResult, type AttachmentAnalysis } from "./attachmentAnalysis";

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

export async function recordSecurityAuditEvent(input: { userId: number; actorRole: "user" | "admin"; eventType: string; resourceType?: string; resourceId?: string; metadata?: Record<string, string | number | boolean | null> }) {
  const db = await requireDb();
  const metadataJson = input.metadata ? JSON.stringify(input.metadata) : null;
  await db.insert(securityAuditEvents).values({ userId: input.userId, actorRole: input.actorRole, eventType: input.eventType.slice(0, 128), resourceType: input.resourceType?.slice(0, 128), resourceId: input.resourceId?.slice(0, 128), metadataJson });
}

export async function listSecurityAuditEvents(limit = 100) {
  const db = await requireDb();
  return db.select().from(securityAuditEvents).orderBy(desc(securityAuditEvents.createdAt)).limit(Math.min(Math.max(limit, 1), 250));
}
export async function listAssistantChatHistory(userId: number) { const db = await requireDb(); const rows = await db.select().from(assistantChatMessages).where(eq(assistantChatMessages.userId, userId)).orderBy(desc(assistantChatMessages.createdAt)).limit(24); return rows.reverse(); }
export async function saveAssistantChatMessage(userId: number, role: "user" | "assistant", content: string) { const db = await requireDb(); await db.insert(assistantChatMessages).values({ userId, role, content }); }

type SaveAnalysis = { userId: number; filename: string; mimeType: string; storageKey: string; storageUrl: string; parsed: ParsedEmailAnalysis; };

function hashChain(parts: string[]) { return createHash("sha256").update(parts.join(":"), "utf8").digest("hex"); }
const GENESIS_HASH = "0".repeat(64);

async function appendEvidenceChainBlock(userId: number, investigationId: number, evidenceHash: string) {
  const db = await requireDb();
  const previous = (await db.select().from(evidenceChain).orderBy(desc(evidenceChain.blockNumber)).limit(1))[0];
  const blockNumber = (previous?.blockNumber || 0) + 1;
  const previousHash = previous?.merkleRoot || GENESIS_HASH;
  const merkleRoot = hashChain([String(blockNumber), evidenceHash, previousHash, String(userId)]);
  await db.insert(evidenceChain).values({ caseId: investigationId, blockNumber, evidenceHash, previousHash, merkleRoot, analystId: userId });
  return { blockNumber, evidenceHash, previousHash, merkleRoot };
}

async function recordIocCampaigns(userId: number, investigationId: number, parsed: ParsedEmailAnalysis) {
  const db = await requireDb();
  const iocs = [...parsed.indicators, { type: "hash" as const, value: parsed.sha256, source: "evidence SHA-256" }];
  await db.insert(iocRecords).values(iocs.map((ioc) => ({ caseId: investigationId, userId, type: ioc.type, value: ioc.value })));
  const all = await db.select().from(iocRecords).where(eq(iocRecords.userId, userId));
  const grouped = new Map<string, { type: "ip" | "domain" | "url" | "email" | "hash"; value: string; caseIds: Set<number>; firstSeen: Date; lastSeen: Date }>();
  all.forEach((ioc) => {
    const key = `${ioc.type}:${ioc.value.toLowerCase()}`;
    const current = grouped.get(key) || { type: ioc.type, value: ioc.value, caseIds: new Set<number>(), firstSeen: ioc.firstSeen, lastSeen: ioc.lastSeen };
    current.caseIds.add(ioc.caseId);
    if (ioc.firstSeen < current.firstSeen) current.firstSeen = ioc.firstSeen;
    if (ioc.lastSeen > current.lastSeen) current.lastSeen = ioc.lastSeen;
    grouped.set(key, current);
  });
  const existing = await db.select().from(campaigns).where(eq(campaigns.userId, userId));
  for (const group of Array.from(grouped.values())) {
    if (group.caseIds.size < 2 || group.type === "hash") continue;
    const caseIds = Array.from(group.caseIds).sort((a, b) => a - b);
    const name = `${group.type.toUpperCase()} correlation · ${group.value.slice(0, 92)}`;
    const current = existing.find((campaign) => campaign.iocType === group.type && campaign.iocValue.toLowerCase() === group.value.toLowerCase());
    const values = { name, caseIds, caseCount: caseIds.length, firstSeen: group.firstSeen, lastSeen: group.lastSeen };
    if (current) await db.update(campaigns).set(values).where(eq(campaigns.id, current.id));
    else await db.insert(campaigns).values({ userId, iocType: group.type, iocValue: group.value, ...values });
  }
}

export async function saveAnalysis(input: SaveAnalysis) {
  const db = await requireDb();
  const timestamp = Date.now().toString(36).toUpperCase();
  const caseNumber = `INV-${new Date().getFullYear()}-${timestamp}`;
  const investigationResult = await db.insert(investigations).values({ userId: input.userId, caseNumber, title: input.parsed.subject || input.filename, severity: input.parsed.severity, threatScore: input.parsed.threatScore, confidence: input.parsed.confidence, summary: input.parsed.summary });
  const investigationId = Number(investigationResult[0].insertId);
  const artifactResult = await db.insert(emailArtifacts).values({ investigationId, userId: input.userId, originalFilename: input.filename, storageKey: input.storageKey, storageUrl: input.storageUrl, mimeType: input.mimeType, sha256: input.parsed.sha256, sender: input.parsed.sender, recipient: input.parsed.recipient, subject: input.parsed.subject, messageId: input.parsed.messageId, sentAt: input.parsed.sentAt, bodyText: input.parsed.bodyText, rawHeaders: input.parsed.rawHeaders, spf: input.parsed.spf, dkim: input.parsed.dkim, dmarc: input.parsed.dmarc, replyTo: input.parsed.replyTo, returnPath: input.parsed.returnPath, originatingIp: input.parsed.originatingIp, urlsJson: JSON.stringify(input.parsed.urls), attachmentNamesJson: JSON.stringify(input.parsed.attachmentNames), attachmentAnalysisJson: JSON.stringify(input.parsed.attachmentAnalysis), findingsJson: JSON.stringify(input.parsed.findings), aiCategory: input.parsed.ai?.category, aiSummary: input.parsed.ai?.summary, aiSocialEngineering: input.parsed.ai?.socialEngineering, aiRecommendationsJson: input.parsed.ai ? JSON.stringify(input.parsed.ai.recommendations) : null, aiModel: input.parsed.ai?.model });
  await db.insert(indicators).values([...input.parsed.indicators, { type: "hash" as const, value: input.parsed.sha256, source: "evidence SHA-256" }].map((indicator) => ({ investigationId, userId: input.userId, ...indicator })));
  const block = await appendEvidenceChainBlock(input.userId, investigationId, input.parsed.sha256);
  await recordIocCampaigns(input.userId, investigationId, input.parsed);
  await db.insert(investigationEvents).values([{ investigationId, userId: input.userId, eventType: "email_uploaded", detail: `${input.filename} was uploaded and stored as evidence.` }, { investigationId, userId: input.userId, eventType: "evidence_chain", detail: `Tamper-evident evidence record #${block.blockNumber} was created for the uploaded SHA-256 hash.` }, { investigationId, userId: input.userId, eventType: "structural_analysis", detail: input.parsed.summary }, ...(input.parsed.ai ? [{ investigationId, userId: input.userId, eventType: "ai_content_analysis", detail: `A bounded content assessment was completed with ${input.parsed.ai.model}.` }] : [])]);
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
export async function getInvestigation(userId: number, id: number) { const db = await requireDb(); const investigation = (await db.select().from(investigations).where(eq(investigations.id, id)).limit(1))[0]; if (!investigation || investigation.userId !== userId) return null; const artifact = (await db.select().from(emailArtifacts).where(eq(emailArtifacts.investigationId, id)).limit(1))[0]; const iocs = await db.select().from(indicators).where(eq(indicators.investigationId, id)); const events = await db.select().from(investigationEvents).where(eq(investigationEvents.investigationId, id)).orderBy(desc(investigationEvents.createdAt)); const notes = await db.select().from(investigationNotes).where(eq(investigationNotes.investigationId, id)).orderBy(desc(investigationNotes.createdAt)); const reputations = await db.select().from(ipReputations).where(eq(ipReputations.investigationId, id)).orderBy(desc(ipReputations.enrichedAt)); const urlReputationsForCase = await db.select().from(urlReputations).where(eq(urlReputations.investigationId, id)).orderBy(desc(urlReputations.enrichedAt)); const chain = await db.select().from(evidenceChain).where(eq(evidenceChain.caseId, id)).orderBy(desc(evidenceChain.blockNumber)); const campaignRows = (await db.select().from(campaigns).where(eq(campaigns.userId, userId))).filter((campaign) => campaign.caseIds.includes(id)); return { investigation, artifact, iocs, events, notes, reputations, urlReputations: urlReputationsForCase, evidenceChain: chain, campaigns: campaignRows }; }
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
async function cachedLocation(ip: string) { const db = await requireDb(); const entry = (await db.select().from(ipGeoCache).where(and(eq(ipGeoCache.ip, ip), gt(ipGeoCache.expiresAt, new Date()))).limit(1))[0]; if (!entry) return null; const value = entry.resultJson as Record<string, unknown>; return { ...value, lastReportedAt: typeof value.lastReportedAt === "string" ? new Date(value.lastReportedAt) : null } as GeolocationLookup; }
export async function enrichInvestigationGeolocation(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const ip = detail.artifact.originatingIp; if (!ip) throw new Error("No source IP was extracted from this email."); const db = await requireDb(); const existing = (await db.select().from(ipGeolocations).where(eq(ipGeolocations.investigationId, investigationId)).limit(1))[0]; if (existing) return existing; const cached = await cachedLocation(ip); const location = cached || await lookupPublicIpLocation(ip); if (!cached) { const resultJson = { ...location, lastReportedAt: location.lastReportedAt?.toISOString() || null }; await db.insert(ipGeoCache).values({ ip, resultJson, expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) }).onDuplicateKeyUpdate({ set: { resultJson, fetchedAt: new Date(), expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) } }); } const result = await db.insert(ipGeolocations).values({ investigationId, artifactId: detail.artifact.id, userId, ...location }); const saved = (await db.select().from(ipGeolocations).where(eq(ipGeolocations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "ip_geolocation", detail: `An analyst approved an approximate location lookup for the extracted source IP using ${location.provider}${cached ? " from the private 24-hour cache" : ""}.` }); return saved; }

export async function enrichInvestigationAttachmentVirusTotal(userId: number, investigationId: number, attachmentHash: string) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const parsed = JSON.parse(detail.artifact.attachmentAnalysisJson || "[]") as AttachmentAnalysis[]; const attachment = parsed.find((item) => item.attachmentHash === attachmentHash); if (!attachment) throw new Error("Select an attachment hash recorded for this private case."); const stats = await lookupVirusTotalFileHash(attachmentHash); const updated = parsed.map((item) => item.attachmentHash === attachmentHash ? withVirusTotalAttachmentResult(item, stats) : item); const db = await requireDb(); await db.update(emailArtifacts).set({ attachmentAnalysisJson: JSON.stringify(updated) }).where(eq(emailArtifacts.id, detail.artifact.id)); await db.insert(investigationEvents).values({ investigationId, userId, eventType: "virustotal_attachment", detail: `An analyst approved a VirusTotal hash check for attachment ${attachment.filename}. Malicious: ${stats.malicious}; suspicious: ${stats.suspicious}.` }); return updated.find((item) => item.attachmentHash === attachmentHash)!; }

export async function verifyInvestigationEvidenceChain(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail) throw new Error("Investigation not found."); const db = await requireDb(); const analystBlocks = await db.select().from(evidenceChain).where(eq(evidenceChain.analystId, userId)).orderBy(evidenceChain.blockNumber); let expectedPrevious = GENESIS_HASH; const valid = analystBlocks.every((block) => { const expectedRoot = hashChain([String(block.blockNumber), block.evidenceHash, expectedPrevious, String(block.analystId)]); const linked = block.previousHash === expectedPrevious; expectedPrevious = block.merkleRoot; return linked && block.merkleRoot === expectedRoot; }); const caseBlocks = analystBlocks.filter((block) => block.caseId === investigationId); return { valid, blocks: caseBlocks.length, latestRoot: caseBlocks.at(-1)?.merkleRoot || null }; }
export async function listCampaigns(userId: number) { const db = await requireDb(); return db.select().from(campaigns).where(eq(campaigns.userId, userId)).orderBy(desc(campaigns.lastSeen)); }
export async function listIpReputations(userId: number) { const db = await requireDb(); return db.select().from(ipReputations).where(eq(ipReputations.userId, userId)).orderBy(desc(ipReputations.enrichedAt)); }
export async function enrichInvestigationReputation(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const ip = detail.artifact.originatingIp; if (!ip) throw new Error("No source IP was extracted from this email."); const db = await requireDb(); const existing = (await db.select().from(ipReputations).where(eq(ipReputations.investigationId, investigationId))).find((item) => item.provider === "AbuseIPDB"); if (existing) return existing; const reputation = await lookupAbuseIpdb(ip); const result = await db.insert(ipReputations).values({ investigationId, artifactId: detail.artifact.id, userId, ...reputation }); const saved = (await db.select().from(ipReputations).where(eq(ipReputations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "abuseipdb_reputation", detail: `An analyst approved an AbuseIPDB reputation lookup for the extracted source IP. Confidence score: ${reputation.abuseConfidenceScore}/100.` }); return saved; }
export async function enrichInvestigationVirusTotal(userId: number, investigationId: number) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); const ip = detail.artifact.originatingIp; if (!ip) throw new Error("No source IP was extracted from this email."); const db = await requireDb(); const existing = (await db.select().from(ipReputations).where(eq(ipReputations.investigationId, investigationId))).find((item) => item.provider === "VirusTotal"); if (existing) return existing; const reputation = await lookupVirusTotalIp(ip); const result = await db.insert(ipReputations).values({ investigationId, artifactId: detail.artifact.id, userId, ...reputation }); const saved = (await db.select().from(ipReputations).where(eq(ipReputations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "virustotal_reputation", detail: `An analyst approved a VirusTotal reputation lookup for the extracted source IP. Malicious: ${reputation.malicious}; suspicious: ${reputation.suspicious}.` }); return saved; }
export async function enrichInvestigationPhishTank(userId: number, investigationId: number, url: string) { const detail = await getInvestigation(userId, investigationId); if (!detail?.artifact) throw new Error("Email evidence was not found for this case."); if (!detail.iocs.some((indicator) => indicator.type === "url" && indicator.value === url)) throw new Error("Select a URL extracted from this private case."); const db = await requireDb(); const existing = (await db.select().from(urlReputations).where(eq(urlReputations.investigationId, investigationId))).find((item) => item.provider === "PhishTank" && item.url === url); if (existing) return existing; const reputation = await lookupPhishTankUrl(url); const result = await db.insert(urlReputations).values({ investigationId, artifactId: detail.artifact.id, userId, ...reputation }); const saved = (await db.select().from(urlReputations).where(eq(urlReputations.id, Number(result[0].insertId))).limit(1))[0]; await db.insert(investigationEvents).values({ investigationId, userId, eventType: "phishtank_reputation", detail: `An analyst approved a PhishTank public-feed lookup for ${reputation.url}. ${reputation.inDatabase ? `Matched verified phish ID ${reputation.phishId || "unknown"}.` : "No verified online match was found in the current feed."}` }); return saved; }
export type { Investigation, EmailArtifact };
