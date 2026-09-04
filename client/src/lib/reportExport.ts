import { jsPDF } from "jspdf";

type ReportDetail = {
  investigation: { caseNumber: string; title: string; status: string; severity: string; threatScore: number; confidence: number; summary: string | null; createdAt: Date | string };
  artifact?: { originalFilename: string; sha256: string; sender: string | null; recipient: string | null; subject: string | null; spf: string; dkim: string; dmarc: string; aiCategory: string | null; aiSummary: string | null; aiSocialEngineering: string | null; aiRecommendationsJson: string | null; aiModel: string | null } | null;
  iocs: Array<{ type: string; value: string; source: string }>;
  reputations?: Array<{ ip: string; provider: string; abuseConfidenceScore: number; totalReports: number; numDistinctUsers: number; isWhitelisted: number; countryCode: string | null; usageType: string | null; isp: string | null; domain: string | null; enrichedAt: Date | string }>;
  urlReputations?: Array<{ url: string; provider: string; inDatabase: number; phishId: number | null; verified: number; online: number; target: string | null; feedUpdatedAt: Date | string | null }>;
  events: Array<{ eventType: string; detail: string; createdAt: Date | string }>;
  notes: Array<{ content: string; createdAt: Date | string }>;
};

function safeCell(value: unknown) {
  const text = String(value ?? "").replace(/[\r\n]+/g, " ");
  const protectedText = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${protectedText.replace(/"/g, '""')}"`;
}

function reportFilename(detail: ReportDetail, extension: "csv" | "pdf") {
  return `${detail.investigation.caseNumber.replace(/[^a-zA-Z0-9_-]/g, "_")}-report.${extension}`;
}

function parseRecommendations(value: string | null | undefined) {
  try { const parsed = JSON.parse(value || "[]"); return Array.isArray(parsed) ? parsed.map(String).join("; ") : ""; } catch { return ""; }
}

export function buildCaseCsv(detail: ReportDetail) {
  const rows: Array<[string, string]> = [
    ["Report type", "Origin Tracker investigation export"],
    ["Case number", detail.investigation.caseNumber],
    ["Case title", detail.investigation.title],
    ["Status", detail.investigation.status],
    ["Severity", detail.investigation.severity],
    ["Threat score", `${detail.investigation.threatScore}/100`],
    ["Confidence", `${detail.investigation.confidence}%`],
    ["Created", new Date(detail.investigation.createdAt).toLocaleString()],
    ["Summary", detail.investigation.summary || ""],
    ["Evidence file", detail.artifact?.originalFilename || ""],
    ["Evidence SHA-256", detail.artifact?.sha256 || ""],
    ["Sender", detail.artifact?.sender || ""],
    ["Recipient", detail.artifact?.recipient || ""],
    ["Subject", detail.artifact?.subject || ""],
    ["SPF", detail.artifact?.spf || ""],
    ["DKIM", detail.artifact?.dkim || ""],
    ["DMARC", detail.artifact?.dmarc || ""],
    ["AI category", detail.artifact?.aiCategory || ""],
    ["AI model", detail.artifact?.aiModel || ""],
    ["AI summary", detail.artifact?.aiSummary || ""],
    ["AI social engineering", detail.artifact?.aiSocialEngineering || ""],
    ["AI recommendations", parseRecommendations(detail.artifact?.aiRecommendationsJson)],
  ];
  detail.iocs.forEach((ioc) => rows.push([`IOC ${ioc.type}`, `${ioc.value} (${ioc.source})`]));
  detail.reputations?.forEach((reputation) => rows.push([`Reputation ${reputation.provider}`, `${reputation.ip}: abuse confidence ${reputation.abuseConfidenceScore}/100; reports ${reputation.totalReports}; reporting users ${reputation.numDistinctUsers}; whitelisted ${reputation.isWhitelisted ? "yes" : "no"}; ${[reputation.usageType, reputation.isp, reputation.domain, reputation.countryCode].filter(Boolean).join(" · ")}`]));
  detail.urlReputations?.forEach((reputation) => rows.push([`Reputation ${reputation.provider}`, `${reputation.url}: ${reputation.inDatabase ? `verified ${reputation.online ? "online " : ""}phish${reputation.phishId ? ` ID ${reputation.phishId}` : ""}${reputation.target ? ` · target ${reputation.target}` : ""}` : "no verified online match in the feed"}`]));
  detail.events.forEach((event) => rows.push([`Timeline ${new Date(event.createdAt).toLocaleString()}`, `${event.eventType}: ${event.detail}`]));
  detail.notes.forEach((note) => rows.push([`Analyst note ${new Date(note.createdAt).toLocaleString()}`, note.content]));
  return rows.map(([key, value]) => `${safeCell(key)},${safeCell(value)}`).join("\n");
}

function download(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function downloadCaseCsv(detail: ReportDetail) {
  download(new Blob([buildCaseCsv(detail)], { type: "text/csv;charset=utf-8" }), reportFilename(detail, "csv"));
}

export function downloadCasePdf(detail: ReportDetail) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const margin = 42;
  const width = 510;
  let y = 48;
  const add = (label: string, value: string) => {
    const lines = doc.splitTextToSize(`${label}: ${value || "Not recorded"}`, width);
    if (y + lines.length * 13 > 795) { doc.addPage(); y = 48; }
    doc.text(lines, margin, y);
    y += lines.length * 13 + 7;
  };
  doc.setFont("courier", "bold"); doc.setFontSize(15); doc.text("ORIGIN TRACKER", margin, y); y += 18;
  doc.setFont("courier", "normal"); doc.setFontSize(9);
  add("Case", detail.investigation.caseNumber);
  add("Title", detail.investigation.title);
  add("Severity", `${detail.investigation.severity} · score ${detail.investigation.threatScore}/100 · confidence ${detail.investigation.confidence}%`);
  add("Created", new Date(detail.investigation.createdAt).toLocaleString());
  add("Summary", detail.investigation.summary || "");
  add("Evidence", `${detail.artifact?.originalFilename || "Not recorded"} · SHA-256 ${detail.artifact?.sha256 || "Not recorded"}`);
  add("Authentication", `SPF ${detail.artifact?.spf || "not recorded"}; DKIM ${detail.artifact?.dkim || "not recorded"}; DMARC ${detail.artifact?.dmarc || "not recorded"}`);
  if (detail.artifact?.aiCategory) { add("AI content review", `${detail.artifact.aiCategory} (${detail.artifact.aiModel || "model not recorded"}): ${detail.artifact.aiSummary || ""}`); add("AI recommendations", parseRecommendations(detail.artifact.aiRecommendationsJson)); }
  detail.iocs.forEach((ioc) => add(`IOC ${ioc.type}`, `${ioc.value} (${ioc.source})`));
  detail.reputations?.forEach((reputation) => add(`${reputation.provider} reputation`, `${reputation.ip}: abuse confidence ${reputation.abuseConfidenceScore}/100; ${reputation.totalReports} reports from ${reputation.numDistinctUsers} users; ${reputation.isWhitelisted ? "whitelisted" : "not whitelisted"}; ${[reputation.usageType, reputation.isp, reputation.domain, reputation.countryCode].filter(Boolean).join(" · ")}`));
  detail.urlReputations?.forEach((reputation) => add(`${reputation.provider} reputation`, `${reputation.url}: ${reputation.inDatabase ? `verified ${reputation.online ? "online " : ""}phish${reputation.phishId ? `ID ${reputation.phishId}` : ""}${reputation.target ? ` · target ${reputation.target}` : ""}` : "no verified online match in the feed"}`));
  detail.events.forEach((event) => add("Timeline", `${new Date(event.createdAt).toLocaleString()} · ${event.eventType}: ${event.detail}`));
  detail.notes.forEach((note) => add("Analyst note", `${new Date(note.createdAt).toLocaleString()} · ${note.content}`));
  doc.save(reportFilename(detail, "pdf"));
}
