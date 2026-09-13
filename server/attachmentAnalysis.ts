import { createHash } from "node:crypto";

export type AttachmentRiskVerdict = "HIGH_RISK" | "MEDIUM_RISK" | "LOW_RISK";

export type AttachmentAnalysis = {
  filename: string;
  size: number;
  mimeType: string | null;
  extension: string | null;
  attachmentHash: string;
  isDangerous: boolean;
  isDoubleExtension: boolean;
  isMimeMismatch: boolean;
  attachmentVerdict: AttachmentRiskVerdict;
  vtDetectionRatio: number | null;
  vtVerdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | null;
  vtMaliciousCount: number | null;
};

export type AttachmentInput = {
  filename?: string | null;
  contentType?: string | null;
  content?: Buffer | null;
  size?: number | null;
};

const DANGEROUS_EXTENSIONS = new Set([".exe", ".bat", ".vbs", ".js", ".ps1", ".scr", ".cmd", ".jar", ".msi", ".iso", ".lnk", ".hta", ".dll", ".com", ".pif", ".reg", ".wsf", ".wsh"]);
const MIME_EXTENSION_MAP: Record<string, string> = {
  ".pdf": "application/pdf",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".xls": "application/vnd.ms-excel",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".zip": "application/zip",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
};

function extensionFor(filename: string) {
  const match = filename.toLowerCase().match(/(\.[a-z0-9]{1,12})$/i);
  return match?.[1] || null;
}

function normalMime(value: string | null | undefined) {
  return value?.split(";")[0]?.trim().toLowerCase() || null;
}

export function analyzeAttachments(attachments: AttachmentInput[]): AttachmentAnalysis[] {
  return attachments.map((attachment) => {
    const filename = attachment.filename?.trim() || "unnamed attachment";
    const extension = extensionFor(filename);
    const mimeType = normalMime(attachment.contentType);
    const expectedMime = extension ? MIME_EXTENSION_MAP[extension] : undefined;
    const isDangerous = extension ? DANGEROUS_EXTENSIONS.has(extension) : false;
    const isDoubleExtension = /\.[a-z0-9]{2,4}\.[a-z0-9]{2,4}$/i.test(filename);
    const isMimeMismatch = Boolean(expectedMime && mimeType && expectedMime !== mimeType);
    const content = attachment.content || Buffer.alloc(0);
    const attachmentHash = createHash("sha256").update(content).digest("hex");
    const attachmentVerdict: AttachmentRiskVerdict = isDangerous || isDoubleExtension || isMimeMismatch ? "HIGH_RISK" : "LOW_RISK";
    return {
      filename,
      size: Number.isFinite(attachment.size) ? Math.max(0, Math.trunc(attachment.size!)) : content.length,
      mimeType,
      extension,
      attachmentHash,
      isDangerous,
      isDoubleExtension,
      isMimeMismatch,
      attachmentVerdict,
      vtDetectionRatio: null,
      vtVerdict: null,
      vtMaliciousCount: null,
    };
  });
}

export function withVirusTotalAttachmentResult(attachment: AttachmentAnalysis, stats: { malicious: number; suspicious: number; harmless: number; undetected: number }) {
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
  const ratio = total > 0 ? stats.malicious / total : 0;
  const vtVerdict = stats.malicious > 0 ? "MALICIOUS" : stats.suspicious > 0 ? "SUSPICIOUS" : "CLEAN";
  const attachmentVerdict: AttachmentRiskVerdict = attachment.isDangerous || attachment.isDoubleExtension || attachment.isMimeMismatch || vtVerdict === "MALICIOUS"
    ? "HIGH_RISK"
    : vtVerdict === "SUSPICIOUS" ? "MEDIUM_RISK" : "LOW_RISK";
  return { ...attachment, attachmentVerdict, vtDetectionRatio: ratio, vtVerdict, vtMaliciousCount: stats.malicious };
}
