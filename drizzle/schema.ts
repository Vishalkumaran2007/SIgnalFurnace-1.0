import { double, int, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export const investigations = mysqlTable("investigations", {
  id: int("id").autoincrement().primaryKey(),
  userId: int("userId").notNull(),
  caseNumber: varchar("caseNumber", { length: 48 }).notNull().unique(),
  title: varchar("title", { length: 512 }).notNull(),
  status: mysqlEnum("status", ["open", "in_progress", "resolved", "closed"]).default("open").notNull(),
  severity: mysqlEnum("severity", ["safe", "low", "medium", "high", "critical"]).default("low").notNull(),
  threatScore: int("threatScore").default(0).notNull(),
  confidence: int("confidence").default(0).notNull(),
  summary: text("summary"),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
});

export const emailArtifacts = mysqlTable("email_artifacts", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  userId: int("userId").notNull(),
  originalFilename: varchar("originalFilename", { length: 512 }).notNull(),
  storageKey: varchar("storageKey", { length: 768 }).notNull(),
  storageUrl: varchar("storageUrl", { length: 1024 }).notNull(),
  mimeType: varchar("mimeType", { length: 128 }).notNull(),
  sha256: varchar("sha256", { length: 128 }).notNull(),
  sender: varchar("sender", { length: 512 }),
  recipient: varchar("recipient", { length: 512 }),
  subject: varchar("subject", { length: 1024 }),
  messageId: varchar("messageId", { length: 1024 }),
  sentAt: timestamp("sentAt"),
  bodyText: text("bodyText"),
  rawHeaders: text("rawHeaders"),
  spf: mysqlEnum("spf", ["pass", "fail", "neutral", "missing"]).default("missing").notNull(),
  dkim: mysqlEnum("dkim", ["pass", "fail", "neutral", "missing"]).default("missing").notNull(),
  dmarc: mysqlEnum("dmarc", ["pass", "fail", "neutral", "missing"]).default("missing").notNull(),
  replyTo: varchar("replyTo", { length: 512 }),
  returnPath: varchar("returnPath", { length: 512 }),
  originatingIp: varchar("originatingIp", { length: 64 }),
  urlsJson: text("urlsJson"),
  attachmentNamesJson: text("attachmentNamesJson"),
  findingsJson: text("findingsJson"),
  aiCategory: varchar("aiCategory", { length: 80 }),
  aiSummary: text("aiSummary"),
  aiSocialEngineering: text("aiSocialEngineering"),
  aiRecommendationsJson: text("aiRecommendationsJson"),
  aiModel: varchar("aiModel", { length: 128 }),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const indicators = mysqlTable("indicators", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  userId: int("userId").notNull(),
  type: mysqlEnum("type", ["ip", "domain", "url", "email", "hash"]).notNull(),
  value: varchar("value", { length: 2048 }).notNull(),
  source: varchar("source", { length: 128 }).notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const ipGeolocations = mysqlTable("ip_geolocations", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  artifactId: int("artifactId").notNull(),
  userId: int("userId").notNull(),
  ip: varchar("ip", { length: 64 }).notNull(),
  country: varchar("country", { length: 128 }),
  countryCode: varchar("countryCode", { length: 8 }),
  region: varchar("region", { length: 128 }),
  city: varchar("city", { length: 128 }),
  latitude: double("latitude"),
  longitude: double("longitude"),
  provider: varchar("provider", { length: 128 }).notNull(),
  enrichedAt: timestamp("enrichedAt").defaultNow().notNull(),
});

export const ipReputations = mysqlTable("ip_reputations", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  artifactId: int("artifactId").notNull(),
  userId: int("userId").notNull(),
  ip: varchar("ip", { length: 64 }).notNull(),
  provider: varchar("provider", { length: 128 }).notNull(),
  abuseConfidenceScore: int("abuseConfidenceScore").notNull(),
  totalReports: int("totalReports").notNull(),
  numDistinctUsers: int("numDistinctUsers").notNull(),
  lastReportedAt: timestamp("lastReportedAt"),
  countryCode: varchar("countryCode", { length: 8 }),
  usageType: varchar("usageType", { length: 256 }),
  isp: varchar("isp", { length: 512 }),
  domain: varchar("domain", { length: 512 }),
  isWhitelisted: int("isWhitelisted").notNull().default(0),
  malicious: int("malicious").notNull().default(0),
  suspicious: int("suspicious").notNull().default(0),
  harmless: int("harmless").notNull().default(0),
  undetected: int("undetected").notNull().default(0),
  reputationScore: int("reputationScore"),
  asn: int("asn"),
  asOwner: varchar("asOwner", { length: 512 }),
  network: varchar("network", { length: 128 }),
  lastAnalysisAt: timestamp("lastAnalysisAt"),
  rawJson: text("rawJson"),
  enrichedAt: timestamp("enrichedAt").defaultNow().notNull(),
});

export const urlReputations = mysqlTable("url_reputations", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  artifactId: int("artifactId").notNull(),
  userId: int("userId").notNull(),
  url: varchar("url", { length: 2048 }).notNull(),
  provider: varchar("provider", { length: 64 }).notNull(),
  inDatabase: int("inDatabase").notNull().default(0),
  phishId: int("phishId"),
  verified: int("verified").notNull().default(0),
  online: int("online").notNull().default(0),
  target: varchar("target", { length: 512 }),
  verifiedAt: timestamp("verifiedAt"),
  feedUpdatedAt: timestamp("feedUpdatedAt"),
  rawJson: text("rawJson"),
  enrichedAt: timestamp("enrichedAt").defaultNow().notNull(),
});

export const investigationEvents = mysqlTable("investigation_events", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  userId: int("userId").notNull(),
  eventType: varchar("eventType", { length: 128 }).notNull(),
  detail: text("detail").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export const investigationNotes = mysqlTable("investigation_notes", {
  id: int("id").autoincrement().primaryKey(),
  investigationId: int("investigationId").notNull(),
  userId: int("userId").notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;
export type Investigation = typeof investigations.$inferSelect;
export type EmailArtifact = typeof emailArtifacts.$inferSelect;
export type Indicator = typeof indicators.$inferSelect;
export type IpGeolocation = typeof ipGeolocations.$inferSelect;
export type IpReputation = typeof ipReputations.$inferSelect;
export type UrlReputation = typeof urlReputations.$inferSelect;
