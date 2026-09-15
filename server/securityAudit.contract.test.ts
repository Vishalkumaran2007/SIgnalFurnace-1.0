import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

describe("durable security audit events", () => {
  const schema = readFileSync(resolve(process.cwd(), "drizzle/schema.ts"), "utf8");
  const db = readFileSync(resolve(process.cwd(), "server/db.ts"), "utf8");
  const router = readFileSync(resolve(process.cwd(), "server/routers.ts"), "utf8");
  const migration = readFileSync(resolve(process.cwd(), "drizzle/0010_curvy_changeling.sql"), "utf8");

  it("uses a durable additive event table with bounded metadata", () => {
    expect(schema).toContain('mysqlTable("security_audit_events"');
    expect(schema).toContain('eventType: varchar("eventType", { length: 128 })');
    expect(schema).toContain('metadataJson: text("metadataJson")');
    expect(db).toContain("recordSecurityAuditEvent");
    expect(db).toContain("input.eventType.slice(0, 128)");
    expect(migration).toContain("CREATE TABLE `security_audit_events`");
  });

  it("exposes audit records only through the administrator router and records protected events", () => {
    expect(router).toContain("auditEvents: protectedProcedure");
    expect(router).toContain('ctx.user.role !== "admin"');
    expect(router).toContain('eventType: "email_ingested"');
    expect(router).toContain('eventType: "role_changed"');
  });
});

// This suite inspects contracts only; it does not insert test rows into the database.
void 0;

