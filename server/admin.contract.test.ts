import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("administrator role-control contract", () => {
  it("keeps user listing and role updates protected by an administrator role check", () => {
    const router = readFileSync("/home/ubuntu/sih26106-cyber-forensics/server/routers.ts", "utf8");
    const settings = readFileSync("/home/ubuntu/sih26106-cyber-forensics/client/src/pages/Home.tsx", "utf8");
    expect(router).toContain("admin: router");
    expect(router).toContain('ctx.user.role !== "admin"');
    expect(router).toContain("updateUserRole");
    expect(router).toContain("cannot remove your own administrator access");
    expect(settings).toContain("trpc.admin.users.useQuery");
    expect(settings).toContain("Administrator access required");
  });
});
