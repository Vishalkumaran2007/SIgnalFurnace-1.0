import { describe, expect, it } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

describe("auth.me", () => {
  it("returns the signed-in user to the protected workspace", async () => {
    const user = {
      id: 7,
      openId: "analyst-7",
      name: "Vishalkumaran V",
      email: "vishal@example.com",
      loginMethod: "manus",
      role: "user" as const,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    };
    const ctx = {
      user,
      req: {} as TrpcContext["req"],
      res: {} as TrpcContext["res"],
    } as TrpcContext;

    const caller = appRouter.createCaller(ctx);
    await expect(caller.auth.me()).resolves.toEqual(user);
  });
});
