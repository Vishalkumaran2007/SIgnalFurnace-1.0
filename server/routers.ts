import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { invokeLLM } from "./_core/llm";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { TRPCError } from "@trpc/server";
import { addInvestigationNote, enrichInvestigationGeolocation, enrichInvestigationPhishTank, enrichInvestigationReputation, enrichInvestigationVirusTotal, findSimilarInvestigations, getDashboardSummary, getInvestigation, listAdministrativeUsers, listGeolocations, listIndicators, listInvestigations, listIpReputations, recordInvestigationEvent, rerunInvestigationAiReview, saveAnalysis, setAdministrativeUserRole, updateInvestigationStatus } from "./db";
import { analyzeEmailContentWithAi, applyAiContentAssessment, isLikelyEml, parseEml } from "./emailAnalysis";
import { storagePut } from "./storage";
import { notifyOwner } from "./_core/notification";
import { z } from "zod";

const guideViews = ["dashboard", "analyzer", "intelligence", "geolocation", "forensics", "assistant", "reports", "settings"] as const;
const guideViewSchema = z.enum(guideViews);

export const appRouter = router({
    // if you need to use socket.io, read and register route in server/_core/index.ts, all api should start with '/api/' so that the gateway can route correctly
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  guide: router({
    ask: protectedProcedure
      .input(z.object({ question: z.string().trim().min(1).max(500), currentView: guideViewSchema }))
      .mutation(async ({ input }) => {
        const navigationRules: Array<{ view: typeof guideViews[number]; matches: RegExp }> = [
          { view: "analyzer", matches: /\b(email check|check an email|analyzer|email page)\b/i },
          { view: "dashboard", matches: /\b(dashboard|home|overview)\b/i },
          { view: "intelligence", matches: /\b(known threats|threats|intelligence)\b/i },
          { view: "geolocation", matches: /\b(location|map|places)\b/i },
          { view: "forensics", matches: /\b(case details|case page|evidence)\b/i },
          { view: "assistant", matches: /\b(ai guide|ai help|guide page)\b/i },
          { view: "reports", matches: /\b(reports?|report page)\b/i },
          { view: "settings", matches: /\b(settings|connect data|data source)\b/i },
        ];
        const requestedNavigation = navigationRules.find((rule) => rule.matches.test(input.question));
        if (requestedNavigation) {
          return {
            reply: `Opening the ${requestedNavigation.view === "analyzer" ? "email check" : requestedNavigation.view} page. I can only navigate within this website.`,
            navigateTo: requestedNavigation.view,
          };
        }

        const response = await invokeLLM({
          maxTokens: 260,
          messages: [
            {
              role: "system",
              content: `You are the Threat OS Guide. You only explain this website and, if asked, select one approved screen to open. You cannot inspect emails, cases, files, reports, accounts, or any live data. You cannot upload, download, create, edit, delete, send, block, change settings, or operate anything outside navigation. Use short, simple English. If a request is outside these limits, politely say so and offer safe navigation help. Return JSON only with exactly: reply (string) and navigateTo (one of ${guideViews.join(", ")} or null).`,
            },
            {
              role: "user",
              content: `The user is on ${input.currentView}. Their question is: ${input.question}`,
            },
          ],
          response_format: {
            type: "json_schema",
            json_schema: {
              name: "guide_response",
              strict: true,
              schema: {
                type: "object",
                properties: {
                  reply: { type: "string" },
                  navigateTo: { anyOf: [{ type: "string", enum: [...guideViews] }, { type: "null" }] },
                },
                required: ["reply", "navigateTo"],
                additionalProperties: false,
              },
            },
          },
        });

        const content = response.choices[0]?.message.content;
        if (typeof content !== "string") {
          return { reply: "I can guide you to a page, but I could not answer right now.", navigateTo: null };
        }

        try {
          const parsed = z.object({ reply: z.string().min(1).max(800), navigateTo: guideViewSchema.nullable() }).parse(JSON.parse(content));
          return parsed;
        } catch {
          return { reply: "I can explain the pages or help you move around this website. Please try again.", navigateTo: null };
        }
      }),
  }),

  analysis: router({
    list: protectedProcedure.query(({ ctx }) => listInvestigations(ctx.user.id)),
    indicators: protectedProcedure.query(({ ctx }) => listIndicators(ctx.user.id)),
    locations: protectedProcedure.query(({ ctx }) => listGeolocations(ctx.user.id)),
    reputations: protectedProcedure.query(({ ctx }) => listIpReputations(ctx.user.id)),
    dashboard: protectedProcedure.query(({ ctx }) => getDashboardSummary(ctx.user.id)),
    detail: protectedProcedure.input(z.object({ investigationId: z.number().int().positive() })).query(async ({ ctx, input }) => {
      const detail = await getInvestigation(ctx.user.id, input.investigationId);
      if (!detail) throw new TRPCError({ code: "NOT_FOUND", message: "Investigation not found." });
      return detail;
    }),
    similar: protectedProcedure.input(z.object({ investigationId: z.number().int().positive() })).query(async ({ ctx, input }) => {
      const matches = await findSimilarInvestigations(ctx.user.id, input.investigationId);
      if (matches === null) throw new TRPCError({ code: "NOT_FOUND", message: "Investigation not found." });
      return matches;
    }),
    enrichLocation: protectedProcedure.input(z.object({ investigationId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
      try { return await enrichInvestigationGeolocation(ctx.user.id, input.investigationId); } catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "The source IP could not be enriched." }); }
    }),
    enrichReputation: protectedProcedure.input(z.object({ investigationId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
      try { return await enrichInvestigationReputation(ctx.user.id, input.investigationId); } catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "The source IP reputation could not be checked." }); }
    }),
    enrichVirusTotal: protectedProcedure.input(z.object({ investigationId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
      try { return await enrichInvestigationVirusTotal(ctx.user.id, input.investigationId); } catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "The source IP reputation could not be checked." }); }
    }),
    enrichPhishTank: protectedProcedure.input(z.object({ investigationId: z.number().int().positive(), url: z.string().url().max(2048) })).mutation(async ({ ctx, input }) => {
      try { return await enrichInvestigationPhishTank(ctx.user.id, input.investigationId, input.url); } catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "The extracted URL could not be checked." }); }
    }),
    reviewAi: protectedProcedure.input(z.object({ investigationId: z.number().int().positive() })).mutation(async ({ ctx, input }) => {
      try { return await rerunInvestigationAiReview(ctx.user.id, input.investigationId); } catch (error) { throw new TRPCError({ code: "BAD_REQUEST", message: error instanceof Error ? error.message : "The bounded AI review could not be completed." }); }
    }),
    ingestEml: protectedProcedure.input(z.object({ filename: z.string().trim().min(1).max(512), mimeType: z.string().trim().max(128), base64: z.string().min(1).max(5_600_000) })).mutation(async ({ ctx, input }) => {
      if (!input.filename.toLowerCase().endsWith(".eml")) throw new TRPCError({ code: "BAD_REQUEST", message: "Upload an .eml file. .msg parsing is not connected yet." });
      const buffer = Buffer.from(input.base64, "base64");
      if (!buffer.length || buffer.length > 4 * 1024 * 1024) throw new TRPCError({ code: "PAYLOAD_TOO_LARGE", message: "Email files must be smaller than 4 MB." });
      if (!isLikelyEml(buffer)) throw new TRPCError({ code: "BAD_REQUEST", message: "This file does not look like a valid RFC822 .eml email." });
      const parsed = await parseEml(buffer);
      const aiAssessment = await analyzeEmailContentWithAi(parsed);
      if (aiAssessment) applyAiContentAssessment(parsed, aiAssessment);
      const stored = await storagePut(`evidence/${ctx.user.id}/${Date.now()}-${input.filename.replace(/[^a-zA-Z0-9._-]/g, "_")}`, buffer, "message/rfc822");
      const saved = await saveAnalysis({ userId: ctx.user.id, filename: input.filename, mimeType: "message/rfc822", storageKey: stored.key, storageUrl: stored.url, parsed });
      let ownerAlert: "not_needed" | "delivered" | "unavailable" = "not_needed";
      if (parsed.threatScore >= 60) {
        const delivered = await notifyOwner({ title: `High-risk email case ${saved.caseNumber}`, content: `A completed private email check reached ${parsed.threatScore}/100 (${parsed.severity}). Review the case in Origin Tracker. No email body or attachment is included in this alert.` }).catch(() => false);
        ownerAlert = delivered ? "delivered" : "unavailable";
        await recordInvestigationEvent(ctx.user.id, saved.investigationId, "high_risk_alert", delivered ? "A high-risk owner alert was accepted for delivery." : "A high-risk owner alert could not be delivered; the case remains saved for review.");
      }
      return { ...saved, ownerAlert, parsed: { sender: parsed.sender, recipient: parsed.recipient, subject: parsed.subject, urls: parsed.urls, attachmentNames: parsed.attachmentNames, spf: parsed.spf, dkim: parsed.dkim, dmarc: parsed.dmarc, threatScore: parsed.threatScore, confidence: parsed.confidence, severity: parsed.severity, summary: parsed.summary, reasons: parsed.reasons, findings: parsed.findings, ai: parsed.ai } };
    }),
    addNote: protectedProcedure.input(z.object({ investigationId: z.number().int().positive(), content: z.string().trim().min(1).max(5000) })).mutation(async ({ ctx, input }) => { await addInvestigationNote(ctx.user.id, input.investigationId, input.content); return { success: true } as const; }),
    updateStatus: protectedProcedure.input(z.object({ investigationId: z.number().int().positive(), status: z.enum(["open", "in_progress", "resolved", "closed"]) })).mutation(async ({ ctx, input }) => { await updateInvestigationStatus(ctx.user.id, input.investigationId, input.status); return { success: true } as const; }),
  }),

  admin: router({
    users: protectedProcedure.query(async ({ ctx }) => {
      if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN", message: "Administrator access is required." });
      return listAdministrativeUsers();
    }),
    updateUserRole: protectedProcedure.input(z.object({ userId: z.number().int().positive(), role: z.enum(["user", "admin"]) })).mutation(async ({ ctx, input }) => {
      if (ctx.user.role !== "admin") throw new TRPCError({ code: "FORBIDDEN", message: "Administrator access is required." });
      if (input.userId === ctx.user.id && input.role !== "admin") throw new TRPCError({ code: "BAD_REQUEST", message: "You cannot remove your own administrator access." });
      await setAdministrativeUserRole(input.userId, input.role);
      return { success: true } as const;
    }),
  }),

  // TODO: add feature routers here, e.g.
  // todo: router({
  //   list: protectedProcedure.query(({ ctx }) =>
  //     db.getUserTodos(ctx.user.id)
  //   ),
  // }),
});

export type AppRouter = typeof appRouter;
