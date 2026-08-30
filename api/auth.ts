import { TRPCError } from "@trpc/server";
import { eq } from "drizzle-orm";
import { publicQuery } from "./middleware";
import { getDb } from "./queries/connection";
import { sessions } from "@db/schema";

// Session-token auth: every protected call requires
// `Authorization: Bearer <token>` from a prior successful key login.
export const authedQuery = publicQuery.use(async ({ ctx, next }) => {
  const header = ctx.req.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) throw new TRPCError({ code: "UNAUTHORIZED", message: "No session" });

  const db = getDb();
  const [session] = await db
    .select()
    .from(sessions)
    .where(eq(sessions.token, token))
    .limit(1);
  if (!session || session.expiresAt.getTime() < Date.now()) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: "Session expired" });
  }
  return next({ ctx: { ...ctx, agentId: session.agentId } });
});
