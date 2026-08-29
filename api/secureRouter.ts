import { z } from "zod";
import { randomBytes } from "node:crypto";
import { TRPCError } from "@trpc/server";
import { and, asc, eq, gt } from "drizzle-orm";
import { createRouter, publicQuery } from "./middleware";
import { authedQuery } from "./auth";
import { getDb } from "./queries/connection";
import { agents, sessions, channels, memberships, messages } from "@db/schema";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24; // 24h, re-login required after

// Anonymous display tag: short prefix of the agent's key hash. Not reversible,
// not a name, unique enough to distinguish senders inside a channel.
const tagOf = (keyHash: string) => keyHash.slice(0, 6).toUpperCase();

async function requireMember(channelId: number, agentId: number) {
  const db = getDb();
  const m = await db.query.memberships.findFirst({
    where: and(eq(memberships.channelId, channelId), eq(memberships.agentId, agentId)),
  });
  if (!m) throw new TRPCError({ code: "FORBIDDEN", message: "Not a channel member" });
}

export const secureRouter = createRouter({
  // ---- Access-key authentication -------------------------------------------

  // Client sends ONLY the SHA-256 hash of the access key. On a completely
  // empty system the first key becomes the founder; afterwards a key must
  // have been issued via invites.issueAccessKey by an existing member.
  login: publicQuery
    .input(z.object({ keyHash: z.string().regex(/^[a-f0-9]{64}$/) }))
    .mutation(async ({ input }) => {
      const db = getDb();
      let agent = await db.query.agents.findFirst({
        where: eq(agents.keyHash, input.keyHash),
      });

      if (!agent) {
        const existing = await db.select({ id: agents.id }).from(agents).limit(1);
        if (existing.length > 0) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Key not recognized" });
        }
        const [row] = await db.insert(agents).values({ keyHash: input.keyHash }).$returningId();
        agent = { id: row.id, keyHash: input.keyHash, createdAt: new Date() };
      }

      const token = randomBytes(32).toString("hex");
      await db.insert(sessions).values({
        token,
        agentId: agent.id,
        expiresAt: new Date(Date.now() + SESSION_TTL_MS),
      });
      return { token, agentTag: tagOf(agent.keyHash) };
    }),

  logout: authedQuery.mutation(async ({ ctx }) => {
    const header = ctx.req.headers.get("authorization") ?? "";
    const token = header.slice(7);
    await getDb().delete(sessions).where(eq(sessions.token, token));
    return { ok: true };
  }),

  // ---- Invites --------------------------------------------------------------

  // An existing member issues a new access key. The client generates the key
  // locally and sends only its hash; the plaintext key is displayed once to
  // the inviter and never touches the server or the database.
  issueAccessKey: authedQuery
    .input(z.object({ keyHash: z.string().regex(/^[a-f0-9]{64}$/) }))
    .mutation(async ({ input }) => {
      const db = getDb();
      const dupe = await db.query.agents.findFirst({
        where: eq(agents.keyHash, input.keyHash),
      });
      if (dupe) throw new TRPCError({ code: "CONFLICT", message: "Key already exists" });
      await db.insert(agents).values({ keyHash: input.keyHash });
      return { ok: true };
    }),

  // ---- Channels -------------------------------------------------------------

  // Client generates the channel invite code locally, derives the message
  // encryption key from it (HKDF), and sends only the code's hash.
  createChannel: authedQuery
    .input(z.object({ inviteHash: z.string().regex(/^[a-f0-9]{64}$/) }))
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const [row] = await db
        .insert(channels)
        .values({ inviteHash: input.inviteHash, createdBy: ctx.agentId })
        .$returningId();
      await db.insert(memberships).values({ channelId: row.id, agentId: ctx.agentId });
      return { channelId: row.id };
    }),

  joinChannel: authedQuery
    .input(z.object({ inviteHash: z.string().regex(/^[a-f0-9]{64}$/) }))
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const channel = await db.query.channels.findFirst({
        where: eq(channels.inviteHash, input.inviteHash),
      });
      if (!channel) throw new TRPCError({ code: "NOT_FOUND", message: "Invalid invite code" });
      const existing = await db.query.memberships.findFirst({
        where: and(eq(memberships.channelId, channel.id), eq(memberships.agentId, ctx.agentId)),
      });
      if (!existing) {
        await db.insert(memberships).values({ channelId: channel.id, agentId: ctx.agentId });
      }
      return { channelId: channel.id };
    }),

  listChannels: authedQuery.query(async ({ ctx }) => {
    const db = getDb();
    const rows = await db
      .select({ id: channels.id, createdAt: channels.createdAt })
      .from(memberships)
      .innerJoin(channels, eq(channels.id, memberships.channelId))
      .where(eq(memberships.agentId, ctx.agentId))
      .orderBy(asc(channels.id));
    return rows;
  }),

  channelMembers: authedQuery
    .input(z.object({ channelId: z.number().int().positive() }))
    .query(async ({ ctx, input }) => {
      await requireMember(input.channelId, ctx.agentId);
      const db = getDb();
      const rows = await db
        .select({ keyHash: agents.keyHash })
        .from(memberships)
        .innerJoin(agents, eq(agents.id, memberships.agentId))
        .where(eq(memberships.channelId, input.channelId));
      return rows.map((r) => ({ tag: tagOf(r.keyHash) }));
    }),

  // ---- Messages (ciphertext only) -------------------------------------------

  sendMessage: authedQuery
    .input(
      z.object({
        channelId: z.number().int().positive(),
        ciphertext: z.string().min(1).max(16384),
        nonce: z.string().min(8).max(32),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await requireMember(input.channelId, ctx.agentId);
      await getDb().insert(messages).values({
        channelId: input.channelId,
        agentId: ctx.agentId,
        ciphertext: input.ciphertext,
        nonce: input.nonce,
      });
      return { ok: true };
    }),

  listMessages: authedQuery
    .input(z.object({ channelId: z.number().int().positive(), afterId: z.number().int().optional() }))
    .query(async ({ ctx, input }) => {
      await requireMember(input.channelId, ctx.agentId);
      const db = getDb();
      const cond = input.afterId
        ? and(eq(messages.channelId, input.channelId), gt(messages.id, input.afterId))
        : eq(messages.channelId, input.channelId);
      const rows = await db
        .select({
          id: messages.id,
          ciphertext: messages.ciphertext,
          nonce: messages.nonce,
          createdAt: messages.createdAt,
          keyHash: agents.keyHash,
        })
        .from(messages)
        .innerJoin(agents, eq(agents.id, messages.agentId))
        .where(cond)
        .orderBy(asc(messages.id))
        .limit(200);
      return rows.map((r) => ({
        id: r.id,
        ciphertext: r.ciphertext,
        nonce: r.nonce,
        createdAt: r.createdAt,
        senderTag: tagOf(r.keyHash),
      }));
    }),
});
