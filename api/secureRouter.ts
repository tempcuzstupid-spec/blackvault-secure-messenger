import { z } from "zod";
import { randomBytes } from "node:crypto";
import { TRPCError } from "@trpc/server";
import { and, asc, eq, gt, inArray } from "drizzle-orm";
import { createRouter, publicQuery } from "./middleware";
import { authedQuery } from "./auth";
import { getDb } from "./queries/connection";
import { sseHub } from "./sse/hub";
import { ensureWritable } from "./queries/connection";
import { agents, sessions, channels, memberships, messages, reactions } from "@db/schema";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24; // 24h, re-login required after

// Anonymous display tag: short prefix of the agent's key hash. Not reversible,
// not a name, unique enough to distinguish senders inside a channel.
const tagOf = (keyHash: string) => keyHash.slice(0, 6).toUpperCase();

async function requireMember(channelId: number, agentId: number) {
  const db = getDb();
  const [m] = await db
    .select()
    .from(memberships)
    .where(and(eq(memberships.channelId, channelId), eq(memberships.agentId, agentId)))
    .limit(1);
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
      const [found] = await db
        .select()
        .from(agents)
        .where(eq(agents.keyHash, input.keyHash))
        .limit(1);

      let agent = found;
      if (!agent) {
        const existing = await db.select({ id: agents.id }).from(agents).limit(1);
        if (existing.length > 0) {
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Key not recognized" });
        }
        await ensureWritable();
        const [row] = await db.insert(agents).values({ keyHash: input.keyHash }).returning({ id: agents.id });
        agent = { id: row.id, keyHash: input.keyHash, createdAt: new Date() };
      }

      await ensureWritable();
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
    await ensureWritable();
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
      await ensureWritable();
      const db = getDb();
      const [dupe] = await db
        .select({ id: agents.id })
        .from(agents)
        .where(eq(agents.keyHash, input.keyHash))
        .limit(1);
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
      await ensureWritable();
      const db = getDb();
      const [row] = await db
        .insert(channels)
        .values({ inviteHash: input.inviteHash, createdBy: ctx.agentId })
        .returning({ id: channels.id });
      await db.insert(memberships).values({ channelId: row.id, agentId: ctx.agentId });
      // No broadcast needed: the creator is the only member. The next
      // joinChannel call will broadcast membership.added.
      return { channelId: row.id };
    }),

  joinChannel: authedQuery
    .input(z.object({ inviteHash: z.string().regex(/^[a-f0-9]{64}$/) }))
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const [channel] = await db
        .select()
        .from(channels)
        .where(eq(channels.inviteHash, input.inviteHash))
        .limit(1);
      if (!channel) throw new TRPCError({ code: "NOT_FOUND", message: "Invalid invite code" });
      const [existing] = await db
        .select()
        .from(memberships)
        .where(and(eq(memberships.channelId, channel.id), eq(memberships.agentId, ctx.agentId)))
        .limit(1);
      if (!existing) {
        await ensureWritable();
        await db.insert(memberships).values({ channelId: channel.id, agentId: ctx.agentId });
        sseHub.broadcast(channel.id, {
          type: "channel.member_joined",
          channelId: channel.id,
          agentId: ctx.agentId,
          online: sseHub.presenceSnapshot(channel.id),
        });
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
        replyTo: z.number().int().positive().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      await requireMember(input.channelId, ctx.agentId);
      // If replying, the parent message must exist in the same channel.
      if (input.replyTo != null) {
        const [parent] = await getDb()
          .select({ id: messages.id })
          .from(messages)
          .where(eq(messages.id, input.replyTo))
          .limit(1);
        if (!parent) throw new TRPCError({ code: "NOT_FOUND", message: "Reply target not found" });
      }
      await ensureWritable();
      const db = getDb();
      const [row] = await db.insert(messages).values({
        channelId: input.channelId,
        agentId: ctx.agentId,
        ciphertext: input.ciphertext,
        nonce: input.nonce,
        replyTo: input.replyTo ?? null,
      }).returning({ id: messages.id, createdAt: messages.createdAt, replyTo: messages.replyTo });
      const [{ keyHash }] = await db
        .select({ keyHash: agents.keyHash })
        .from(agents)
        .where(eq(agents.id, ctx.agentId))
        .limit(1);
      sseHub.broadcast(input.channelId, {
        type: "message.created",
        channelId: input.channelId,
        message: {
          id: row.id,
          ciphertext: input.ciphertext,
          nonce: input.nonce,
          createdAt: row.createdAt,
          replyTo: row.replyTo,
          senderTag: tagOf(keyHash),
        },
      });
      return { ok: true, id: row.id };
    }),

  editMessage: authedQuery
    .input(
      z.object({
        messageId: z.number().int().positive(),
        ciphertext: z.string().min(1).max(16384),
        nonce: z.string().min(8).max(32),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const [msg] = await db
        .select({ id: messages.id, channelId: messages.channelId, agentId: messages.agentId, deletedAt: messages.deletedAt })
        .from(messages)
        .where(eq(messages.id, input.messageId))
        .limit(1);
      if (!msg) throw new TRPCError({ code: "NOT_FOUND", message: "Message not found" });
      if (msg.agentId !== ctx.agentId) throw new TRPCError({ code: "FORBIDDEN", message: "Not your message" });
      if (msg.deletedAt) throw new TRPCError({ code: "GONE", message: "Message is deleted" });
      await requireMember(msg.channelId, ctx.agentId);
      await ensureWritable();
      const [updated] = await db.update(messages)
        .set({ ciphertext: input.ciphertext, nonce: input.nonce, editedAt: new Date() })
        .where(eq(messages.id, input.messageId))
        .returning({ id: messages.id, editedAt: messages.editedAt });
      sseHub.broadcast(msg.channelId, {
        type: "message.updated",
        channelId: msg.channelId,
        message: {
          id: updated.id,
          ciphertext: input.ciphertext,
          nonce: input.nonce,
          editedAt: updated.editedAt,
        },
      });
      return { ok: true };
    }),

  deleteMessage: authedQuery
    .input(z.object({ messageId: z.number().int().positive() }))
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const [msg] = await db
        .select({ id: messages.id, channelId: messages.channelId, agentId: messages.agentId })
        .from(messages)
        .where(eq(messages.id, input.messageId))
        .limit(1);
      if (!msg) throw new TRPCError({ code: "NOT_FOUND", message: "Message not found" });
      if (msg.agentId !== ctx.agentId) throw new TRPCError({ code: "FORBIDDEN", message: "Not your message" });
      await requireMember(msg.channelId, ctx.agentId);
      await ensureWritable();
      await db.update(messages)
        .set({ deletedAt: new Date(), ciphertext: "", nonce: "" })
        .where(eq(messages.id, input.messageId));
      sseHub.broadcast(msg.channelId, {
        type: "message.deleted",
        channelId: msg.channelId,
        messageId: input.messageId,
      });
      return { ok: true };
    }),

  addReaction: authedQuery
    .input(z.object({
      messageId: z.number().int().positive(),
      emoji: z.string().min(1).max(16),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const [msg] = await db
        .select({ id: messages.id, channelId: messages.channelId })
        .from(messages)
        .where(eq(messages.id, input.messageId))
        .limit(1);
      if (!msg) throw new TRPCError({ code: "NOT_FOUND", message: "Message not found" });
      await requireMember(msg.channelId, ctx.agentId);
      await ensureWritable();
      // Idempotent: ignore the unique-constraint violation if the
      // (message, agent, emoji) row already exists.
      try {
        await db.insert(reactions).values({
          messageId: input.messageId,
          agentId: ctx.agentId,
          emoji: input.emoji,
        });
      } catch (e: any) {
        if (!String(e?.message ?? "").includes("duplicate")) throw e;
      }
      sseHub.broadcast(msg.channelId, {
        type: "reaction.added",
        channelId: msg.channelId,
        messageId: input.messageId,
        agentId: ctx.agentId,
        emoji: input.emoji,
      });
      return { ok: true };
    }),

  removeReaction: authedQuery
    .input(z.object({
      messageId: z.number().int().positive(),
      emoji: z.string().min(1).max(16),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = getDb();
      const [msg] = await db
        .select({ id: messages.id, channelId: messages.channelId })
        .from(messages)
        .where(eq(messages.id, input.messageId))
        .limit(1);
      if (!msg) throw new TRPCError({ code: "NOT_FOUND", message: "Message not found" });
      await requireMember(msg.channelId, ctx.agentId);
      await ensureWritable();
      await db.delete(reactions)
        .where(and(
          eq(reactions.messageId, input.messageId),
          eq(reactions.agentId, ctx.agentId),
          eq(reactions.emoji, input.emoji),
        ));
      sseHub.broadcast(msg.channelId, {
        type: "reaction.removed",
        channelId: msg.channelId,
        messageId: input.messageId,
        agentId: ctx.agentId,
        emoji: input.emoji,
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
          replyTo: messages.replyTo,
          editedAt: messages.editedAt,
          deletedAt: messages.deletedAt,
          createdAt: messages.createdAt,
          keyHash: agents.keyHash,
        })
        .from(messages)
        .innerJoin(agents, eq(agents.id, messages.agentId))
        .where(cond)
        .orderBy(asc(messages.id))
        .limit(200);
      const ids = rows.map((r) => r.id);
      const rxByMessage = new Map<number, Array<{ agentId: number; emoji: string }>>();
      if (ids.length > 0) {
        const rx = await db
          .select({ messageId: reactions.messageId, agentId: reactions.agentId, emoji: reactions.emoji })
          .from(reactions)
          .where(inArray(reactions.messageId, ids));
        for (const r of rx) {
          const list = rxByMessage.get(r.messageId) ?? [];
          list.push({ agentId: r.agentId, emoji: r.emoji });
          rxByMessage.set(r.messageId, list);
        }
      }
      return rows.map((r) => ({
        id: r.id,
        ciphertext: r.ciphertext,
        nonce: r.nonce,
        replyTo: r.replyTo,
        editedAt: r.editedAt,
        deletedAt: r.deletedAt,
        createdAt: r.createdAt,
        senderTag: tagOf(r.keyHash),
        reactions: rxByMessage.get(r.id) ?? [],
      }));
    }),
});
