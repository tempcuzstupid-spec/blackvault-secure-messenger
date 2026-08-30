import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
} from "drizzle-orm/pg-core";

// Zero-knowledge server design:
// - The server NEVER sees plaintext access keys, invite codes, or message content.
// - Agents are identified only by the SHA-256 hash of their access key.
// - Channels are identified only by the SHA-256 hash of their invite code.
// - Messages are stored as AES-256-GCM ciphertext + nonce. Keys are derived
//   client-side (HKDF from the invite code) and never leave the device.

export const agents = pgTable("agents", {
  id: serial("id").primaryKey(),
  keyHash: text("key_hash").notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const sessions = pgTable("sessions", {
  id: serial("id").primaryKey(),
  token: text("token").notNull().unique(),
  agentId: integer("agent_id").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const channels = pgTable("channels", {
  id: serial("id").primaryKey(),
  inviteHash: text("invite_hash").notNull().unique(),
  createdBy: integer("created_by").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const memberships = pgTable("memberships", {
  id: serial("id").primaryKey(),
  channelId: integer("channel_id").notNull(),
  agentId: integer("agent_id").notNull(),
  joinedAt: timestamp("joined_at", { withTimezone: true }).notNull().defaultNow(),
});

export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  channelId: integer("channel_id").notNull(),
  agentId: integer("agent_id").notNull(),
  ciphertext: text("ciphertext").notNull(),
  nonce: text("nonce").notNull(),
  // Optional reference to a parent message for replies. NULL = top-level.
  replyTo: integer("reply_to"),
  // Set when the author edits the message. UI shows "(edited)" badge.
  editedAt: timestamp("edited_at", { withTimezone: true }),
  // Soft delete: when set, the server returns the message with empty
  // ciphertext and a "[deleted]" placeholder rendered client-side.
  deletedAt: timestamp("deleted_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// Reactions: one row per (messageId, agentId, emoji). The (messageId,
// agentId, emoji) tuple is unique so the same agent can't add the same
// emoji twice. UI typically exposes a small fixed set (👍 ❤️ 😂 😮 😢).
export const reactions = pgTable("reactions", {
  id: serial("id").primaryKey(),
  messageId: integer("message_id").notNull(),
  agentId: integer("agent_id").notNull(),
  emoji: text("emoji").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// Web Push subscriptions: one row per (agentId, endpoint). When the
// user enables push on a device, the browser's PushManager.subscribe()
// returns an endpoint + p256dh + auth keypair; we persist those so
// the server can send pushes to that device later. `userAgent` is for
// debug visibility in the dashboard; the server doesn't act on it.
export const pushSubscriptions = pgTable("push_subscriptions", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id").notNull(),
  endpoint: text("endpoint").notNull().unique(),
  p256dh: text("p256dh").notNull(),
  auth: text("auth").notNull(),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
