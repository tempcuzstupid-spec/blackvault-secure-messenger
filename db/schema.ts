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
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
