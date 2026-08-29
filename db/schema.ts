import {
  mysqlTable,
  serial,
  varchar,
  text,
  timestamp,
  bigint,
} from "drizzle-orm/mysql-core";

// Zero-knowledge server design:
// - The server NEVER sees plaintext access keys, invite codes, or message content.
// - Agents are identified only by the SHA-256 hash of their access key.
// - Channels are identified only by the SHA-256 hash of their invite code.
// - Messages are stored as AES-256-GCM ciphertext + nonce. Keys are derived
//   client-side (HKDF from the invite code) and never leave the device.

export const agents = mysqlTable("agents", {
  id: serial("id").primaryKey(),
  keyHash: varchar("key_hash", { length: 64 }).notNull().unique(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const sessions = mysqlTable("sessions", {
  id: serial("id").primaryKey(),
  token: varchar("token", { length: 64 }).notNull().unique(),
  agentId: bigint("agent_id", { mode: "number", unsigned: true }).notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const channels = mysqlTable("channels", {
  id: serial("id").primaryKey(),
  inviteHash: varchar("invite_hash", { length: 64 }).notNull().unique(),
  createdBy: bigint("created_by", { mode: "number", unsigned: true }).notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

export const memberships = mysqlTable("memberships", {
  id: serial("id").primaryKey(),
  channelId: bigint("channel_id", { mode: "number", unsigned: true }).notNull(),
  agentId: bigint("agent_id", { mode: "number", unsigned: true }).notNull(),
  joinedAt: timestamp("joined_at").notNull().defaultNow(),
});

export const messages = mysqlTable("messages", {
  id: serial("id").primaryKey(),
  channelId: bigint("channel_id", { mode: "number", unsigned: true }).notNull(),
  agentId: bigint("agent_id", { mode: "number", unsigned: true }).notNull(),
  ciphertext: text("ciphertext").notNull(),
  nonce: varchar("nonce", { length: 32 }).notNull(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});
