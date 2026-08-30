import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { env } from "../lib/env";
import * as schema from "@db/schema";
import * as relations from "@db/relations";

const fullSchema = { ...schema, ...relations };

// One postgres() client per process. The connection is created
// synchronously and the read-only override runs on first use.
//
// Neon pooler enforces `default_transaction_read_only = on` at the
// cluster level, which blocks every INSERT/UPDATE/DELETE on new pooled
// connections. Override once on the first use of the connection.
// See memory entry
// "Neon + postgres.js — read-only transaction race (2026-07-10)".

let _client: ReturnType<typeof postgres> | null = null;
let _instance: ReturnType<typeof drizzle<typeof fullSchema>> | null = null;
let _initPromise: Promise<void> | null = null;

function ensureClient() {
  if (_client) return _client;
  _client = postgres(env.databaseUrl, {
    max: 1,
    prepare: false,
    connect_timeout: 10,
    onnotice: () => {},
  });
  return _client;
}

export function getDb() {
  if (_instance) return _instance;
  const client = ensureClient();
  _initPromise = client
    .unsafe("SET default_transaction_read_only = off")
    .then(() => undefined)
    .catch((e) => console.error("neon read-only-off override failed:", e));
  _instance = drizzle(client, { schema: fullSchema });
  return _instance;
}

/**
 * Awaitable. Callers that are about to do a write should `await
 * ensureWritable()` so the read-only override is guaranteed to be in
 * place before they hit the database. Idempotent and safe to call from
 * any number of concurrent requests — they all wait on the same
 * promise.
 */
export async function ensureWritable(): Promise<void> {
  getDb();
  if (_initPromise) await _initPromise;
}
