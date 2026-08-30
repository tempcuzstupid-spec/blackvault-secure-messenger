import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { env } from "../lib/env";
import * as schema from "@db/schema";
import * as relations from "@db/relations";

const fullSchema = { ...schema, ...relations };

let instance: ReturnType<typeof drizzle<typeof fullSchema>>;

export function getDb() {
  if (!instance) {
    // Neon pooler enforces `default_transaction_read_only = on` at the cluster
    // level, which would block every INSERT/UPDATE/DELETE on new pooled
    // connections. Override once per connection. See memory entry
    // "Neon + postgres.js — read-only transaction race (2026-07-10)".
    const client = postgres(env.databaseUrl, {
      max: 1,
      prepare: false,
      connect_timeout: 10,
      onnotice: () => {},
    });
    client
      .unsafe("SET default_transaction_read_only = off")
      .catch((e) => console.error("neon read-only-off override failed:", e));

    instance = drizzle(client, { schema: fullSchema });
  }
  return instance;
}
