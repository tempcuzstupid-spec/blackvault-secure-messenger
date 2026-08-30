import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { HttpBindings } from "@hono/node-server";
import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { appRouter } from "./router";
import { createContext } from "./context";
import { env } from "./lib/env";
import { sseHandler, sseChannelControls } from "./sse/handler";

const app = new Hono<{ Bindings: HttpBindings }>();

app.use(bodyLimit({ maxSize: 50 * 1024 * 1024 }));
app.use("/api/trpc/*", async (c) => {
  return fetchRequestHandler({
    endpoint: "/api/trpc",
    req: c.req.raw,
    router: appRouter,
    createContext,
  });
});

// Health endpoint for the SSE route (separate from tRPC ping used by
// Render's deploy health check).
app.get("/sse-ping", (c) => c.json({ ok: true, transport: "sse" }));

// Public VAPID public key — clients need this to subscribe to push.
// No auth (the public key is meant to be public).
app.get("/api/push/vapid-key", (c) => {
  if (!env.vapidPublicKey) return c.json({ error: "VAPID not configured" }, 503);
  return c.json({ publicKey: env.vapidPublicKey, subject: env.vapidSubject });
});

// SSE endpoint + companion REST controls
sseHandler(app);
sseChannelControls(app);

app.all("/api/*", (c) => c.json({ error: "Not Found" }, 404));

export default app;

if (env.isProduction) {
  const { serve } = await import("@hono/node-server");
  const { serveStaticFiles } = await import("./lib/vite");
  serveStaticFiles(app);

  const port = parseInt(process.env.PORT || "3000");
  serve({ fetch: app.fetch, port }, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}
