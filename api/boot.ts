import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import type { HttpBindings } from "@hono/node-server";
import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { appRouter } from "./router";
import { createContext } from "./context";
import { env } from "./lib/env";

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

// Health/pong endpoint for the WebSocket — separate from /api/trpc/ping
// which is the tRPC route used by the deploy health check.
app.get("/ws-ping", (c) => c.json({ ok: true, ws: "available" }));
app.all("/api/*", (c) => c.json({ error: "Not Found" }, 404));

export default app;

if (env.isProduction) {
  const { serve } = await import("@hono/node-server");
  const { serveStaticFiles } = await import("./lib/vite");
  const { WebSocketServer } = await import("ws");
  const { handleWsConnection } = await import("./ws/handler");
  serveStaticFiles(app);

  const port = parseInt(process.env.PORT || "3000");
  const server = serve({ fetch: app.fetch, port }, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });

  // WebSocket server: only intercepts upgrades on /ws, lets everything
  // else pass through to Hono.
  const wss = new WebSocketServer({ noServer: true });
  wss.on("connection", handleWsConnection);
  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/ws") {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      wss.emit("connection", ws, req);
    });
  });
}
