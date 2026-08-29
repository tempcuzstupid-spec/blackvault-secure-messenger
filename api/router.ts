import { createRouter, publicQuery } from "./middleware";
import { secureRouter } from "./secureRouter";

export const appRouter = createRouter({
  ping: publicQuery.query(() => ({ ok: true, ts: Date.now() })),
  secure: secureRouter,
});

export type AppRouter = typeof appRouter;
