// Web Push sender. Wraps `web-push` with a content-hidden payload
// policy: push bodies NEVER contain message text, ciphertext, sender
// tags, or channel names. The payload is just enough to wake the
// device and show a generic notification; the user opens the app to
// see what the message actually says.

import webpush from "web-push";
import { eq } from "drizzle-orm";
import { getDb } from "../queries/connection";
import { pushSubscriptions } from "@db/schema";
import { env } from "../lib/env";

let configured = false;
function configure() {
  if (configured) return;
  if (!env.vapidPublicKey || !env.vapidPrivateKey || !env.vapidSubject) {
    // No VAPID keys yet; push will silently no-op.
    return;
  }
  webpush.setVapidDetails(env.vapidSubject, env.vapidPublicKey, env.vapidPrivateKey);
  configured = true;
}

export type PushPayload = {
  // Generic, content-hidden fields. The recipient opens the app to
  // read the actual message; this notification exists only to wake
  // the device.
  title: string;
  body: string;
  tag: string;
  url: string; // deep-link the notification click opens
  icon?: string;
  badge?: string;
};

/**
 * Send a push notification to a specific subscription. Resolves true
 * if delivered, false if the subscription is gone (410 Gone) or
 * otherwise permanently invalid (we should remove it from the DB).
 */
export async function sendToSubscription(
  sub: { endpoint: string; p256dh: string; auth: string },
  payload: PushPayload,
): Promise<boolean> {
  configure();
  if (!configured) return false;
  try {
    await webpush.sendNotification(
      {
        endpoint: sub.endpoint,
        keys: { p256dh: sub.p256dh, auth: sub.auth },
      } as any,
      JSON.stringify(payload),
      { TTL: 60 * 60 * 24 }, // 24h
    );
    return true;
  } catch (e: any) {
    const status = e?.statusCode ?? 0;
    if (status === 404 || status === 410) {
      // Subscription is gone; clean it up.
      const db = getDb();
      await db.delete(pushSubscriptions).where(eq(pushSubscriptions.endpoint, sub.endpoint));
    }
    return false;
  }
}

/**
 * Fan out a push to every push subscription belonging to agents in
 * `agentIds`, EXCEPT the sender. Pushes are sent in parallel; failures
 * are logged but don't throw.
 */
export async function pushToAgents(agentIds: number[], payload: PushPayload, exceptAgentId?: number) {
  if (agentIds.length === 0) return;
  const db = getDb();
  const targets = agentIds.filter((id) => id !== exceptAgentId);
  if (targets.length === 0) return;
  const rows = await db
    .select({ endpoint: pushSubscriptions.endpoint, p256dh: pushSubscriptions.p256dh, auth: pushSubscriptions.auth })
    .from(pushSubscriptions);
  // De-dupe by endpoint (one endpoint per device)
  const byEndpoint = new Map<string, { endpoint: string; p256dh: string; auth: string }>();
  for (const r of rows) byEndpoint.set(r.endpoint, r);
  await Promise.all([...byEndpoint.values()].map((s) => sendToSubscription(s, payload)));
}
