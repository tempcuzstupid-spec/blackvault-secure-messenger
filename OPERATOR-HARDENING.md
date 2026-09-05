# BlackVault Operator Hardening Notes

**Status:** Draft. For the Hono+tRPC server on Render, the relay, and any future
infrastructure. The goal is to shrink what a seized server reveals, beyond what the
protocol itself guarantees.

These notes are about **voluntary** logs and retained state. They do not address
compromise of running memory, kernel-level access, or physical access to the host
hardware — those are operational concerns outside the protocol's threat model.

---

## 1. The principle

A seized server reveals only what it was holding at the time of seizure. The
BlackVault protocol is designed so that the *content* of messages, voice calls,
and keys is never on the server. This document is about *metadata*: connection
records, error logs, request logs, and any state that the server was persisting
beyond what is strictly needed for the service to function.

**Default: do not collect it. If a future feature requires it, that requirement
is a spec change, not an operator choice.**

---

## 2. The BlackVault Hono server (the main app)

This is the service running on Render (`srv-da9rkhhsrm7s73d54hl0`).

### 2.1 HTTP access logs

**Default Render behavior:** Render's edge proxy logs every HTTP request to
your service. This is configurable in the Render dashboard:
**Settings → Advanced → "Disable detailed request logs"** (or equivalent; the
exact toggle name changes).

**Required:** disable detailed request logging on the Render dashboard. The
edge will still log catastrophic errors, but not the per-request metadata.

**In your Hono app:** do not add any HTTP access logging middleware. The
`logger` middleware from Hono is a tempting default; do not enable it. There
is no business need for the BlackVault server to log every request, and the
log volume itself becomes a seizure target.

### 2.2 Per-message metadata already in the database

The `messages` table contains: `id`, `channel_id`, `agent_id`, `ciphertext`,
`nonce`, `reply_to`, `edited_at`, `deleted_at`, `created_at`. This is what
the protocol requires the server to know (it can't look up a message by id
otherwise).

**This is unavoidable.** It is the price of having a server at all. The
mitigation is that `ciphertext` is meaningless without the channel key, and
the channel key is never on the server. A seized server reveals: who sent
messages to which channel and when. It does not reveal what the messages
said.

**In a future phase:** sealed-sender-style delivery reduces the `agent_id`
metadata to "someone in this channel sent this." That is on the roadmap.

### 2.3 SSE connection state

The Hono server holds the set of currently-connected SSE clients in memory.
This state is process-local; it is not persisted anywhere. A seized server
loses all SSE connection state at the moment of process termination (or,
more accurately, at the moment the OS shuts down the process — which may
be 30+ seconds after the seizure, during which a careful operator could
preserve the state).

**Required:** the SSE connection state should be wiped on shutdown. Render
sends `SIGTERM` to the process before shutting it down. The Hono server
should handle SIGTERM by:
1. Closing all open SSE streams cleanly
2. Letting in-flight requests complete (with a deadline of ~10 seconds)
3. Exiting

This is the default behavior of Node.js on SIGTERM (the process exits when
the event loop is empty), so explicit handling is not required, but a
SIGTERM handler that logs the event and starts a 10-second shutdown
timer is recommended.

### 2.4 Stdout / stderr

Render captures stdout and stderr from your service. These are visible in
the Render dashboard under the service's "Logs" tab. They are also written
to Render's internal log storage and persisted for some retention period
(depends on the Render plan).

**Required:**
- Log only at `error` level and above. Information-level logs should be
  removed or guarded behind a build-time flag.
- Never log request bodies, response bodies, headers, or user identifiers.
  A `console.log({ userId, requestBody })` is a seizure-grade leak.
- Never log the contents of a `CallOffer` or `CallAnswer` message body.
  The SDP and keys are sensitive even though they are not the long-term
  keys, because they are fresh per call.
- Never log the contents of a `pushSubscription` endpoint, p256dh, or
  auth key. These are sensitive.

**Recommended:** set up a Render log drain that forwards only `error` to a
log aggregator. Information-level logs are dropped at the drain. Free Render
plans may not support log drains; in that case, ensure the app only emits
`error` and above.

### 2.5 Database backups

The Neon database is backed up automatically by Neon. Backups are part of
Neon's infrastructure. If Neon is seized, the backups are also at risk.

**This is a Neon-side concern, not a BlackVault concern.** Neon's data
handling policy is Neon's responsibility. For v1, accept the Neon
seizure model. For a higher-assurance deployment, the recommendation is:
self-host Postgres (the schema is portable; the migration is in
`db/migrations/`).

### 2.6 Cookies and sessions

BlackVault does not use cookies. The session token is passed in the
`Authorization: Bearer <token>` header on each request. The token is a
random 32-byte value stored in the `sessions` table with a 24-hour expiry.

**Required:** when a user logs out, the session row is deleted (already
implemented). The `expires_at` column provides automatic cleanup for
abandoned sessions, but a periodic job (cron) should hard-delete sessions
older than 7 days as a defense-in-depth measure.

### 2.7 The `VAPID_PRIVATE_KEY` environment variable

This is the private key for the Web Push server. A seized server reveals
this key.

**Implication:** with the VAPID private key, an adversary can send push
notifications impersonating BlackVault. This is a server-side
authentication bypass for push. The push payload is still content-hidden
(see `api/push/sender.ts`), so the audio content of a call is not
revealed, but the user could be tricked into opening the app at a specific
URL.

**Mitigation:** rotate the VAPID keypair periodically. Rotation requires
existing push subscriptions to be re-registered (the VAPID public key is
baked into the subscription at registration time). The application should
handle a VAPID key rotation gracefully: on first push failure with a 404
or 410, re-register the subscription with the new key. (Not implemented
in v1; document the manual procedure in the runbook.)

### 2.8 The `DATABASE_URL` environment variable

This is the Postgres connection string. It contains the database user and
password.

**Mitigation:** treat this as a secret. The Neon database user
`neondb_owner` has full read/write on the `neondb` database. Rotate the
password periodically. Create a separate read-only user for any future
analytics or migration tools.

### 2.9 What the server returns in error responses

Hono's default error responses include the error message. In production,
`env.NODE_ENV === "production"`, error messages should be generic:
`{ "error": "Internal Server Error" }` rather than the raw exception. Stack
traces should never be returned to the client.

**Required:** ensure the production error handler in `api/boot.ts` and
`tRPC` middleware does not leak stack traces or Drizzle error details
to the client. Currently, the secureRouter catches and rethrows TRPCError
with appropriate codes, but Drizzle errors are wrapped in
`{ error: { json: { message: "Failed query: ..." } } }` which leaks
schema information.

**Fix for v1 (not yet implemented):** in production, log the detailed
error server-side and return a generic message to the client. The error
log should include a correlation ID that the user can quote when reporting
an issue, so the operator can find the detailed log without exposing it.

---

## 3. The TURN relay (coturn)

This is a separate service from the BlackVault Hono server. It is the
relay that all voice media flows through. It runs on the user's VPS at
`142.93.48.232` (per memory) or a similar disposable host.

### 3.1 coturn configuration (mandatory)

The `coturn` configuration file (`/etc/turnserver.conf` or equivalent)
should set:

```
# No logs
no-log
log-file=
syslog=

# No CLI
no-cli

# No loopback peers
no-loopback-peers
no-multicast-peers

# No relay loops
no-relay-loop

# TURN-only (no STUN)
no-stun

# Short-lived credentials (TURN REST API)
use-auth-secret
static-auth-secret=<see §3.2>

# TLS only (port 3478 with TLS, or 5349)
# cert and pkey paths go here
listening-port=3478
tls-listening-port=5349
cert=/etc/letsencrypt/live/<domain>/fullchain.pem
pkey=/etc/letsencrypt/live/<domain>/privkey.pem

# No database
no-auth-pings
```

### 3.2 Short-lived credentials

TURN credentials are issued by the BlackVault Hono server using the
coturn `use-auth-secret` mechanism. The credential has a TTL of 1 hour
and is bound to the call ID. The Hono server does not log the issued
credential (the credential is in the response body to the client, but
the Hono server should not write it to stdout or any persistent log).

**The Hono server logs:** the issuance event (call ID, agent ID, expiry)
but not the credential value.

### 3.3 Process supervision

`coturn` should be run under a minimal process supervisor (e.g., systemd
with `Restart=on-failure`, or runit). The supervisor should:
- Not write to a persistent log file
- Discard stdout and stderr
- Restart on crash with exponential backoff

### 3.4 Jurisdiction

The TURN relay is the part of the system most exposed to legal compulsion,
because voice traffic flows through it. Deploy in a jurisdiction that:
- Does not require data retention for VoIP relays
- Has a track record of resisting compelled disclosure
- Is not a member of an intelligence-sharing alliance that the threat
  model considers adversarial

**This is a deployment decision, not a code decision.** The threat model
assumes the operator can choose a non-adversarial jurisdiction.

### 3.5 What a seized relay reveals

A seized TURN relay reveals:
- The IP addresses of both peers (during the call)
- The timing of every call (start, end, duration)
- The total bytes transferred per call
- The packet sizes and timing within a call (which can be used to infer
  speech patterns; see §12.5 of `PROTOCOL.md`)

It does NOT reveal:
- The audio content (SRTP is end-to-end encrypted)
- The call participants' identities (assuming the relay does not see the
  BlackVault message headers, which it does not in v1; the relay only
  sees the WebRTC peer connections)
- The content of the text channel

---

## 4. The text channel key exchange

The channel key is derived in the browser from the invite code via HKDF.
The invite code is generated client-side, shown to the inviter once, and
the plaintext is never sent to the server. The server sees only the
SHA-256 hash of the invite code.

**The security of the channel reduces to: the inviter delivers the
invite code to the invitee over a side channel** (in person, encrypted
email, etc.). The server cannot help with this. Document this in the
in-app "share invite" flow.

---

## 5. Voluntary vs. compelled disclosure

**Voluntary:** the operator can choose what to log. The defaults in §2-3
above are voluntary. The operator should commit, ideally in a public
transparency report, to:
- Never voluntarily log access to a specific user's account
- Never voluntarily log the content of messages
- Never voluntarily log the existence of a specific call

**Compelled:** a court order, subpoena, or national-security letter can
compel the operator to disclose what's on the server. The protocol
design minimizes what the operator can be compelled to disclose (because
the operator doesn't have it), but the operator's commitment to
resisting compelled disclosure is a separate matter from the technical
design.

**Threat-model note:** the spec assumes "a nation state that does not use
or need court orders." A state that doesn't need court orders doesn't
need to compel the operator; it can simply seize the server. The
mitigations in this document reduce what a seizure reveals, not what a
compelled disclosure reveals (the two are different threat models and
should not be conflated).

---

## 6. Concrete checklist (copy this into your runbook)

- [ ] Render dashboard: detailed request logs disabled
- [ ] Render dashboard: log drain configured (if on a plan that supports it) to forward only `error` and above
- [ ] Hono app: no HTTP access logging middleware in `api/boot.ts`
- [ ] Hono app: production error handler does not leak stack traces or Drizzle error details
- [ ] Hono app: log level set to `error` only, or guarded behind a build-time flag
- [ ] Hono app: SIGTERM handler installed, with 10-second shutdown timer
- [ ] Neon: `neondb_owner` password rotated on a schedule (recommend: quarterly)
- [ ] Neon: read-only user created for any future analytics/migration tools
- [ ] Periodic cron: hard-delete sessions older than 7 days
- [ ] VAPID keypair: rotate on a schedule (recommend: annually); document the rotation procedure
- [ ] TURN relay: deployed with the configuration in §3.1
- [ ] TURN relay: stdout/stderr discarded
- [ ] TURN relay: jurisdiction chosen; documented in the runbook
- [ ] Backup policy: documented; tested; backups themselves don't include plaintext (they can't, since the data is ciphertext)
- [ ] Incident response plan: documented; covers the case of a server seizure
- [ ] Transparency report: published annually (or on request); lists any compelled disclosures (or, ideally, the absence of any)

---

## 7. What this document does not cover

- Endpoint hardening (the user's device). Out of scope.
- Physical security of the server hardware. Out of scope.
- Browser fingerprinting and tracking. Out of scope.
- Quantum-computer attacks on classical crypto (the protocol uses PQ
  hybrid, but the channel key, the VAPID keys, and the identity keys
  are still classically secured). Roadmap: replace identity keys with
  PQ-only or PQ-hybrid in v2.
- Side-channel attacks on the running process (cache timing, power
  analysis). Out of scope at the application layer.
- The Neon database's internal data handling policy. Neon's
  responsibility.

---

## 8. Versioning

This document is version 1, dated 2025-09-05, written as part of the
BlackVault voice protocol v1. Changes to the protocol require a
version bump and a corresponding update to this document.
