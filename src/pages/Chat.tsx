import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { trpc } from "@/providers/trpc";
import { decryptText, deriveChannelKey, encryptText, generateCode, normalizeCode, sha256Hex } from "@/lib/crypto";
import { clearSession, getAgentTag, getLocalChannels, rememberChannel } from "@/lib/session";
import { openWs, sendWs, useWsConnection, useWsEvent } from "@/lib/ws";
import {
  ShieldCheck, Plus, LogIn, UserPlus, Send, LogOut, Copy, Check, Hash, Lock, Wifi, WifiOff,
} from "lucide-react";

type PlainMsg = { id: number; senderTag: string; text: string; createdAt: Date };
type Panel = "none" | "create" | "join" | "invite";

export default function Chat() {
  const navigate = useNavigate();
  const utils = trpc.useUtils();

  const [activeId, setActiveId] = useState<number | null>(null);
  const [panel, setPanel] = useState<Panel>("none");
  const [draft, setDraft] = useState("");
  const [label, setLabel] = useState("");
  const [joinCode, setJoinCode] = useState("");
  const [oneTimeSecret, setOneTimeSecret] = useState<{ title: string; code: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [panelError, setPanelError] = useState("");
  const [plain, setPlain] = useState<Record<number, PlainMsg[]>>({});
  const keyCache = useRef<Map<number, CryptoKey>>(new Map());
  const bottomRef = useRef<HTMLDivElement>(null);

  const channelsQuery = trpc.secure.listChannels.useQuery(undefined, { refetchInterval: 5000 });
  const membersQuery = trpc.secure.channelMembers.useQuery(
    { channelId: activeId! },
    { enabled: activeId != null },
  );
  // Initial message load: poll once on channel change, then let WS push
  // updates. This avoids the cold-start race where the WS connects after
  // the user has already loaded the page.
  const messagesQuery = trpc.secure.listMessages.useQuery(
    { channelId: activeId! },
    { enabled: activeId != null, refetchInterval: false, refetchOnWindowFocus: false },
  );

  // Live state derived from WS events
  const [onlineByChannel, setOnlineByChannel] = useState<Record<number, number[]>>({});
  const [typingByChannel, setTypingByChannel] = useState<Record<number, Record<number, boolean>>>({});
  const wsState = useWsConnection();

  useEffect(() => {
    openWs();
  }, []);

  // Subscribe to the active channel over WS
  useEffect(() => {
    if (activeId == null) return;
    sendWs({ type: "subscribe", channelId: activeId });
    return () => { sendWs({ type: "unsubscribe", channelId: activeId }); };
  }, [activeId]);

  // Live message arrival: decrypt and append
  useWsEvent("message.created", async (e) => {
    if (e.channelId !== activeId) return;
    const key = await getKey(e.channelId);
    if (!key) return;
    let text: string;
    try {
      text = await decryptText(key, e.message.ciphertext, e.message.nonce);
    } catch {
      text = "[unable to decrypt]";
    }
    setPlain((p) => ({
      ...p,
      [e.channelId]: [...(p[e.channelId] ?? []), {
        id: e.message.id,
        senderTag: e.message.senderTag,
        text,
        createdAt: new Date(e.message.createdAt),
      }],
    }));
  });

  useWsEvent("presence.update", (e) => {
    setOnlineByChannel((s) => ({ ...s, [e.channelId]: e.online }));
  });
  useWsEvent("channel.member_joined", (e) => {
    setOnlineByChannel((s) => ({ ...s, [e.channelId]: e.online }));
  });
  useWsEvent("typing.update", (e) => {
    setTypingByChannel((s) => {
      const cur = { ...(s[e.channelId] ?? {}) };
      if (e.isTyping) cur[e.agentId] = true;
      else delete cur[e.agentId];
      return { ...s, [e.channelId]: cur };
    });
  });

  const createChannel = trpc.secure.createChannel.useMutation();
  const joinChannel = trpc.secure.joinChannel.useMutation();
  const issueKey = trpc.secure.issueAccessKey.useMutation();
  const sendMessage = trpc.secure.sendMessage.useMutation();
  const logout = trpc.secure.logout.useMutation();

  const localChannels = getLocalChannels();
  const channels = useMemo(
    () =>
      (channelsQuery.data ?? []).map((c) => {
        const local = localChannels.find((l) => l.id === c.id);
        return { id: c.id, label: local?.label ?? `Channel #${c.id}`, hasKey: !!local };
      }),
    [channelsQuery.data, localChannels],
  );

  const activeLocal = activeId != null ? localChannels.find((c) => c.id === activeId) : undefined;

  async function getKey(channelId: number): Promise<CryptoKey | null> {
    if (keyCache.current.has(channelId)) return keyCache.current.get(channelId)!;
    const local = getLocalChannels().find((c) => c.id === channelId);
    if (!local) return null;
    const key = await deriveChannelKey(local.inviteCode);
    keyCache.current.set(channelId, key);
    return key;
  }

  // Decrypt incoming ciphertext client-side.
  useEffect(() => {
    if (!activeId || !messagesQuery.data) return;
    const existing = plain[activeId] ?? [];
    const known = new Set(existing.map((m) => m.id));
    const fresh = messagesQuery.data.filter((m) => !known.has(m.id));
    if (fresh.length === 0) return;
    (async () => {
      const key = await getKey(activeId);
      if (!key) return;
      const decoded: PlainMsg[] = [];
      for (const m of fresh) {
        try {
          decoded.push({
            id: m.id,
            senderTag: m.senderTag,
            text: await decryptText(key, m.ciphertext, m.nonce),
            createdAt: m.createdAt,
          });
        } catch {
          decoded.push({ id: m.id, senderTag: m.senderTag, text: "[unable to decrypt]", createdAt: m.createdAt });
        }
      }
      setPlain((p) => ({
        ...p,
        [activeId]: [...(p[activeId] ?? []), ...decoded].sort((a, b) => a.id - b.id),
      }));
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messagesQuery.data, activeId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [plain, activeId]);

  // Auto-select first channel
  useEffect(() => {
    if (activeId == null && channels.length > 0) setActiveId(channels[0].id);
  }, [channels, activeId]);

  const myTag = getAgentTag();
  const msgs = activeId != null ? plain[activeId] ?? [] : [];

  async function handleCreate() {
    setPanelError("");
    if (!label.trim()) return setPanelError("Give the channel a local label.");
    const inviteCode = generateCode(8, 5);
    const inviteHash = await sha256Hex(normalizeCode(inviteCode));
    const res = await createChannel.mutateAsync({ inviteHash });
    rememberChannel({ id: res.channelId, label: label.trim(), inviteCode });
    setOneTimeSecret({ title: "Channel invite code — share it in person. It will not be shown again.", code: inviteCode });
    setLabel("");
    setActiveId(res.channelId);
    utils.secure.listChannels.invalidate();
  }

  async function handleJoin() {
    setPanelError("");
    const code = normalizeCode(joinCode);
    if (code.length < 20) return setPanelError("Invite code looks too short.");
    try {
      const inviteHash = await sha256Hex(code);
      const res = await joinChannel.mutateAsync({ inviteHash });
      rememberChannel({
        id: res.channelId,
        label: label.trim() || `Channel #${res.channelId}`,
        inviteCode: joinCode.toUpperCase(),
      });
      setJoinCode("");
      setLabel("");
      setActiveId(res.channelId);
      setPanel("none");
      utils.secure.listChannels.invalidate();
    } catch {
      setPanelError("Invalid invite code.");
    }
  }

  async function handleInvite() {
    setPanelError("");
    const newKey = generateCode(8, 5);
    const keyHash = await sha256Hex(normalizeCode(newKey));
    await issueKey.mutateAsync({ keyHash });
    setOneTimeSecret({ title: "New access key — deliver it in person. It will not be shown again.", code: newKey });
  }

  async function handleSend() {
    if (!draft.trim() || activeId == null) return;
    const key = await getKey(activeId);
    if (!key) return;
    const { ciphertext, nonce } = await encryptText(key, draft.trim());
    const text = draft.trim();
    setDraft("");
    // typing.stop is implicit when the draft clears
    if (activeId) sendWs({ type: "typing.stop", channelId: activeId });
    await sendMessage.mutateAsync({ channelId: activeId, ciphertext, nonce });
    // The WS message.created broadcast will append the message; we don't
    // optimistic-insert here anymore (the broadcast handles it). The
    // server is the source of truth for message ids and timestamps.
  }

  // Typing: send typing.start on first keystroke, typing.stop 3s after
  // the last keystroke (or when the draft is cleared).
  const typingTimer = useRef<number | null>(null);
  function onDraftChange(v: string) {
    setDraft(v);
    if (activeId == null) return;
    if (v.length === 0) {
      if (typingTimer.current != null) window.clearTimeout(typingTimer.current);
      typingTimer.current = null;
      sendWs({ type: "typing.stop", channelId: activeId });
      return;
    }
    sendWs({ type: "typing.start", channelId: activeId });
    if (typingTimer.current != null) window.clearTimeout(typingTimer.current);
    typingTimer.current = window.setTimeout(() => {
      sendWs({ type: "typing.stop", channelId: activeId });
      typingTimer.current = null;
    }, 3000);
  }

  function handleLogout() {
    logout.mutate();
    clearSession();
    navigate("/");
  }

  return (
    <div className="flex h-screen bg-neutral-950 text-neutral-200">
      {/* Sidebar */}
      <aside className="flex w-64 shrink-0 flex-col border-r border-neutral-800 bg-neutral-900/60">
        <div className="flex items-center gap-2 border-b border-neutral-800 px-4 py-4">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          <span className="text-sm font-semibold tracking-widest">BLACKVAULT</span>
        </div>

        <div className="flex gap-1.5 px-3 pt-3">
          <SideBtn icon={<Plus className="h-4 w-4" />} label="New" onClick={() => { setPanel("create"); setOneTimeSecret(null); setPanelError(""); }} />
          <SideBtn icon={<LogIn className="h-4 w-4" />} label="Join" onClick={() => { setPanel("join"); setOneTimeSecret(null); setPanelError(""); }} />
          <SideBtn icon={<UserPlus className="h-4 w-4" />} label="Invite" onClick={() => { setPanel("invite"); setOneTimeSecret(null); setPanelError(""); }} />
        </div>

        <div className="mt-4 flex-1 overflow-y-auto px-2">
          {channels.map((c) => (
            <button
              key={c.id}
              onClick={() => setActiveId(c.id)}
              className={`mb-1 flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm transition ${
                activeId === c.id ? "bg-emerald-500/10 text-emerald-300" : "text-neutral-400 hover:bg-neutral-800"
              }`}
            >
              <Hash className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate">{c.label}</span>
              {!c.hasKey && <Lock className="ml-auto h-3 w-3 text-amber-500" />}
            </button>
          ))}
          {channels.length === 0 && (
            <p className="px-3 pt-4 text-xs text-neutral-600">No channels yet. Create one or join with an invite code.</p>
          )}
        </div>

        <div className="border-t border-neutral-800 px-4 py-3">
          <div className="mb-2 flex items-center justify-between text-xs text-neutral-500">
            <span>Agent</span>
            <span className="font-mono text-emerald-400">{myTag}</span>
          </div>
          <button onClick={handleLogout} className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-xs text-neutral-500 hover:bg-neutral-800 hover:text-red-400">
            <LogOut className="h-3.5 w-3.5" /> Wipe session & exit
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex flex-1 flex-col">
        {panel !== "none" ? (
          <div className="flex flex-1 items-center justify-center p-6">
            <div className="w-full max-w-md rounded-2xl border border-neutral-800 bg-neutral-900 p-6">
              {oneTimeSecret ? (
                <>
                  <h2 className="mb-1 text-sm font-semibold text-neutral-100">Secret issued</h2>
                  <p className="mb-4 text-xs text-amber-400">{oneTimeSecret.title}</p>
                  <div className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-neutral-950 p-3">
                    <code className="flex-1 break-all font-mono text-sm text-emerald-300">{oneTimeSecret.code}</code>
                    <button
                      onClick={() => { navigator.clipboard.writeText(oneTimeSecret.code); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
                      className="text-neutral-400 hover:text-emerald-400"
                    >
                      {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                    </button>
                  </div>
                  <button onClick={() => { setOneTimeSecret(null); setPanel("none"); }} className="mt-4 w-full rounded-lg bg-neutral-800 py-2 text-sm hover:bg-neutral-700">
                    Done
                  </button>
                </>
              ) : panel === "create" ? (
                <>
                  <h2 className="mb-4 text-sm font-semibold text-neutral-100">Create channel</h2>
                  <Field label="Local label (only stored on your device)" value={label} onChange={setLabel} placeholder="e.g. ops" />
                  <Err msg={panelError} />
                  <ActionBtn onClick={handleCreate} loading={createChannel.isPending} text="Generate invite code & create" />
                </>
              ) : panel === "join" ? (
                <>
                  <h2 className="mb-4 text-sm font-semibold text-neutral-100">Join channel</h2>
                  <Field label="Invite code" value={joinCode} onChange={setJoinCode} placeholder="XXXXX-XXXXX-…" mono />
                  <div className="mt-3">
                    <Field label="Local label (optional)" value={label} onChange={setLabel} placeholder="e.g. ops" />
                  </div>
                  <Err msg={panelError} />
                  <ActionBtn onClick={handleJoin} loading={joinChannel.isPending} text="Join" />
                </>
              ) : (
                <>
                  <h2 className="mb-2 text-sm font-semibold text-neutral-100">Invite a new member</h2>
                  <p className="mb-4 text-xs text-neutral-500">
                    Generates a one-time access key. Only its hash is stored — the plaintext key is shown once, to you.
                  </p>
                  <Err msg={panelError} />
                  <ActionBtn onClick={handleInvite} loading={issueKey.isPending} text="Generate access key" />
                </>
              )}
              {!oneTimeSecret && (
                <button onClick={() => setPanel("none")} className="mt-3 w-full text-center text-xs text-neutral-600 hover:text-neutral-400">
                  Cancel
                </button>
              )}
            </div>
          </div>
        ) : activeId == null ? (
          <div className="flex flex-1 items-center justify-center text-sm text-neutral-600">
            Select a channel, or create one.
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between border-b border-neutral-800 px-5 py-3">
              <div className="flex items-center gap-2 text-sm">
                <Hash className="h-4 w-4 text-emerald-400" />
                <span className="font-medium">{channels.find((c) => c.id === activeId)?.label}</span>
                <span className="ml-2 flex items-center gap-1 rounded-full border border-emerald-500/30 px-2 py-0.5 text-[10px] text-emerald-400">
                  <Lock className="h-2.5 w-2.5" /> E2E encrypted
                </span>
                <span className={`ml-2 flex items-center gap-1 text-[10px] ${wsState === "open" ? "text-emerald-400" : "text-amber-400"}`} title={wsState === "open" ? "Live connection" : "Reconnecting…"}>
                  {wsState === "open" ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                  {wsState === "open" ? "live" : "offline"}
                </span>
              </div>
              <span className="text-xs text-neutral-600">
                {membersQuery.data?.length ?? 0} member(s): {(membersQuery.data ?? []).map((m) => m.tag).join(" · ")}
                {(() => {
                  const online = onlineByChannel[activeId!] ?? [];
                  if (online.length === 0) return null;
                  return <span className="ml-2 text-emerald-400">{online.length} online</span>;
                })()}
              </span>
            </div>

            {!activeLocal && (
              <div className="border-b border-amber-500/20 bg-amber-500/5 px-5 py-2 text-xs text-amber-400">
                This device doesn't hold the invite code for this channel — messages can't be decrypted here. Re-join with the invite code.
              </div>
            )}

            <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
              {msgs.map((m) => (
                <div key={m.id} className={`flex flex-col ${m.senderTag === myTag ? "items-end" : "items-start"}`}>
                  <div
                    className={`max-w-[70%] rounded-2xl px-4 py-2 text-sm ${
                      m.senderTag === myTag
                        ? "rounded-br-sm bg-emerald-600/90 text-white"
                        : "rounded-bl-sm bg-neutral-800 text-neutral-200"
                    }`}
                  >
                    {m.text}
                  </div>
                  <span className="mt-1 font-mono text-[10px] text-neutral-600">
                    {m.senderTag} · {new Date(m.createdAt).toLocaleTimeString()}
                  </span>
                </div>
              ))}
              {(() => {
                const typing = Object.keys(typingByChannel[activeId!] ?? {}).filter((id) => Number(id) !== undefined);
                if (typing.length === 0) return null;
                return (
                  <div className="flex items-center gap-2 px-2 text-[10px] text-neutral-500">
                    <span className="flex gap-0.5">
                      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-emerald-400 [animation-delay:-0.3s]" />
                      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-emerald-400 [animation-delay:-0.15s]" />
                      <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-emerald-400" />
                    </span>
                    {typing.length === 1 ? "someone" : `${typing.length} people`} typing…
                  </div>
                );
              })()}
              <div ref={bottomRef} />
            </div>

            <div className="border-t border-neutral-800 p-4">
              <div className="flex items-center gap-2">
                <input
                  value={draft}
                  onChange={(e) => onDraftChange(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSend()}
                  placeholder="Message (encrypted before it leaves this device)…"
                  className="flex-1 rounded-lg border border-neutral-700 bg-neutral-900 px-4 py-2.5 text-sm outline-none placeholder:text-neutral-600 focus:border-emerald-500"
                />
                <button
                  onClick={handleSend}
                  disabled={sendMessage.isPending || !draft.trim()}
                  className="rounded-lg bg-emerald-600 p-2.5 text-white hover:bg-emerald-500 disabled:opacity-40"
                >
                  <Send className="h-4 w-4" />
                </button>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

function SideBtn({ icon, label, onClick }: { icon: React.ReactNode; label: string; onClick: () => void }) {
  return (
    <button onClick={onClick} className="flex flex-1 flex-col items-center gap-1 rounded-lg border border-neutral-800 py-2 text-[10px] text-neutral-400 hover:border-emerald-500/40 hover:text-emerald-300">
      {icon}
      {label}
    </button>
  );
}

function Field({ label, value, onChange, placeholder, mono }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean;
}) {
  return (
    <div>
      <label className="mb-1 block text-xs text-neutral-500">{label}</label>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        className={`w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm outline-none focus:border-emerald-500 ${mono ? "font-mono text-emerald-300" : ""}`}
      />
    </div>
  );
}

function Err({ msg }: { msg: string }) {
  return msg ? <p className="mt-3 text-xs text-red-400">{msg}</p> : null;
}

function ActionBtn({ onClick, loading, text }: { onClick: () => void; loading: boolean; text: string }) {
  return (
    <button onClick={onClick} disabled={loading} className="mt-4 w-full rounded-lg bg-emerald-600 py-2.5 text-sm font-semibold text-white hover:bg-emerald-500 disabled:opacity-50">
      {loading ? "Working…" : text}
    </button>
  );
}
