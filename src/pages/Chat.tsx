import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { trpc } from "@/providers/trpc";
import { decryptText, deriveChannelKey, encryptText, generateCode, normalizeCode, sha256Hex } from "@/lib/crypto";
import { clearSession, getAgentTag, getLocalChannels, rememberChannel } from "@/lib/session";
import { openWs, sendWs, useWsConnection, useWsEvent } from "@/lib/ws";
import { ensurePushSubscribed } from "@/lib/push";
import {
  ShieldCheck, Plus, LogIn, UserPlus, Send, LogOut, Copy, Check, Hash, Lock, Wifi, WifiOff,
  Smile, Reply, Pencil, Trash2, X,
} from "lucide-react";

type Reaction = { agentId: number; emoji: string };
type PlainMsg = {
  id: number;
  senderTag: string;
  text: string;
  createdAt: Date;
  editedAt?: Date | null;
  deletedAt?: Date | null;
  replyTo?: number | null;
  reactions: Reaction[];
};
type Panel = "none" | "create" | "join" | "invite";

const REACTION_EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "🔥"];

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
  const [onlineByChannel, setOnlineByChannel] = useState<Record<number, number[]>>({});
  const [typingByChannel, setTypingByChannel] = useState<Record<number, Record<number, boolean>>>({});
  const [replyTo, setReplyTo] = useState<number | null>(null);
  const [editing, setEditing] = useState<number | null>(null);
  const [editDraft, setEditDraft] = useState("");
  const [reactionPicker, setReactionPicker] = useState<number | null>(null);
  const keyCache = useRef<Map<number, CryptoKey>>(new Map());
  const bottomRef = useRef<HTMLDivElement>(null);
  const typingTimer = useRef<number | null>(null);

  const channelsQuery = trpc.secure.listChannels.useQuery(undefined, { refetchInterval: 5000 });
  const membersQuery = trpc.secure.channelMembers.useQuery(
    { channelId: activeId! },
    { enabled: activeId != null },
  );
  const messagesQuery = trpc.secure.listMessages.useQuery(
    { channelId: activeId! },
    { enabled: activeId != null, refetchOnWindowFocus: false },
  );

  const createChannel = trpc.secure.createChannel.useMutation();
  const joinChannel = trpc.secure.joinChannel.useMutation();
  const issueKey = trpc.secure.issueAccessKey.useMutation();
  const sendMessage = trpc.secure.sendMessage.useMutation();
  const editMessage = trpc.secure.editMessage.useMutation();
  const deleteMessage = trpc.secure.deleteMessage.useMutation();
  const addReaction = trpc.secure.addReaction.useMutation();
  const removeReaction = trpc.secure.removeReaction.useMutation();
  const logout = trpc.secure.logout.useMutation();

  const wsState = useWsConnection();
  const myTag = getAgentTag();
  const myAgentId = useMemo(() => {
    // SSE "ready" event sets this. We don't know it without a server
    // round-trip, but a fresh page reload will get it within 1s.
    return undefined as number | undefined;
  }, []);

  useEffect(() => { openWs(); }, []);

  // Try to enable Web Push on first mount (only prompts the user the
  // first time; subsequent mounts are silent if already subscribed).
  useEffect(() => { void ensurePushSubscribed(); }, []);

  useEffect(() => {
    if (activeId == null) return;
    sendWs({ type: "subscribe", channelId: activeId });
    return () => { sendWs({ type: "unsubscribe", channelId: activeId }); };
  }, [activeId]);

  // Local message cache for any channel we have the key for. Decryption
  // is best-effort: a [unable to decrypt] placeholder is fine for a
  // message encrypted with a key the device doesn't hold.
  async function getKey(channelId: number): Promise<CryptoKey | null> {
    if (keyCache.current.has(channelId)) return keyCache.current.get(channelId)!;
    const local = getLocalChannels().find((c) => c.id === channelId);
    if (!local) return null;
    const key = await deriveChannelKey(local.inviteCode);
    keyCache.current.set(channelId, key);
    return key;
  }

  // Decrypt the freshly fetched listMessages payload (initial load)
  useEffect(() => {
    if (!activeId || !messagesQuery.data) return;
    (async () => {
      const key = await getKey(activeId);
      const out: PlainMsg[] = [];
      for (const m of messagesQuery.data) {
        let text = "";
        if (m.deletedAt) {
          text = "[deleted]";
        } else if (key) {
          try { text = await decryptText(key, m.ciphertext, m.nonce); }
          catch { text = "[unable to decrypt]"; }
        } else {
          text = "[no key for this channel on this device]";
        }
        out.push({
          id: m.id,
          senderTag: m.senderTag,
          text,
          createdAt: new Date(m.createdAt),
          editedAt: m.editedAt ? new Date(m.editedAt) : null,
          deletedAt: m.deletedAt ? new Date(m.deletedAt) : null,
          replyTo: m.replyTo,
          reactions: m.reactions ?? [],
        });
      }
      setPlain((p) => ({ ...p, [activeId]: out }));
    })();
  }, [messagesQuery.data, activeId]);

  // Auto-select first channel
  useEffect(() => {
    if (activeId == null && channels.length > 0) setActiveId(channels[0].id);
  }, [channels, activeId]);

  // Auto-scroll on new messages
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [plain, activeId]);

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
  const msgs = activeId != null ? plain[activeId] ?? [] : [];

  // --- SSE event handlers ---
  useWsEvent("message.created", async (e) => {
    if (e.channelId !== activeId) return;
    const key = await getKey(e.channelId);
    let text = "";
    if (key) {
      try { text = await decryptText(key, e.message.ciphertext, e.message.nonce); }
      catch { text = "[unable to decrypt]"; }
    }
    setPlain((p) => ({
      ...p,
      [e.channelId]: [...(p[e.channelId] ?? []), {
        id: e.message.id,
        senderTag: e.message.senderTag,
        text,
        createdAt: new Date(e.message.createdAt),
        replyTo: e.message.replyTo,
        editedAt: null,
        deletedAt: null,
        reactions: [],
      }],
    }));
  });

  useWsEvent("message.updated", async (e) => {
    if (e.channelId !== activeId) return;
    const key = await getKey(e.channelId);
    let text = "";
    if (key) {
      try { text = await decryptText(key, e.message.ciphertext, e.message.nonce); }
      catch { text = "[unable to decrypt]"; }
    }
    setPlain((p) => {
      const list = p[e.channelId] ?? [];
      return {
        ...p,
        [e.channelId]: list.map((m) => m.id === e.message.id
          ? { ...m, text, editedAt: e.message.editedAt ? new Date(e.message.editedAt) : m.editedAt }
          : m),
      };
    });
  });

  useWsEvent("message.deleted", (e) => {
    if (e.channelId !== activeId) return;
    setPlain((p) => {
      const list = p[e.channelId] ?? [];
      return {
        ...p,
        [e.channelId]: list.map((m) => m.id === e.messageId
          ? { ...m, text: "[deleted]", deletedAt: new Date() }
          : m),
      };
    });
  });

  useWsEvent("reaction.added", (e) => {
    if (e.channelId !== activeId) return;
    setPlain((p) => {
      const list = p[e.channelId] ?? [];
      return {
        ...p,
        [e.channelId]: list.map((m) => {
          if (m.id !== e.messageId) return m;
          if (m.reactions.some((r) => r.agentId === e.agentId && r.emoji === e.emoji)) return m;
          return { ...m, reactions: [...m.reactions, { agentId: e.agentId, emoji: e.emoji }] };
        }),
      };
    });
  });

  useWsEvent("reaction.removed", (e) => {
    if (e.channelId !== activeId) return;
    setPlain((p) => {
      const list = p[e.channelId] ?? [];
      return {
        ...p,
        [e.channelId]: list.map((m) => m.id === e.messageId
          ? { ...m, reactions: m.reactions.filter((r) => !(r.agentId === e.agentId && r.emoji === e.emoji)) }
          : m),
      };
    });
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

  // --- Actions ---
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
      setJoinCode(""); setLabel(""); setActiveId(res.channelId); setPanel("none");
      utils.secure.listChannels.invalidate();
    } catch { setPanelError("Invalid invite code."); }
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
    if (activeId) sendWs({ type: "typing.stop", channelId: activeId });
    setDraft("");
    const reply = replyTo;
    setReplyTo(null);
    await sendMessage.mutateAsync({ channelId: activeId, ciphertext, nonce, replyTo: reply ?? undefined });
  }
  async function handleEditSave(messageId: number) {
    if (activeId == null || !editDraft.trim()) return;
    const key = await getKey(activeId);
    if (!key) return;
    const { ciphertext, nonce } = await encryptText(key, editDraft.trim());
    await editMessage.mutateAsync({ messageId, ciphertext, nonce });
    setEditing(null); setEditDraft("");
  }
  async function handleDelete(messageId: number) {
    if (!confirm("Delete this message? (It will be removed for everyone.)")) return;
    await deleteMessage.mutateAsync({ messageId });
  }
  async function handleReact(messageId: number, emoji: string) {
    await addReaction.mutateAsync({ messageId, emoji });
    setReactionPicker(null);
  }
  async function handleUnreact(messageId: number, emoji: string) {
    await removeReaction.mutateAsync({ messageId, emoji });
  }
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

  const replyTarget = activeId != null && replyTo != null
    ? (plain[activeId] ?? []).find((m) => m.id === replyTo)
    : null;

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

            {replyTarget && (
              <div className="flex items-center justify-between border-b border-emerald-500/20 bg-emerald-500/5 px-5 py-2 text-xs text-emerald-300">
                <span>Replying to <span className="font-mono">{replyTarget.senderTag}</span>: {replyTarget.text.slice(0, 80)}{replyTarget.text.length > 80 ? "…" : ""}</span>
                <button onClick={() => setReplyTo(null)} className="text-emerald-500 hover:text-emerald-300">
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            )}

            <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
              {msgs.map((m) => {
                const mine = m.senderTag === myTag;
                const isEditing = editing === m.id;
                return (
                  <div key={m.id} className={`group flex flex-col ${mine ? "items-end" : "items-start"}`}>
                    {/* Reply context (preview of the parent message) */}
                    {m.replyTo != null && (
                      <div className={`mb-1 max-w-[70%] rounded-lg border-l-2 border-emerald-500/40 bg-neutral-900/40 px-3 py-1 text-[11px] text-neutral-500`}>
                        <span className="font-mono text-emerald-500">↳ reply to #{m.replyTo}</span>
                        <span className="ml-2 text-neutral-400">
                          {(plain[activeId!] ?? []).find((x) => x.id === m.replyTo)?.text.slice(0, 60) ?? "(unavailable)"}
                        </span>
                      </div>
                    )}
                    <div className="flex items-end gap-2">
                      {!mine && (
                        <button
                          onClick={() => setReactionPicker(reactionPicker === m.id ? null : m.id)}
                          className="invisible self-center rounded p-1 text-neutral-500 hover:bg-neutral-800 hover:text-emerald-400 group-hover:visible"
                          title="React"
                        >
                          <Smile className="h-3.5 w-3.5" />
                        </button>
                      )}
                      <div
                        className={`max-w-[70%] rounded-2xl px-4 py-2 text-sm ${
                          m.deletedAt
                            ? "rounded-bl-sm bg-neutral-900 text-neutral-600 italic"
                            : mine
                            ? "rounded-br-sm bg-emerald-600/90 text-white"
                            : "rounded-bl-sm bg-neutral-800 text-neutral-200"
                        }`}
                      >
                        {isEditing ? (
                          <div className="flex flex-col gap-2">
                            <input
                              value={editDraft}
                              onChange={(e) => setEditDraft(e.target.value)}
                              onKeyDown={(e) => { if (e.key === "Enter") handleEditSave(m.id); if (e.key === "Escape") { setEditing(null); setEditDraft(""); } }}
                              autoFocus
                              className="rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-sm text-neutral-100"
                            />
                            <div className="flex gap-2 text-xs">
                              <button onClick={() => handleEditSave(m.id)} className="rounded bg-emerald-600 px-2 py-1 text-white">Save</button>
                              <button onClick={() => { setEditing(null); setEditDraft(""); }} className="rounded bg-neutral-700 px-2 py-1 text-neutral-200">Cancel</button>
                            </div>
                          </div>
                        ) : (
                          <>
                            {m.text}
                            {m.editedAt && !m.deletedAt && (
                              <span className={`ml-1 text-[10px] ${mine ? "text-emerald-100/70" : "text-neutral-500"}`} title={`Edited ${new Date(m.editedAt).toLocaleString()}`}>
                                (edited)
                              </span>
                            )}
                          </>
                        )}
                      </div>
                      {mine && !m.deletedAt && (
                        <div className="invisible flex items-center gap-1 self-center group-hover:visible">
                          <button
                            onClick={() => { setEditing(m.id); setEditDraft(m.text); }}
                            className="rounded p-1 text-neutral-500 hover:bg-neutral-800 hover:text-emerald-400"
                            title="Edit"
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => handleDelete(m.id)}
                            className="rounded p-1 text-neutral-500 hover:bg-neutral-800 hover:text-red-400"
                            title="Delete"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      )}
                      {mine && (
                        <button
                          onClick={() => setReactionPicker(reactionPicker === m.id ? null : m.id)}
                          className="invisible self-center rounded p-1 text-neutral-500 hover:bg-neutral-800 hover:text-emerald-400 group-hover:visible"
                          title="React"
                        >
                          <Smile className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                    {/* Action row: reply + reactions */}
                    <div className="mt-1 flex flex-wrap items-center gap-1 px-1">
                      {!m.deletedAt && (
                        <button
                          onClick={() => setReplyTo(m.id)}
                          className="invisible rounded px-1.5 py-0.5 text-[10px] text-neutral-500 hover:bg-neutral-800 hover:text-neutral-300 group-hover:visible"
                          title="Reply"
                        >
                          <Reply className="h-3 w-3" />
                        </button>
                      )}
                      {m.reactions.map((r, i) => {
                        const iReacted = myAgentId === r.agentId; // best-effort; myAgentId may be undefined
                        return (
                          <button
                            key={i}
                            onClick={() => iReacted ? handleUnreact(m.id, r.emoji) : handleReact(m.id, r.emoji)}
                            className="rounded-full border border-neutral-700 bg-neutral-900 px-2 py-0.5 text-[11px] hover:border-emerald-500/50"
                            title="Toggle reaction"
                          >
                            {r.emoji} <span className="text-neutral-500">{m.reactions.filter((x) => x.emoji === r.emoji).length}</span>
                          </button>
                        );
                      })}
                      {reactionPicker === m.id && (
                        <div className="ml-1 flex gap-1 rounded-full border border-neutral-700 bg-neutral-900 px-2 py-1">
                          {REACTION_EMOJIS.map((e) => (
                            <button
                              key={e}
                              onClick={() => handleReact(m.id, e)}
                              className="text-base hover:scale-125 transition"
                            >
                              {e}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                    <span className="mt-0.5 font-mono text-[10px] text-neutral-600">
                      {m.senderTag} · {new Date(m.createdAt).toLocaleTimeString()}
                    </span>
                  </div>
                );
              })}
              {(() => {
                const typing = Object.keys(typingByChannel[activeId!] ?? {});
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
