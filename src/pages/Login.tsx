import { useState } from "react";
import { useNavigate } from "react-router";
import { trpc } from "@/providers/trpc";
import { normalizeCode, sha256Hex } from "@/lib/crypto";
import { setSession } from "@/lib/session";
import { ShieldCheck, KeyRound, Eye, EyeOff } from "lucide-react";

export default function Login() {
  const navigate = useNavigate();
  const [key, setKey] = useState("");
  const [show, setShow] = useState(false);
  const [error, setError] = useState("");
  const login = trpc.secure.login.useMutation();

  const submit = async () => {
    setError("");
    const normalized = normalizeCode(key);
    if (normalized.length < 20) {
      setError("Access key looks too short.");
      return;
    }
    try {
      const keyHash = await sha256Hex(normalized);
      const res = await login.mutateAsync({ keyHash });
      setSession(res.token, res.agentTag);
      navigate("/vault");
    } catch {
      setError("Key not recognized. Access is by invitation only.");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-950 px-4">
      <div className="w-full max-w-sm rounded-2xl border border-neutral-800 bg-neutral-900 p-8 shadow-2xl">
        <div className="mb-8 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-full border border-emerald-500/30 bg-emerald-500/10">
            <ShieldCheck className="h-7 w-7 text-emerald-400" />
          </div>
          <h1 className="text-xl font-semibold tracking-widest text-neutral-100">BLACKVAULT</h1>
          <p className="text-center text-xs text-neutral-500">
            Anonymous · Invite-only · End-to-end encrypted
          </p>
        </div>

        <label className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-neutral-400">
          <KeyRound className="h-3.5 w-3.5" /> Access Key
        </label>
        <div className="relative">
          <input
            type={show ? "text" : "password"}
            value={key}
            onChange={(e) => setKey(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="XXXXX-XXXXX-XXXXX-…"
            autoComplete="off"
            spellCheck={false}
            className="w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2.5 pr-10 font-mono text-sm text-emerald-300 outline-none placeholder:text-neutral-700 focus:border-emerald-500"
          />
          <button
            onClick={() => setShow(!show)}
            className="absolute right-2.5 top-2.5 text-neutral-500 hover:text-neutral-300"
          >
            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>

        {error && <p className="mt-3 text-xs text-red-400">{error}</p>}

        <button
          onClick={submit}
          disabled={login.isPending}
          className="mt-6 w-full rounded-lg bg-emerald-600 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:opacity-50"
        >
          {login.isPending ? "Verifying…" : "Enter Vault"}
        </button>

        <p className="mt-6 text-center text-[11px] leading-relaxed text-neutral-600">
          No accounts. No names. No passwords.
          <br />
          Your key is hashed in the browser — it never leaves this device.
        </p>
      </div>
    </div>
  );
}
