"use client";

import { useRef, useState } from "react";

const PBKDF2_ITERS = Number(process.env.NEXT_PUBLIC_PBKDF2_ITERS || "200000");
const POST_TIMEOUT_MS = Number(process.env.NEXT_PUBLIC_POST_TIMEOUT_MS || "25000");

export default function LoginZKPage() {
  const [domain, setDomain] = useState("");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [loading, setLoading] = useState(false);
  const [timing, setTiming] = useState<{ pbkdf2Ms?: number; proveMs?: number; postMs?: number; totalMs?: number }>();
  const [elapsedSec, setElapsedSec] = useState(0);
  const startedAtRef = useRef<number | null>(null);
  const intervalRef = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  async function limbProofFromPassphrase(passphrase: string, domain: string) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
    const salt = enc.encode(domain.toLowerCase());
    const t0 = performance.now();
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERS },
      key,
      512,
    );
    const secret = new Uint8Array(bits); // 64 bytes
    // Build public limbs
    const digestBuf = await crypto.subtle.digest("SHA-256", secret as unknown as BufferSource);
    const digest = new Uint8Array(digestBuf);
    function limb128ToBigInt(bytes: Uint8Array) {
      let x = 0n;
      for (const b of bytes) {
        x = (x << 8n) + BigInt(b);
      }
      return x;
    }
    const hi = limb128ToBigInt(digest.slice(0, 16));
    const lo = limb128ToBigInt(digest.slice(16, 32));
    const input = { in: Array.from(secret), h_hi: hi.toString(), h_lo: lo.toString() } as any;
    const hHex = "0x" + hi.toString(16).padStart(32, "0") + lo.toString(16).padStart(32, "0");
    const wasm = "/api/zk-artifacts/commit64_sha256_js/commit64_sha256.wasm";
    const zkey = "/api/zk-artifacts/commit64_final.zkey";
    const snark: any = await import("snarkjs");
    const t1 = performance.now();
    const out = await snark.groth16.fullProve(input, wasm, zkey);
    const t2 = performance.now();
    setTiming({ pbkdf2Ms: t1 - t0, proveMs: t2 - t1 });
    return { ...out, hHex };
  }

  function startTimer() {
    startedAtRef.current = Date.now();
    setElapsedSec(0);
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    // Use window.setInterval to ensure number type in browser
    intervalRef.current = window.setInterval(() => {
      const s = startedAtRef.current ? Math.floor((Date.now() - startedAtRef.current) / 1000) : 0;
      setElapsedSec(s);
    }, 250);
  }

  function stopTimer() {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    startedAtRef.current = null;
  }

  async function login() {
    setError("");
    setLoading(true);
    setSessionId("");
    try {
      if (!domain || !pass) throw new Error("domain and passphrase required");
      startTimer();
      // Prepare abort controller and timeout for POST
      const controller = new AbortController();
      abortRef.current = controller;
      const postAbortTimer = window.setTimeout(() => controller.abort(), POST_TIMEOUT_MS);
      const { proof, publicSignals, hHex } = await limbProofFromPassphrase(pass, domain);
      const postStart = performance.now();
      const res = await fetch("/api/login-zk", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain, proof, publicSignals, hHex }),
        signal: controller.signal,
      });
      window.clearTimeout(postAbortTimer);
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "login failed");
      setTiming(t => ({
        ...t,
        postMs: performance.now() - postStart,
        totalMs: (t?.pbkdf2Ms || 0) + (t?.proveMs || 0) + (performance.now() - postStart),
      }));
      setSessionId(json.sessionId);
    } catch (e: any) {
      if (e?.name === "AbortError") {
        setError("Request aborted");
      } else {
        setError(e?.message || String(e));
      }
    } finally {
      stopTimer();
      abortRef.current = null;
      setLoading(false);
    }
  }

  return (
    <div className="container mx-auto max-w-md p-6 space-y-4">
      <h1 className="text-2xl font-semibold">ZK Login</h1>
      {error && <div className="alert alert-error">{error}</div>}
      <label className="block text-sm font-medium">Domain</label>
      <input
        className="input input-bordered w-full"
        placeholder="example.com"
        value={domain}
        onChange={e => setDomain(e.target.value)}
        disabled={loading}
      />
      <label className="block text-sm font-medium">Passphrase</label>
      <input
        className="input input-bordered w-full"
        type="password"
        placeholder="Your passphrase"
        value={pass}
        onChange={e => setPass(e.target.value)}
        disabled={loading}
      />
      <div className="flex items-center gap-2">
        <button className="btn btn-primary" onClick={login} disabled={loading || !domain || !pass}>
          {loading ? `Logging in… (${elapsedSec}s)` : "Login"}
        </button>
        {loading && (
          <button className="btn" onClick={() => abortRef.current?.abort()}>
            Cancel
          </button>
        )}
      </div>
      {timing && (
        <div className="text-xs text-neutral">
          <p>
            Timing — PBKDF2: {timing.pbkdf2Ms?.toFixed(0)}ms, Prove: {timing.proveMs?.toFixed(0)}ms, POST:{" "}
            {timing.postMs?.toFixed(0)}ms, Total: {timing.totalMs?.toFixed(0)}ms
          </p>
        </div>
      )}
      {sessionId && (
        <div className="alert border-4 border-base-content">
          <div>
            <h2 className="font-extrabold">Welcome</h2>
            <p className="text-sm">
              Session: <code>{sessionId}</code>
            </p>
          </div>
        </div>
      )}
      <div className="text-sm">
        <p>
          Need to verify first?{" "}
          <a className="link" href="/headers-verify-mint">
            Verify headers
          </a>
        </p>
      </div>
    </div>
  );
}
