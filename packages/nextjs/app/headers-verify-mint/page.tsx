"use client";

import { useMemo, useState } from "react";

const PBKDF2_ITERS = Number(process.env.NEXT_PUBLIC_PBKDF2_ITERS || "200000");

export default function Page() {
  const [domain, setDomain] = useState("");
  const [session, setSession] = useState<{ id: string; nonce: string } | null>(null);
  const [headers, setHeaders] = useState("");
  const [isRawEmail, setIsRawEmail] = useState<boolean>(true);
  const [domainHash, setDomainHash] = useState<string>("");
  const [hHex, setHHex] = useState<string>("");
  const [zkRegistered, setZkRegistered] = useState<boolean>(false);
  const [timing, setTiming] = useState<{
    pbkdf2Ms?: number;
    proveMs?: number;
    postMs?: number;
    totalMs?: number;
    server?: { readVkMs: number; verifyMs: number; storeMs: number; totalMs: number };
  }>();
  const [postAbort, setPostAbort] = useState<AbortController | null>(null);
  const [elapsedMs, setElapsedMs] = useState<number>(0);
  const [tick, setTick] = useState<number | null>(null);
  const [error, setError] = useState<string>("");
  const [loading, setLoading] = useState<{
    session?: boolean;
    verify?: boolean;
    prove?: boolean;
    auth?: boolean;
    mint?: boolean;
  }>({});
  const accessGranted = !!domainHash && zkRegistered; // require ZK registration

  const step = useMemo(() => {
    if (!session) return 1;
    if (!domainHash) return 2;
    if (!zkRegistered) return 3;
    return 3;
  }, [session, domainHash, zkRegistered]);

  // Helpers
  // Derive secret from passphrase and register ZK login (mandatory)
  function startTimer() {
    try {
      if (tick) clearInterval(tick as any);
    } catch {}
    setElapsedMs(0);
    const start = performance.now();
    const id = window.setInterval(() => {
      setElapsedMs(performance.now() - start);
    }, 200);
    setTick(id);
  }
  function stopTimer() {
    try {
      if (tick) clearInterval(tick as any);
    } catch {}
    setTick(null);
  }

  async function createZKLogin(passphrase: string) {
    if (!domain) throw new Error("domain required");
    startTimer();
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
    // Build public limbs for h = SHA-256(secret)
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
    const wasm = "/api/zk-artifacts/commit64_sha256_js/commit64_sha256.wasm";
    const zkey = "/api/zk-artifacts/commit64_final.zkey";
    const snark: any = await import("snarkjs");
    const t1 = performance.now();
    const { proof, publicSignals } = await snark.groth16.fullProve(input, wasm, zkey);
    const t2 = performance.now();
    // Register on server
    // Set hHex immediately for UX; will mark Registered after server confirms
    const hiHex = BigInt(publicSignals?.[0] ?? hi)
      .toString(16)
      .padStart(32, "0");
    const loHex = BigInt(publicSignals?.[1] ?? lo)
      .toString(16)
      .padStart(32, "0");
    const hLocal = "0x" + hiHex + loHex;
    setHHex(hLocal);
    const postStart = performance.now();
    // Abort POST if it hangs too long
    const ctrl = new AbortController();
    setPostAbort(ctrl);
    const timeoutMs = Number(process.env.NEXT_PUBLIC_POST_TIMEOUT_MS || "20000");
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch("/api/register-zk", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain, proof, publicSignals, hHex: hLocal }),
        signal: ctrl.signal,
      });
    } catch (e: any) {
      if (e?.name === "AbortError") {
        stopTimer();
        setPostAbort(null);
        throw new Error(`Request aborted (timeout ${Math.floor(timeoutMs / 1000)}s)`);
      }
      throw e;
    } finally {
      clearTimeout(timer);
      setPostAbort(null);
    }
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || "register failed");
    const postEnd = performance.now();
    setTiming({
      pbkdf2Ms: t1 - t0,
      proveMs: t2 - t1,
      postMs: postEnd - postStart,
      totalMs: postEnd - t0,
      server: json?.timings,
    });
    // Confirmed
    setZkRegistered(true);
    stopTimer();
  }

  async function startSession() {
    setError("");
    setLoading(l => ({ ...l, session: true }));
    try {
      const res = await fetch("/api/session", {
        method: "POST",
        body: JSON.stringify({ domain }),
        headers: { "content-type": "application/json" },
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "session failed");
      setSession({ id: json.sessionId, nonce: json.nonce });
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(l => ({ ...l, session: false }));
    }
  }

  async function verifyHeaders() {
    if (!session) return;
    setError("");
    setLoading(l => ({ ...l, verify: true }));
    try {
      // Auto-detect raw email if textarea contains a blank line separating headers/body
      const looksRaw = /\r?\n\r?\n/.test(headers);
      const payload: any = { sessionId: session.id };
      if (looksRaw || isRawEmail) payload.rawEmail = headers;
      else payload.headersText = headers;
      const res = await fetch("/api/verify-dkim-headers", {
        method: "POST",
        body: JSON.stringify(payload),
        headers: { "content-type": "application/json" },
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || json.reason || "verify failed");
      setDomainHash(json.domainHash);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(l => ({ ...l, verify: false }));
    }
  }

  // Manual proof submit (advanced): directly register
  async function submitProof(proofText: string, publicSignalsText: string) {
    setError("");
    setLoading(l => ({ ...l, prove: true }));
    try {
      const proof = JSON.parse(proofText);
      const publicSignals = JSON.parse(publicSignalsText);
      const res = await fetch("/api/register-zk", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain, proof, publicSignals }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "register failed");
      const hiHex = BigInt(publicSignals[0]).toString(16).padStart(32, "0");
      const loHex = BigInt(publicSignals[1]).toString(16).padStart(32, "0");
      setHHex("0x" + hiHex + loHex);
      setZkRegistered(true);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setLoading(l => ({ ...l, prove: false }));
    }
  }

  // Minting and wallet flows removed

  return (
    <div className="container mx-auto max-w-3xl p-6 space-y-6">
      <h1 className="text-2xl font-semibold">Verify your email domain</h1>
      <p className="text-sm text-neutral">Headers-only DKIM with a mandatory ZK commitment. No wallet required.</p>

      {/* Stepper */}
      <ol className="flex items-center w-full text-sm">
        {["Session", "Headers", "ZK"].map((label, i) => {
          const n = i + 1;
          const active = step === n;
          const done = step > n;
          return (
            <li
              key={n}
              className={`flex-1 flex items-center gap-2 ${done ? "text-success" : active ? "text-primary" : "text-base-content/60"}`}
            >
              <span className={`badge ${done ? "badge-success" : active ? "badge-primary" : ""}`}>{n}</span>
              <span>{label}</span>
              {i < 2 && <span className="flex-1 border-t border-base-300 mx-2" />}
            </li>
          );
        })}
      </ol>

      {error && (
        <div className="alert alert-error">
          <span>{error}</span>
        </div>
      )}
      {accessGranted && session && (
        <div className="alert border-4 border-base-content">
          <div>
            <h2 className="font-extrabold">Access granted</h2>
            <p className="text-sm">
              Session: <code>{session.id}</code>
            </p>
            <p className="text-sm">ZK login registered for this domain.</p>
          </div>
        </div>
      )}
      <section className="space-y-3">
        <label className="block text-sm font-medium">Domain</label>
        <input
          className="input input-bordered w-full"
          placeholder="example.com"
          value={domain}
          onChange={e => setDomain(e.target.value)}
        />
        <button className="btn btn-primary" onClick={startSession} disabled={!domain || loading.session}>
          {" "}
          {loading.session ? "Starting…" : "Start session"}{" "}
        </button>
        {session && (
          <p className="text-sm">
            Nonce: <code>{session.nonce}</code>
            <button className="btn btn-xs ml-2" onClick={() => navigator.clipboard.writeText(session.nonce)}>
              Copy
            </button>
            — Send an email to yourself with this in the Subject and paste delivered headers below.
          </p>
        )}
      </section>

      <section className="space-y-3">
        <label className="block text-sm font-medium">Delivered headers</label>
        <textarea
          className="textarea textarea-bordered w-full h-40"
          placeholder="Paste full raw email or just the headers"
          value={headers}
          onChange={e => setHeaders(e.target.value)}
        />
        <div className="flex gap-2">
          <button className="btn" onClick={() => navigator.clipboard.readText().then(t => setHeaders(t))}>
            Paste from clipboard
          </button>
          <label className="label cursor-pointer flex items-center gap-2">
            <input
              type="checkbox"
              className="checkbox checkbox-sm"
              checked={isRawEmail}
              onChange={e => setIsRawEmail(e.target.checked)}
            />
            <span className="label-text">Input is raw email</span>
          </label>
          <button className="btn" onClick={verifyHeaders} disabled={!session || !headers || loading.verify}>
            {loading.verify ? "Verifying…" : "Verify DKIM"}
          </button>
        </div>
        {domainHash && <p className="text-xs break-all">domainHash: {domainHash}</p>}
      </section>

      {/* Mandatory ZK registration step */}
      {domainHash && (
        <section className="space-y-3">
          <label className="block text-sm font-medium">Create ZK login (mandatory)</label>
          <p className="text-sm text-neutral">
            Set a passphrase to enable future passwordless login without sending an email again.
          </p>
          <div className="flex gap-2">
            <input
              id="zkpass"
              type="password"
              className="input input-bordered w-full"
              placeholder="Enter a passphrase"
            />
            <button
              className="btn btn-primary"
              disabled={loading.prove || zkRegistered}
              onClick={async () => {
                setError("");
                setLoading(l => ({ ...l, prove: true }));
                try {
                  const el = document.getElementById("zkpass") as HTMLInputElement | null;
                  const pass = (el?.value || "").trim();
                  if (!pass) throw new Error("Passphrase required");
                  await createZKLogin(pass);
                } catch (e: any) {
                  setError(e?.message || String(e));
                } finally {
                  setLoading(l => ({ ...l, prove: false }));
                  try {
                    stopTimer();
                  } catch {}
                }
              }}
            >
              {zkRegistered ? "Registered" : "Create ZK login"}
            </button>
            {loading.prove && postAbort && (
              <button
                className="btn btn-outline"
                onClick={() => {
                  try {
                    postAbort.abort();
                  } catch {}
                }}
              >
                Cancel
              </button>
            )}
          </div>
          {hHex && <p className="text-xs break-all">H: {hHex}</p>}
          {loading.prove && !zkRegistered && (
            <p className="text-xs text-neutral">
              Registering… Elapsed: {(elapsedMs / 1000).toFixed(1)}s. If this takes too long, click Cancel and try
              again.
            </p>
          )}
          {timing && (
            <div className="text-xs text-neutral">
              <p>
                Timing — PBKDF2: {timing.pbkdf2Ms?.toFixed(0)}ms, Prove: {timing.proveMs?.toFixed(0)}ms, POST:{" "}
                {timing.postMs?.toFixed(0)}ms, Total: {timing.totalMs?.toFixed(0)}ms
              </p>
              {timing.server && (
                <p>
                  Server — readVK: {timing.server.readVkMs}ms, verify: {timing.server.verifyMs}ms, store:{" "}
                  {timing.server.storeMs}ms, total: {timing.server.totalMs}ms
                </p>
              )}
            </div>
          )}
          {zkRegistered && (
            <div className="flex gap-2">
              <button
                className="btn btn-outline btn-sm"
                onClick={async () => {
                  try {
                    const el = document.getElementById("zkpass") as HTMLInputElement | null;
                    const pass = (el?.value || "").trim();
                    if (!pass) throw new Error("Enter the same passphrase to test login");
                    // Reuse login-zk flow inline
                    const enc = new TextEncoder();
                    const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
                    const salt = enc.encode(domain.toLowerCase());
                    const bits = await crypto.subtle.deriveBits(
                      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERS },
                      key,
                      512,
                    );
                    const secret = new Uint8Array(bits);
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
                    const wasm = "/api/zk-artifacts/commit64_sha256_js/commit64_sha256.wasm";
                    const zkey = "/api/zk-artifacts/commit64_final.zkey";
                    const snark: any = await import("snarkjs");
                    const { proof, publicSignals } = await snark.groth16.fullProve(input, wasm, zkey);
                    const res = await fetch("/api/login-zk", {
                      method: "POST",
                      headers: { "content-type": "application/json" },
                      body: JSON.stringify({ domain, proof, publicSignals }),
                    });
                    const json = await res.json();
                    if (!res.ok) throw new Error(json.error || "login failed");
                    alert("Login proof verified. Session: " + json.sessionId);
                  } catch (e: any) {
                    alert(e?.message || String(e));
                  }
                }}
              >
                Test passphrase login
              </button>
            </div>
          )}
          <details>
            <summary className="link">Advanced: paste proof manually</summary>
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
              <textarea
                id="ps"
                className="textarea textarea-bordered min-h-40"
                placeholder='["h_hi","h_lo"]'
              ></textarea>
              <textarea
                id="pr"
                className="textarea textarea-bordered min-h-40"
                placeholder='{"pi_a":[...],"pi_b":[[...]...],"pi_c":[...]}'
              ></textarea>
            </div>
            <div className="flex gap-2 mt-2">
              <button
                className="btn"
                disabled={loading.prove || zkRegistered}
                onClick={() => {
                  const ps = (document.getElementById("ps") as HTMLTextAreaElement | null)?.value || "";
                  const pr = (document.getElementById("pr") as HTMLTextAreaElement | null)?.value || "";
                  submitProof(pr, ps);
                }}
              >
                {loading.prove ? "Registering…" : "Submit and register"}
              </button>
              <a className="link" href="/README-EMAIL.md" target="_blank" rel="noreferrer">
                How to generate a proof
              </a>
            </div>
          </details>
        </section>
      )}

      <section className="space-y-3">
        <div className="text-sm">
          <p>
            Already registered before?{" "}
            <a className="link" href="/login-zk">
              Log in with passphrase (ZK)
            </a>
          </p>
        </div>
      </section>
    </div>
  );
}
