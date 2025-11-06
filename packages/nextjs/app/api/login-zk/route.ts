import { NextResponse } from "next/server";
import { spawn } from "node:child_process";
import { createSession } from "~~/services/store/session";
import { hasZKUser } from "~~/services/store/zkUsers";
import { getVerificationKey } from "~~/services/zk/getVkey";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const t0 = Date.now();
    const body = await req.json();
    const domain = String(body?.domain || "").toLowerCase();
    const proof = body?.proof;
    const publicSignals = body?.publicSignals;
    const hHexFromBody = typeof body?.hHex === "string" ? String(body.hHex) : undefined;
    if (!domain || !proof || !publicSignals) {
      return NextResponse.json({ error: "domain, proof, publicSignals required" }, { status: 400 });
    }
    let vkPath: string;
    try {
      const got = await getVerificationKey();
      vkPath = got.path;
    } catch (e: any) {
      return NextResponse.json({ error: e?.message || String(e) }, { status: 500 });
    }
    // Verify in a child process to avoid runtime quirks
    const verifyResult = await new Promise<true | false | "timeout">(resolve => {
      const child = spawn(process.execPath, ["services/zk/verify_runner.js"], { cwd: process.cwd() });
      const timeout = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {}
        resolve("timeout");
      }, 30000);
      let out = "";
      let err = "";
      child.stdout.on("data", d => (out += d));
      child.stderr.on("data", d => (err += d));
      child.on("exit", () => {
        clearTimeout(timeout);
        try {
          const parsed = out ? JSON.parse(out) : null;
          resolve(parsed && parsed.ok === true ? true : false);
        } catch {
          resolve(false);
        }
      });
      const payload = JSON.stringify({ vkeyPath: vkPath, proof, publicSignals });
      child.stdin.write(payload);
      child.stdin.end();
    });
    if (verifyResult === "timeout") {
      return NextResponse.json({ error: "verification timeout", vkPath }, { status: 504 });
    }
    const ok = verifyResult as boolean;
    if (!ok) return NextResponse.json({ error: "invalid ZK proof" }, { status: 400 });
    // Reconstruct hHex from public signals [h_hi, h_lo] if available; else accept hHex in body as a fallback
    let hHex: string | undefined;
    if (
      Array.isArray(publicSignals) &&
      publicSignals.length >= 2 &&
      publicSignals[0] != null &&
      publicSignals[1] != null
    ) {
      const hi = BigInt(publicSignals[0]).toString(16).padStart(32, "0");
      const lo = BigInt(publicSignals[1]).toString(16).padStart(32, "0");
      hHex = "0x" + hi + lo;
    } else if (hHexFromBody && /^0x[0-9a-fA-F]{64}$/.test(hHexFromBody)) {
      hHex = hHexFromBody.toLowerCase();
    } else {
      return NextResponse.json({ error: "cannot derive hHex from publicSignals; provide hHex" }, { status: 400 });
    }
    if (!hasZKUser(domain, hHex)) {
      return NextResponse.json({ error: "no ZK registration for this domain/secret" }, { status: 403 });
    }
    const t1 = Date.now();
    const session = createSession(domain);
    const timings = { verifyMs: t1 - t0 };
    return NextResponse.json({ ok: true, sessionId: session.id, domain: session.domain, timings, vkPath });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || String(e) }, { status: 500 });
  }
}
