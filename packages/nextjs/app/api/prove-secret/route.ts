import { NextResponse } from "next/server";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export const runtime = "nodejs";

function normalizeSecret(input: string | ArrayBuffer | Uint8Array): Buffer {
  if (typeof input === "string") {
    // try hex, then base64, else utf8
    const hex = input.trim().toLowerCase();
    if (/^(0x)?[0-9a-f]+$/.test(hex)) {
      const h = hex.startsWith("0x") ? hex.slice(2) : hex;
      return Buffer.from(h, "hex");
    }
    try {
      return Buffer.from(input, "base64");
    } catch {}
    return Buffer.from(input, "utf8");
  }
  if (input instanceof Uint8Array) return Buffer.from(input);
  return Buffer.from(input);
}

function pad64(buf: Buffer): Buffer {
  if (buf.length === 64) return buf;
  if (buf.length > 64) return buf.subarray(0, 64);
  const out = Buffer.alloc(64);
  buf.copy(out, 0);
  return out;
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    // Enforce ZK by default; allow disabling only if ENFORCE_ZK explicitly set to "false"
    const enforce = process.env.ENFORCE_ZK !== "false";
    if (enforce) {
      const proof = body?.proof;
      const publicSignals = body?.publicSignals;
      if (!proof || !publicSignals) {
        return NextResponse.json({ error: "ENFORCE_ZK=true: provide {proof, publicSignals}" }, { status: 400 });
      }
      // Load verification key
      // Default VK path is relative to the Next.js package working directory
      let vkPath = process.env.ZK_VK_PATH || path.join(process.cwd(), "services/zk/verification_key.json");
      let vkey;
      try {
        const raw = await fs.readFile(vkPath, "utf8");
        vkey = JSON.parse(raw);
      } catch {
        // Fallback: try monorepo zk build output if available
        const alt = path.join(process.cwd(), "..", "zk", "build", "verification_key.json");
        try {
          const raw = await fs.readFile(alt, "utf8");
          vkey = JSON.parse(raw);
          vkPath = alt;
        } catch {
          return NextResponse.json({ error: `verification key not found at ${vkPath}` }, { status: 500 });
        }
      }
      // Import snarkjs and verify
      // Note: snarkjs is CJS; dynamic import returns the module namespace
      const snark: any = await import("snarkjs");
      const ok = await snark.groth16.verify(vkey, publicSignals, proof);
      if (!ok) return NextResponse.json({ error: "invalid ZK proof" }, { status: 400 });
      // Try to derive hHex from two public signals [h_hi, h_lo] (big-endian halves)
      let hHex = body?.hHex as string | undefined;
      if (!hHex && Array.isArray(publicSignals) && publicSignals.length >= 2) {
        try {
          const hi = BigInt(publicSignals[0]).toString(16);
          const lo = BigInt(publicSignals[1]).toString(16);
          const hiP = hi.padStart(32, "0"); // 128 bits = 16 bytes = 32 hex chars
          const loP = lo.padStart(32, "0");
          hHex = "0x" + hiP + loP;
        } catch {}
      }
      return NextResponse.json({ ok: true, hHex, verified: true });
    } else {
      const secret = body?.secret ?? crypto.randomBytes(32).toString("hex");
      const b = normalizeSecret(secret);
      const L = pad64(b);
      const H = crypto.createHash("sha256").update(L).digest("hex");
      return NextResponse.json({ hHex: "0x" + H, secretProvided: !!body?.secret });
    }
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || String(e) }, { status: 500 });
  }
}
