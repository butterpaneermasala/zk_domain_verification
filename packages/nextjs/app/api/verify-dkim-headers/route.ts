import { NextResponse } from "next/server";
import { verifyHeadersOnly, verifyRawEmailWithLibrary } from "../../../services/server/dkim";
import { getSession } from "../../../services/store/session";
import { keccak256, toUtf8Bytes } from "ethers";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const sessionId = String(body?.sessionId || "");
    const headersText = String(body?.headersText || "");
    const rawEmail = String(body?.rawEmail || "");
    if (!sessionId) return NextResponse.json({ error: "sessionId required" }, { status: 400 });
    // If raw email provided, prefer library-based verification
    if (rawEmail) {
      const v = await verifyRawEmailWithLibrary(rawEmail);
      const session = await getSession(sessionId);
      if (!session) return NextResponse.json({ error: "session not found" }, { status: 404 });
      if (!v.ok || !v.domain) {
        return NextResponse.json({ ok: false, reason: v.reason || "dkim failed" }, { status: 400 });
      }
      const domain = v.domain.toLowerCase();
      if (domain !== session.domain) {
        return NextResponse.json({ ok: false, reason: "domain mismatch" }, { status: 400 });
      }
      const subject = (v.subject || "").toLowerCase();
      if (!subject.includes(session.nonce.toLowerCase())) {
        return NextResponse.json({ ok: false, reason: "nonce not found in subject" }, { status: 400 });
      }
      const signed = (v.signedHeaders || []).map(h => h.toLowerCase());
      if (!signed.includes("subject")) {
        return NextResponse.json({ ok: false, reason: "subject not signed by dkim" }, { status: 400 });
      }
      const domainHash = keccak256(toUtf8Bytes(domain));
      return NextResponse.json({ ok: true, domain, domainHash });
    }
    // Fallback: headers-only flow
    if (!headersText) return NextResponse.json({ error: "headersText or rawEmail required" }, { status: 400 });
    const session = await getSession(sessionId);
    if (!session) return NextResponse.json({ error: "session not found" }, { status: 404 });

    const v = await verifyHeadersOnly(headersText);
    if (!v.ok || !v.domain) {
      return NextResponse.json({ ok: false, reason: v.reason || "dkim failed" }, { status: 400 });
    }
    const domain = v.domain.toLowerCase();
    if (domain !== session.domain) {
      return NextResponse.json({ ok: false, reason: "domain mismatch" }, { status: 400 });
    }
    // ensure Subject contains nonce and Subject is in signed headers
    const subject = (v.subject || "").toLowerCase();
    if (!subject.includes(session.nonce.toLowerCase())) {
      return NextResponse.json({ ok: false, reason: "nonce not found in subject" }, { status: 400 });
    }
    const signed = (v.signedHeaders || []).map(h => h.toLowerCase());
    if (!signed.includes("subject")) {
      return NextResponse.json({ ok: false, reason: "subject not signed by dkim" }, { status: 400 });
    }

    const domainHash = keccak256(toUtf8Bytes(domain));
    return NextResponse.json({ ok: true, domain, domainHash });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || String(e) }, { status: 500 });
  }
}
