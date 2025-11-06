import { NextResponse } from "next/server";
import { createSession } from "../../../services/store/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const domain = String(body?.domain || "").trim();
    if (!domain) return NextResponse.json({ error: "domain required" }, { status: 400 });
    const session = createSession(domain);
    return NextResponse.json({ sessionId: session.id, nonce: session.nonce, domain: session.domain });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || String(e) }, { status: 500 });
  }
}
