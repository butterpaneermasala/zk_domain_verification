// Mint auth has been removed. This route is intentionally disabled.
import { NextResponse } from "next/server";

export const runtime = "nodejs";
export async function POST() {
  return NextResponse.json({ error: "minting disabled" }, { status: 404 });
}
