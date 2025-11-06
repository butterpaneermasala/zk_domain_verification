import { NextResponse } from "next/server";
import fs from "node:fs/promises";
import path from "node:path";

export const runtime = "nodejs";

// In app runtime, cwd is the Next.js package; zk build is one level up
async function existsDir(p: string): Promise<boolean> {
  try {
    const s = await fs.stat(p);
    return s.isDirectory();
  } catch {
    return false;
  }
}
async function resolveBaseDir(): Promise<string> {
  const envDir = process.env.ZK_ARTIFACTS_DIR;
  if (envDir && (await existsDir(envDir))) return envDir;
  const candidates = [
    path.join(process.cwd(), "..", "zk", "build"),
    path.join(process.cwd(), "packages", "zk", "build"),
  ];
  for (const c of candidates) if (await existsDir(c)) return c;
  return candidates[0];
}

export async function GET(_: Request, { params }: { params: Promise<{ name: string }> }) {
  try {
    const { name } = await params;
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) return new NextResponse("bad name", { status: 400 });
    const base = await resolveBaseDir();
    const filePath = path.join(base, name);
    const data = await fs.readFile(filePath);
    const ext = path.extname(name).toLowerCase();
    let type = "application/octet-stream";
    if (ext === ".wasm") type = "application/wasm";
    if (ext === ".json") type = "application/json";
    return new NextResponse(new Uint8Array(data).buffer, { status: 200, headers: { "content-type": type } });
  } catch {
    return new NextResponse("not found", { status: 404 });
  }
}

export async function HEAD(req: Request, ctx: { params: Promise<{ name: string }> }) {
  const res = await GET(req, ctx);
  return new Response(null, { status: (res as any).status || 200, headers: (res as any).headers });
}
