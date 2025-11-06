import { NextResponse } from "next/server";
import fs from "node:fs/promises";
import path from "node:path";

export const runtime = "nodejs";

// Serve zk artifacts from the monorepo's packages/zk/build directory.
// Example URLs:
//   /api/zk-artifacts/commit64_sha256_js/commit64_sha256.wasm
//   /api/zk-artifacts/commit64_final.zkey

function contentTypeFor(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case ".wasm":
      return "application/wasm";
    case ".zkey":
      return "application/octet-stream";
    case ".json":
      return "application/json";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".txt":
      return "text/plain; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

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
  for (const c of candidates) {
    if (await existsDir(c)) return c;
  }
  // Fallback to first candidate even if missing; downstream will 404
  return candidates[0];
}

export async function GET(_req: Request, { params }: { params: Promise<{ path?: string[] }> }) {
  try {
    const { path: segs } = await params;
    const segments = segs || [];
    if (segments.length === 0) {
      return NextResponse.json({ error: "path required" }, { status: 400 });
    }
    const baseDir = await resolveBaseDir();
    const candidate = path.join(baseDir, ...segments);
    // Prevent path traversal
    const resolved = path.resolve(candidate);
    if (!resolved.startsWith(path.resolve(baseDir) + path.sep) && resolved !== path.resolve(baseDir)) {
      return NextResponse.json({ error: "forbidden" }, { status: 403 });
    }
    const stat = await fs.stat(resolved).catch(() => null);
    if (!stat || !stat.isFile()) {
      return NextResponse.json({ error: "not found" }, { status: 404 });
    }
    const buf = await fs.readFile(resolved);
    const headers = new Headers({
      "content-type": contentTypeFor(resolved),
      // Cache for a while in the browser; dev can be reloaded to invalidate
      "cache-control": "public, max-age=3600",
    });
    return new Response(new Uint8Array(buf), { status: 200, headers });
  } catch (e: any) {
    return NextResponse.json({ error: e?.message || String(e) }, { status: 500 });
  }
}

// Some browsers or middlewares may issue HEAD; respond same headers without body
export async function HEAD(req: Request, ctx: { params: Promise<{ path?: string[] }> }) {
  const res = await GET(req, ctx);
  // Strip body for HEAD
  return new Response(null, { status: (res as any).status || 200, headers: (res as any).headers });
}
