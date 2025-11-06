import fs from "node:fs/promises";
import path from "node:path";

let cachedVkey: any | null = null;
let cachedPath: string | null = null;

async function tryReadJSON(p: string) {
  const raw = await fs.readFile(p, "utf8");
  return JSON.parse(raw);
}

export async function getVerificationKey(): Promise<{ vkey: any; path: string }> {
  // If cache exists and points to zk/build path, use it; otherwise resolve fresh
  if (cachedVkey && cachedPath && cachedPath.includes(`${process.cwd()}/..`)) {
    return { vkey: cachedVkey, path: cachedPath };
  }
  // Prefer env override
  const envPath = process.env.ZK_VK_PATH;
  const candidates = [
    ...(envPath ? [envPath] : []),
    // Prefer the build output vkey that matches the zkey used for proving
    path.join(process.cwd(), "..", "zk", "build", "verification_key.json"),
    // Fallback to a checked-in copy if present
    path.join(process.cwd(), "services/zk/verification_key.json"),
  ];
  for (const p of candidates) {
    try {
      const v = await tryReadJSON(p);
      cachedVkey = v;
      cachedPath = p;
      return { vkey: v, path: p };
    } catch {}
  }
  const last = candidates[candidates.length - 1];
  throw new Error(`verification key not found at ${last}`);
}
