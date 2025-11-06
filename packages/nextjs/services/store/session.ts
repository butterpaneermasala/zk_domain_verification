import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export type Session = {
  id: string;
  domain: string;
  nonce: string;
  createdAt: number;
};

const SESSIONS = new Map<string, Session>();
const TTL_MS = 30 * 60 * 1000; // 30 minutes
const DATA_DIR = path.join(process.cwd(), ".data");
const DATA_FILE = path.join(DATA_DIR, "sessions.json");

async function ensureDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch {}
}

async function loadFromDisk() {
  try {
    const json = await fs.readFile(DATA_FILE, "utf8");
    const arr: Session[] = JSON.parse(json);
    const now = Date.now();
    for (const s of arr) {
      if (now - s.createdAt < TTL_MS) SESSIONS.set(s.id, s);
    }
  } catch {
    // ignore
  }
}

async function persistToDisk() {
  try {
    await ensureDir();
    const arr = Array.from(SESSIONS.values());
    await fs.writeFile(DATA_FILE, JSON.stringify(arr), "utf8");
  } catch {
    // ignore
  }
}

// Load once on module init
void loadFromDisk();

export function createSession(domain: string): Session {
  const id = crypto.randomUUID();
  const nonce = crypto.randomBytes(8).toString("hex");
  const s: Session = { id, domain: domain.toLowerCase(), nonce, createdAt: Date.now() };
  SESSIONS.set(id, s);
  // fire-and-forget persist
  void persistToDisk();
  return s;
}

export async function getSession(id: string): Promise<Session | undefined> {
  // prune expired occasionally
  const now = Date.now();
  for (const [k, s] of SESSIONS) {
    if (now - s.createdAt >= TTL_MS) SESSIONS.delete(k);
  }
  const found = SESSIONS.get(id);
  if (found) return found;
  // fall back to disk to bridge separate route bundles / workers
  await loadFromDisk();
  return SESSIONS.get(id);
}

export function deleteSession(id: string) {
  SESSIONS.delete(id);
  void persistToDisk();
}
