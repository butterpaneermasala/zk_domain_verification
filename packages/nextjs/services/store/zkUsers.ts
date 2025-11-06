import fs from "node:fs/promises";
import path from "node:path";

export type ZKUserStore = Record<string, string[]>; // domain -> array of hHex commitments

const DATA_DIR = path.join(process.cwd(), ".data");
const FILE_PATH = path.join(DATA_DIR, "zk-users.json");

let MEM: ZKUserStore = {};

async function ensureDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch {}
}

export async function loadZKStore() {
  try {
    const raw = await fs.readFile(FILE_PATH, "utf8");
    MEM = JSON.parse(raw) as ZKUserStore;
  } catch {
    MEM = {};
  }
}

export async function saveZKStore() {
  try {
    await ensureDir();
    await fs.writeFile(FILE_PATH, JSON.stringify(MEM, null, 2), "utf8");
  } catch {}
}

void loadZKStore();

export function addZKUser(domain: string, hHex: string) {
  const d = domain.toLowerCase();
  const arr = MEM[d] || [];
  if (!arr.includes(hHex)) arr.push(hHex);
  MEM[d] = arr;
  void saveZKStore();
}

export function hasZKUser(domain: string, hHex: string): boolean {
  const d = domain.toLowerCase();
  const arr = MEM[d] || [];
  return arr.includes(hHex);
}

export function listZKUsers(domain: string): string[] {
  return MEM[domain.toLowerCase()] || [];
}
