import crypto from "node:crypto";
import dns from "node:dns/promises";

export type VerifyResult = {
  ok: boolean;
  domain?: string;
  subject?: string;
  signedHeaders?: string[];
  reason?: string;
};

/**
 * DKIM verification (headers-only, RSA-SHA256) with DNS TXT lookup.
 * We verify the header signature over the signed header list (h=) and DKIM-Signature (with b= empty).
 * This does not recompute body hash (bh) but ensures the header signature covers bh, protecting it from tampering.
 */
export async function verifyHeadersOnly(headersText: string): Promise<VerifyResult> {
  try {
    const raw = headersText.trim().replace(/\r?\n[ \t]+/g, m => m); // keep folding for parsing
    const headers = parseHeaders(raw);
    const dkim = parseDkimSignature(headers.rawDkim);
    if (!dkim) return { ok: false, reason: "no dkim-signature header" };
    if (dkim.a.toLowerCase() !== "rsa-sha256") return { ok: false, reason: `unsupported a=${dkim.a}` };
    const subject = getHeaderValue(headers.list, "subject") || undefined;

    // Build canonicalized header block per relaxed header canonicalization
    const selected = selectSignedHeaders(headers.list, dkim.h);
    const canon = selected.map(relaxedHeader).join("\r\n");
    const dkimHeaderCanon = relaxedHeader(withEmptyB(headers.rawDkim));
    const signedData = canon + "\r\n" + dkimHeaderCanon;

    // Fetch DNS key: s._domainkey.d
    const keyName = `${dkim.s}._domainkey.${dkim.d}`;
    const pubKey = await fetchDkimPublicKey(dkim.s, dkim.d);
    if (!pubKey) return { ok: false, reason: `dkim public key not found for ${keyName}` };

    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(signedData);
    verifier.end();
    const sigOk = verifier.verify(pubKey, Buffer.from(dkim.b, "base64"));
    if (!sigOk) return { ok: false, reason: "dkim signature invalid" };

    return { ok: true, domain: dkim.d, subject, signedHeaders: dkim.h };
  } catch (e: any) {
    return { ok: false, reason: e?.message || String(e) };
  }
}

/**
 * Library-based DKIM verification using the full raw email (headers + body).
 * Requires a DKIM TXT with p= to be published for s._domainkey.d.
 */
export async function verifyRawEmailWithLibrary(rawEmail: string): Promise<VerifyResult> {
  try {
    // Prefer the stable verify function from mailauth
    const mod: any = await import("mailauth/lib/dkim/verify");
    const { dkimVerify } = mod || {};
    if (!dkimVerify) return { ok: false, reason: "dkim library not available" };
    const out: any = await dkimVerify(rawEmail, {});
    const results: any[] = Array.isArray(out?.results) ? out.results : [];
    const pass = results.find(r => r?.status?.result === "pass") || results[0];
    if (!pass) return { ok: false, reason: "no dkim signatures found" };
    const d = pass?.signingDomain;
    const s = pass?.selector;
    if (!d || !s) return { ok: false, reason: "dkim signature missing selector/domain" };
    // Parse subject from headers portion for later nonce checks
    const idx = rawEmail.search(/\r?\n\r?\n/);
    const headersText = idx >= 0 ? rawEmail.slice(0, idx) : rawEmail;
    const headers = parseHeaders(headersText);
    const subject = getHeaderValue(headers.list, "subject") || undefined;
    // Prefer library-provided signed headers; if missing, derive from matching DKIM-Signature h=
    let signedHeaders: string[] | undefined = Array.isArray(pass?.signingHeaders?.keys)
      ? pass.signingHeaders.keys
      : undefined;
    if (!signedHeaders || signedHeaders.length === 0) {
      // find the DKIM-Signature matching the passing signature (selector/domain and signature value)
      const hdrs = parseHeaders(headersText);
      const passSig = (pass?.signature || "").replace(/\s+/g, "");
      const matching = hdrs.rawDkim ? [hdrs.rawDkim] : [];
      // if parseHeaders only returned one, that's fine; else scan all DKIM-Signature lines
      if (!matching.length) {
        const allBlocks = headersText.split(/\r?\n(?=\S)/).filter(b => /^dkim-signature:/i.test(b));
        matching.push(...allBlocks);
      }
      for (const block of matching) {
        const parsed = parseDkimSignature(block);
        if (!parsed) continue;
        if (parsed.d?.toLowerCase() === String(d).toLowerCase() && parsed.s === String(s)) {
          if (!passSig || passSig === parsed.b) {
            signedHeaders = parsed.h;
            break;
          }
        }
      }
    }
    if (signedHeaders) signedHeaders = signedHeaders.map(h => h.toLowerCase());
    return { ok: true, domain: String(d), subject, signedHeaders };
  } catch (e: any) {
    return { ok: false, reason: e?.message || String(e) };
  }
}

function getHeaderValue(list: Array<{ name: string; value: string }>, name: string): string | null {
  const n = name.toLowerCase();
  for (let i = list.length - 1; i >= 0; i--) {
    if (list[i].name.toLowerCase() === n) return list[i].value;
  }
  return null;
}

function parseHeaders(raw: string) {
  const lines = raw.split(/\r?\n/);
  const list: Array<{ name: string; value: string }> = [];
  let current: { name: string; value: string } | null = null;
  const rawBlocks: string[] = [];
  let block = "";
  for (const line of lines) {
    if (/^[ \t]/.test(line)) {
      // continuation
      if (current) current.value += line.trim();
      block += "\r\n" + line;
    } else if (line.trim() === "") {
      // end of headers
      break;
    } else {
      if (current) rawBlocks.push(block);
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      current = { name: line.slice(0, idx), value: line.slice(idx + 1).trim() };
      list.push(current);
      block = line;
    }
  }
  if (block) rawBlocks.push(block);
  const rawDkim = rawBlocks.find(b => /^dkim-signature:/i.test(b)) || "";
  return { list, rawDkim };
}

type DkimSig = { a: string; d: string; s: string; h: string[]; b: string; c: string };
function parseDkimSignature(raw: string): DkimSig | null {
  if (!raw) return null;
  const lower = raw.toLowerCase();
  if (!lower.startsWith("dkim-signature:")) return null;
  const paramsStr = raw.slice(raw.indexOf(":") + 1);
  const tags = Object.fromEntries(
    paramsStr
      .split(";")
      .map(p => p.trim())
      .filter(Boolean)
      .map(kv => {
        const idx = kv.indexOf("=");
        if (idx === -1) return [kv.toLowerCase(), ""];
        const k = kv.slice(0, idx).trim().toLowerCase();
        const v = kv.slice(idx + 1).trim();
        return [k, v];
      }),
  );
  const a = tags["a"] || "rsa-sha256";
  const d = tags["d"];
  const s = tags["s"];
  const h = (tags["h"] || "")
    .split(":")
    .map((x: string) => x.trim().toLowerCase())
    .filter(Boolean);
  const b = (tags["b"] || "").replace(/\s+/g, "");
  const c = tags["c"] || "relaxed/relaxed";
  if (!d || !s || !h.length || !b) return null;
  return { a, d, s, h, b, c };
}

function relaxedHeader(h: { name: string; value: string } | string): string {
  if (typeof h === "string") {
    // assume already "name: value"
    const idx = h.indexOf(":");
    const name = h.slice(0, idx).toLowerCase();
    const value = h
      .slice(idx + 1)
      .replace(/[ \t]+/g, " ")
      .trim();
    return `${name}:${value}`;
  }
  const name = h.name.toLowerCase();
  const value = h.value.replace(/[ \t]+/g, " ").trim();
  return `${name}:${value}`;
}

function selectSignedHeaders(list: Array<{ name: string; value: string }>, hList: string[]) {
  // For each header name in h=, select the last unused occurrence from the message headers
  const indicesByName = new Map<string, number[]>();
  list.forEach((hdr, i) => {
    const n = hdr.name.toLowerCase();
    if (!indicesByName.has(n)) indicesByName.set(n, []);
    indicesByName.get(n)!.push(i);
  });
  // Pointers at last index for each name
  const ptr = new Map<string, number>();
  for (const [n, arr] of indicesByName) ptr.set(n, arr.length - 1);
  const selected: Array<{ name: string; value: string }> = [];
  for (const nRaw of hList) {
    const n = nRaw.toLowerCase();
    const arr = indicesByName.get(n);
    if (!arr || arr.length === 0) continue;
    const p = ptr.get(n)!;
    if (p < 0) continue;
    const idx = arr[p];
    ptr.set(n, p - 1);
    selected.push(list[idx]);
  }
  return selected;
}

function withEmptyB(rawDkim: string): { name: string; value: string } | string {
  // Replace b= value with empty per RFC when building the signed DKIM-Signature header
  const idx = rawDkim.toLowerCase().indexOf("dkim-signature:");
  if (idx !== 0) return rawDkim;
  let headerValue = rawDkim.slice(rawDkim.indexOf(":") + 1);
  // Unfold whitespace for manipulation
  headerValue = headerValue.replace(/\r?\n[ \t]+/g, " ");
  headerValue = headerValue.replace(/\bb=([^;]+)(;?)/i, "b=$2");
  return { name: "dkim-signature", value: headerValue.trim() };
}

async function fetchDkimPublicKey(selector: string, domain: string): Promise<string | null> {
  const name = `${selector}._domainkey.${domain}`;
  try {
    const records = await dns.resolveTxt(name);
    const flat = records.map(parts => parts.join("")).join("");
    const m = flat.match(/\bp=([^;\s]+)/);
    if (!m) return null;
    const p = m[1];
    const pem = wrapPem(p);
    return pem;
  } catch {
    return null;
  }
}

function wrapPem(base64: string): string {
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
