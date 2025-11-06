#!/usr/bin/env node
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const snarkjs = require('snarkjs');
const { performance } = require('perf_hooks');

async function deriveSecret(passphrase, domain) {
  const salt = Buffer.from(domain.toLowerCase(), 'utf8');
  return crypto.pbkdf2Sync(Buffer.from(passphrase, 'utf8'), salt, 200_000, 64, 'sha256');
}
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function be128ToBigInt(bytes) { return bytes.reduce((x, b) => (x << 8n) + BigInt(b), 0n); }

async function main() {
  const domain = process.argv[2] || process.env.DOMAIN || 'example.com';
  const passphrase = process.argv[3] || process.env.PASSPHRASE || 'correct-horse-battery-staple';
  const base = path.join(__dirname, '..', '..', 'zk', 'build');
  const wasm = path.join(base, 'commit64_sha256_js', 'commit64_sha256.wasm');
  const zkey = path.join(base, 'commit64_final.zkey');
  if (!fs.existsSync(wasm) || !fs.existsSync(zkey)) {
    console.error('Missing artifacts at', { wasm, zkey });
    process.exit(1);
  }
  const t0 = performance.now();
  const secret = await deriveSecret(passphrase, domain);
  const digest = sha256(secret);
  const hi = be128ToBigInt(digest.subarray(0, 16));
  const lo = be128ToBigInt(digest.subarray(16, 32));
  const input = { in: Array.from(secret), h_hi: hi.toString(), h_lo: lo.toString() };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  const hHex = '0x' + hi.toString(16).padStart(32, '0') + lo.toString(16).padStart(32, '0');
  const t1 = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Number(process.env.POST_TIMEOUT_MS || 15000));
  let res;
  try {
  res = await fetch('http://localhost:3000/api/login-zk', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ domain, proof, publicSignals, hHex }), signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
  const t2 = performance.now();
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  console.log('status', res.status, json);
  console.log('timings (ms): prove=', (t1-t0).toFixed(0), 'post=', (t2-t1).toFixed(0));
  if (!res.ok) process.exit(2);
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
