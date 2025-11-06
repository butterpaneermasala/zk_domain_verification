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
  const vkeyBuild = path.join(base, 'verification_key.json');
  const vkeyServices = path.join(__dirname, '..', 'services', 'zk', 'verification_key.json');
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
  const t1 = performance.now();
  console.log('proving took', (t1 - t0).toFixed(0), 'ms');

  async function verifyWith(vkeyPath, label) {
    if (!fs.existsSync(vkeyPath)) { console.log(label, 'missing at', vkeyPath); return; }
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
    const start = performance.now();
    const result = await Promise.race([
      snarkjs.groth16.verify(vkey, publicSignals, proof),
      new Promise(r => setTimeout(() => r('timeout'), 10000)),
    ]);
    const end = performance.now();
    console.log(label, '=>', result, 'in', (end - start).toFixed(0), 'ms');
  }

  await verifyWith(vkeyBuild, 'vkeyBuild');
  await verifyWith(vkeyServices, 'vkeyServices');
}

main().catch(e => { console.error(e); process.exit(1); });
