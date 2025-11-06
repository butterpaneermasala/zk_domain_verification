#!/usr/bin/env node
const fs = require('fs');
const snarkjs = require('snarkjs');

async function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => data += chunk);
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

(async function main(){
  const raw = await readStdin();
  let payload;
  try { payload = JSON.parse(raw); } catch (e) {
    console.error('invalid json');
    process.exit(2);
  }
  const { vkeyPath, proof, publicSignals } = payload || {};
  if (!vkeyPath || !proof || !publicSignals) {
    console.error('missing fields');
    process.exit(2);
  }
  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
  const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  process.stdout.write(JSON.stringify({ ok }));
  process.exit(ok ? 0 : 3);
})().catch(e => { console.error(String(e && e.message || e)); process.exit(1); });
