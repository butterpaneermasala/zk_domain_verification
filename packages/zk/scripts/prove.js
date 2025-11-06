#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

async function main() {
  const buildDir = path.join(__dirname, '..', 'build');
  const wasm = path.join(buildDir, 'commit64_sha256_js', 'commit64_sha256.wasm');
  const zkey = path.join(buildDir, 'commit64_final.zkey');
  const inputPath = path.join(buildDir, 'input.json');

  if (!fs.existsSync(inputPath)) {
    console.error('Missing build/input.json');
    process.exit(1);
  }
  const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  fs.writeFileSync(path.join(buildDir, 'proof.json'), JSON.stringify(proof, null, 2));
  fs.writeFileSync(path.join(buildDir, 'public.json'), JSON.stringify(publicSignals, null, 2));
  console.log('Proof and public signals written to build/proof.json and build/public.json');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
