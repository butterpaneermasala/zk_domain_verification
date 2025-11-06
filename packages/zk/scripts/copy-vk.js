#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '..', 'build', 'verification_key.json');
const dest = path.join(__dirname, '..', '..', 'nextjs', 'services', 'zk', 'verification_key.json');

if (!fs.existsSync(src)) {
  console.error('Missing build/verification_key.json');
  process.exit(1);
}
fs.mkdirSync(path.dirname(dest), { recursive: true });
fs.copyFileSync(src, dest);
console.log('Copied verification key to nextjs/services/zk/verification_key.json');
