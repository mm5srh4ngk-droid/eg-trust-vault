#!/usr/bin/env node
// verify-chain.mjs — proves checkpoint-chain integrity from any READ-ONLY clone.
// Checks: genesis integrity, seq continuity (no gaps/dupes), prev-hash linkage, self-hash of
// every checkpoint. Exit 0 = intact; exit 1 = broken (with the first break named).
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
const sha256 = s => createHash('sha256').update(s).digest('hex');
const CHAIN = process.argv[2] || './chain';

const g = JSON.parse(readFileSync(join(CHAIN, 'GENESIS.json'), 'utf8'));
const { self_hash: gh, ...gbody } = g;
if (sha256(JSON.stringify({ ...gbody, self_hash: undefined })) !== gh) { console.log('BROKEN: genesis'); process.exit(1); }
let prev = gh, seq = 0;

const files = readdirSync(CHAIN).filter(f => /^\d{6}\.json$/.test(f)).sort();
for (const f of files) {
  const cp = JSON.parse(readFileSync(join(CHAIN, f), 'utf8'));
  const { self_hash, vault_mac, ...body } = cp;
  if (cp.seq !== seq + 1)                { console.log(`BROKEN: seq gap at ${f} (got ${cp.seq}, want ${seq + 1})`); process.exit(1); }
  if (cp.prev !== prev)                  { console.log(`BROKEN: prev-hash mismatch at ${f}`); process.exit(1); }
  if (sha256(JSON.stringify(body)) !== self_hash) { console.log(`BROKEN: self-hash at ${f}`); process.exit(1); }
  prev = self_hash; seq = cp.seq;
}
console.log(`CHAIN INTACT — ${files.length} checkpoint(s), head seq ${seq}, head ${String(prev).slice(0, 16)}…`);
