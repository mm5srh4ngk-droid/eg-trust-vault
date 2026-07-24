#!/usr/bin/env node
// score.mjs — vault-side scorer. Runs ONLY in GitHub Actions on the vault owner's servers.
//
// Inputs (env): ISSUE_BODY_FILE (path to untrusted issue body), TRUTH_SALT, TRUTH_VERDICTS_B64,
//               CHAIN_DIR (default ./chain).
// Output: appends a hash-chained checkpoint chain/NNNN.json + writes RESULT.md (verdict comment
//         body) + prints the verdict token. Fail-CLOSED: any parse/validation/consistency gap →
//         verdict INVALID, exit 0 with checkpoint recording the rejection (a refusal is also
//         chained history), or exit 1 on chain-integrity failure (never mint on a broken chain).
//
// The issue body is UNTRUSTED DATA: strict JSON extraction from one fenced block, no eval, no
// shell interpolation, byte-size capped, schema-validated with type() checks.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const sha256 = s => createHash('sha256').update(s).digest('hex');
const CHAIN = process.env.CHAIN_DIR || './chain';
const out = (name, s) => writeFileSync(name, s);

function fail(msg) { // unmintable situation — no checkpoint may be trusted
  out('RESULT.md', `## ❌ REFUSED — ${msg}\n\nNo checkpoint minted. The eval stays advisory. (Fail-closed.)`);
  console.log(`REFUSED: ${msg}`); process.exit(1);
}

// --- load + verify existing chain head (never append to a broken chain) ---
const files = readdirSync(CHAIN).filter(f => /^\d{4}\.json$/.test(f)).sort();
let prevHash, prevSeq;
if (files.length === 0) {
  if (!existsSync(join(CHAIN, 'GENESIS.json'))) fail('no genesis');
  const g = JSON.parse(readFileSync(join(CHAIN, 'GENESIS.json'), 'utf8'));
  prevHash = sha256(JSON.stringify({ ...g, self_hash: undefined })); prevSeq = 0;
  if (g.self_hash !== prevHash) fail('genesis integrity');
} else {
  const last = JSON.parse(readFileSync(join(CHAIN, files[files.length - 1]), 'utf8'));
  const { self_hash, ...body } = last;
  if (sha256(JSON.stringify(body)) !== self_hash) fail('chain head integrity');
  prevHash = self_hash; prevSeq = last.seq;
}

// --- secrets → commitment index (commit hash → {verdict, cls}); case names never leave here ---
const salt = process.env.TRUTH_SALT || '';
let truth;
try { truth = JSON.parse(Buffer.from(process.env.TRUTH_VERDICTS_B64 || '', 'base64').toString('utf8')); }
catch { fail('truth secret unparseable'); }
if (!Array.isArray(truth) || truth.length === 0 || !salt) fail('truth secret empty');
const index = new Map();
for (const t of truth) {
  if (typeof t.case !== 'string' || !['SHIP','FIX-FIRST','BLOCK'].includes(t.verdict) || !['good','bad'].includes(t.cls)) fail('truth entry malformed');
  index.set(sha256(`${salt}\n${t.case}\n${t.verdict}`), { verdict: t.verdict, cls: t.cls });
}

// --- untrusted round extraction (strict) ---
let raw = '';
try { raw = readFileSync(process.env.ISSUE_BODY_FILE, 'utf8'); } catch { /* fallthrough */ }
if (raw.length > 20000) raw = '';                       // size cap — oversized bodies are rejected
const m = raw.match(/```json\s*\n([\s\S]*?)\n```/);      // exactly one fenced json block
let round = null, reject = null;
if (!m) reject = 'no json block found in submission';
else {
  try { round = JSON.parse(m[1]); } catch { reject = 'submission JSON unparseable'; }
}
if (round && (typeof round.run_id !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(round.run_id))) reject = 'bad run_id';
if (round && (!Array.isArray(round.entries) || round.entries.length === 0 || round.entries.length > 50)) reject = 'bad entries';

// --- score (fail-closed taxonomy, mirrors the local scorer) ---
let counts = { caught: 0, match: 0, miss: 0, overblock: 0, invalid: 0 };
const results = [];
if (!reject) {
  for (const e of round.entries) {
    const commit = typeof e.commit === 'string' ? e.commit.toLowerCase() : '';
    const council = typeof e.council === 'string' ? e.council.toUpperCase().trim() : '';
    if (!/^[0-9a-f]{64}$/.test(commit) || !['SHIP','FIX-FIRST','BLOCK'].includes(council)) { counts.invalid++; results.push({ commit: commit.slice(0,12), r: 'INVALID-MALFORMED' }); continue; }
    const t = index.get(commit);
    if (!t) { counts.invalid++; results.push({ commit: commit.slice(0,12), r: 'INVALID-UNKNOWN-COMMIT' }); continue; }
    let r;
    if (t.cls === 'bad')  r = council === 'SHIP' ? (counts.miss++, 'DRIFT-MISS') : (counts.caught++, 'CAUGHT');
    else                  r = council === 'SHIP' ? (counts.match++, 'MATCH') : (counts.overblock++, 'DRIFT-OVERBLOCK');
    results.push({ commit: commit.slice(0,12), r });
  }
}
const verdict = reject ? 'INVALID' :
  counts.miss > 0 ? 'DRIFT' : counts.overblock > 0 ? 'OVERBLOCK' : counts.invalid > 0 ? 'INVALID' : 'PASS';

// --- mint the checkpoint (a rejection is ALSO chained — refusals are history too) ---
const cp = { seq: prevSeq + 1, prev: prevHash, ts: new Date().toISOString(),
  run_id: round?.run_id ?? '(rejected)', reject: reject ?? null, counts, results, verdict };
cp.self_hash = sha256(JSON.stringify(cp));
writeFileSync(join(CHAIN, String(cp.seq).padStart(4, '0') + '.json'), JSON.stringify(cp, null, 2));

out('RESULT.md', [`## Vault verdict: **${verdict}**`,
  reject ? `Rejected: ${reject}` : `run \`${cp.run_id}\` — caught ${counts.caught}, match ${counts.match}, miss ${counts.miss}, overblock ${counts.overblock}, invalid ${counts.invalid}`,
  counts.miss > 0 ? '⚠ **DRIFT-MISS: the council approved a known-bad case. THE ALARM.**' : '',
  `Checkpoint \`${String(cp.seq).padStart(4,'0')}\` · self \`${cp.self_hash.slice(0,16)}…\` · chained to \`${String(prevHash).slice(0,16)}…\``,
  `_Minted by GitHub Actions on the vault. No council machine can produce this._`].filter(Boolean).join('\n\n'));
console.log(verdict);
