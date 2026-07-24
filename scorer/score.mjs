#!/usr/bin/env node
// score.mjs (v2) — vault-side scorer. Runs ONLY in GitHub Actions on the vault owner's servers.
// Fail-CLOSED throughout; a rejection is chained as INVALID (refusals are history); only a
// chain-integrity failure exits 1 (never mint on a broken chain).
//
// v2 hardening (per adversarial gate):
//  - STRICT parse: exactly ONE fenced json block; byte-capped; object-shape enforced; NO unknown
//    keys; entries must be plain objects; duplicate commitments rejected; null-safe (malformed
//    entries chain INVALID, never crash).
//  - ANTI-CHERRY-PICK POLICY: PASS additionally requires ≥MIN_BAD bad-class entries (default 1) —
//    a round of only easy/control cases can never mint PASS (verdict INSUFFICIENT).
//  - REPLAY REJECTION: run_id or payload hash already in the chain → INVALID-REPLAY.
//  - BINDING: checkpoint records submitter, issue, workflow run, repo SHA, payload sha256, and the
//    FULL entries — provable which submission was graded.
//  - VAULT MAC: hmac-sha256(TRUTH_SALT, checkpoint-body) — only the secret-holder's CI can mint a
//    valid MAC; forged look-alike checkpoints are detectable by the vault.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { createHash, createHmac } from 'node:crypto';
import { join } from 'node:path';

const sha256 = s => createHash('sha256').update(s).digest('hex');
const CHAIN = process.env.CHAIN_DIR || './chain';
const MIN_BAD = Number.isFinite(Number(process.env.MIN_BAD)) && Number(process.env.MIN_BAD) >= 0 ? Number(process.env.MIN_BAD) : 1;
const out = (n, s) => writeFileSync(n, s);
const CP_RE = /^\d{6}\.json$/;

function fail(msg) { // unmintable — chain untrustworthy
  out('RESULT.md', `## ❌ REFUSED — ${msg}\n\nNo checkpoint minted. The eval stays advisory. (Fail-closed.)`);
  console.log(`REFUSED: ${msg}`); process.exit(1);
}

// --- chain head (verify before any mint) + replay index ---
const files = readdirSync(CHAIN).filter(f => CP_RE.test(f)).sort();
let prevHash, prevSeq; const seenRuns = new Set(), seenPayloads = new Set();
if (files.length === 0) {
  if (!existsSync(join(CHAIN, 'GENESIS.json'))) fail('no genesis');
  const g = JSON.parse(readFileSync(join(CHAIN, 'GENESIS.json'), 'utf8'));
  prevHash = sha256(JSON.stringify({ ...g, self_hash: undefined })); prevSeq = 0;
  if (g.self_hash !== prevHash) fail('genesis integrity');
} else {
  for (const f of files) { const c = JSON.parse(readFileSync(join(CHAIN, f), 'utf8')); if (c.run_id) seenRuns.add(c.run_id); if (c.payload_sha256) seenPayloads.add(c.payload_sha256); }
  const last = JSON.parse(readFileSync(join(CHAIN, files[files.length - 1]), 'utf8'));
  const { self_hash, vault_mac, ...body } = last;
  if (sha256(JSON.stringify(body)) !== self_hash) fail('chain head integrity');
  prevHash = self_hash; prevSeq = last.seq;
}

// --- secrets → commitment index ---
const salt = process.env.TRUTH_SALT || '';
let truth;
try { truth = JSON.parse(Buffer.from(process.env.TRUTH_VERDICTS_B64 || '', 'base64').toString('utf8')); }
catch { fail('truth secret unparseable'); }
if (!Array.isArray(truth) || truth.length === 0 || !salt) fail('truth secret empty');
const index = new Map();
for (const t of truth) {
  if (typeof t?.case !== 'string' || !['SHIP','FIX-FIRST','BLOCK'].includes(t?.verdict) || !['good','bad'].includes(t?.cls)) fail('truth entry malformed');
  index.set(sha256(`${salt}\n${t.case}\n${t.verdict}`), { verdict: t.verdict, cls: t.cls });
}

// --- untrusted submission: STRICT extraction ---
let raw = '';
try { raw = readFileSync(process.env.ISSUE_BODY_FILE, 'utf8'); } catch { /* fallthrough */ }
let reject = null, round = null, payloadHash = null;
if (Buffer.byteLength(raw, 'utf8') > 20000) reject = 'submission exceeds 20KB';
const blocks = reject ? [] : [...raw.matchAll(/```json\s*\n([\s\S]*?)\n```/g)];
if (!reject && blocks.length !== 1) reject = `expected exactly one json block, found ${blocks.length}`;
if (!reject) {
  payloadHash = sha256(blocks[0][1]);
  try { round = JSON.parse(blocks[0][1]); } catch { reject = 'submission JSON unparseable'; }
}
if (!reject && (typeof round !== 'object' || round === null || Array.isArray(round))) reject = 'submission not an object';
if (!reject) {
  const keys = Object.keys(round).sort().join(',');
  if (keys !== 'entries,run_id') reject = `unknown/missing top-level keys (${keys})`;
}
if (!reject && (typeof round.run_id !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(round.run_id))) reject = 'bad run_id';
if (!reject && (!Array.isArray(round.entries) || round.entries.length === 0 || round.entries.length > 50)) reject = 'bad entries';
if (!reject && seenRuns.has(round.run_id)) reject = `INVALID-REPLAY: run_id already chained`;
if (!reject && seenPayloads.has(payloadHash)) reject = `INVALID-REPLAY: identical payload already chained`;

// --- score ---
let counts = { caught: 0, match: 0, miss: 0, overblock: 0, invalid: 0, bad_seen: 0 };
const results = []; const seenCommits = new Set();
if (!reject) {
  for (const e of round.entries) {
    if (typeof e !== 'object' || e === null || Array.isArray(e) || Object.keys(e).sort().join(',') !== 'commit,council') { counts.invalid++; results.push({ commit: '?', council: '?', r: 'INVALID-MALFORMED' }); continue; }
    const commit = typeof e.commit === 'string' ? e.commit.toLowerCase() : '';
    const council = typeof e.council === 'string' ? e.council.toUpperCase().trim() : '';
    if (!/^[0-9a-f]{64}$/.test(commit) || !['SHIP','FIX-FIRST','BLOCK'].includes(council)) { counts.invalid++; results.push({ commit: commit || '?', council, r: 'INVALID-MALFORMED' }); continue; }
    if (seenCommits.has(commit)) { counts.invalid++; results.push({ commit, council, r: 'INVALID-DUPLICATE' }); continue; }
    seenCommits.add(commit);
    const t = index.get(commit);
    if (!t) { counts.invalid++; results.push({ commit, council, r: 'INVALID-UNKNOWN-COMMIT' }); continue; }
    let r;
    if (t.cls === 'bad') { counts.bad_seen++; r = council === 'SHIP' ? (counts.miss++, 'DRIFT-MISS') : (counts.caught++, 'CAUGHT'); }
    else                 { r = council === 'SHIP' ? (counts.match++, 'MATCH') : (counts.overblock++, 'DRIFT-OVERBLOCK'); }
    results.push({ commit, council, r });
  }
}
const verdict = reject ? 'INVALID' :
  counts.miss > 0 ? 'DRIFT' : counts.overblock > 0 ? 'OVERBLOCK' : counts.invalid > 0 ? 'INVALID' :
  counts.bad_seen < MIN_BAD ? 'INSUFFICIENT' : 'PASS';

// --- mint (bound + MAC'd; rejections are also chained) ---
const cp = { seq: prevSeq + 1, prev: prevHash, ts: new Date().toISOString(),
  run_id: round?.run_id ?? '(rejected)', reject: reject ?? null,
  submitter: process.env.SUBMITTER || '(unknown)', issue: process.env.ISSUE_NUMBER || null,
  workflow_run: process.env.WF_RUN_ID || null, repo_sha: process.env.REPO_SHA || null,
  payload_sha256: payloadHash, min_bad_policy: MIN_BAD, counts, results, verdict };
cp.self_hash = sha256(JSON.stringify(cp));
cp.vault_mac = createHmac('sha256', salt).update(cp.self_hash).digest('hex');
writeFileSync(join(CHAIN, String(cp.seq).padStart(6, '0') + '.json'), JSON.stringify(cp, null, 2));

out('RESULT.md', [`## Vault verdict: **${verdict}**`,
  reject ? `Rejected: ${reject}` : `run \`${cp.run_id}\` — caught ${counts.caught}, match ${counts.match}, miss ${counts.miss}, overblock ${counts.overblock}, invalid ${counts.invalid}, bad-cases ${counts.bad_seen}/${MIN_BAD} required`,
  counts.miss > 0 ? '⚠ **DRIFT-MISS: the council approved a known-bad case. THE ALARM.**' : '',
  verdict === 'INSUFFICIENT' ? `⚠ Round contained fewer than ${MIN_BAD} known-bad case(s) — a PASS cannot be minted from easy/control cases only. Resample.` : '',
  `Checkpoint \`${String(cp.seq).padStart(6,'0')}\` · submitter \`${cp.submitter}\` · issue \`${cp.issue}\` · payload \`${String(payloadHash||'').slice(0,16)}…\``,
  `_Minted by GitHub Actions on the vault (MAC'd with the vault secret). No council machine can produce this._`].filter(Boolean).join('\n\n'));
console.log(verdict);
