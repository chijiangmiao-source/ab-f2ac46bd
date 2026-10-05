// Rule tests for the causal authorization log. Run: node tests/model.test.mjs
import assert from 'node:assert/strict';
import { makeSubjects, Builder, loadAndEvaluate } from './util.mjs';
import { loadSubjects, evaluateLog, ERROR, LIMITS } from '../core/model.js';
import { b64encode } from '../core/codec.js';
import { canonicalize, canonicalBytes } from '../core/canonical.js';
import * as ed from '@noble/ed25519';

let passed = 0;
const failures = [];
async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log('  ok -', name);
  } catch (e) {
    failures.push({ name, e });
    console.log('  FAIL -', name);
    console.log(String(e && e.stack ? e.stack : e).split('\n').map((l) => '      ' + l).join('\n'));
  }
}
function verdict(res, i) {
  return res.records[i].verdict;
}

// ---------------------------------------------------------------------------
console.log('canonical JSON:');
await test('keys are sorted and JSON survives reordering', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(canonicalize({ signature: 'x', a: [1, { z: 0, y: 0 }] }), '{"a":[1,{"y":0,"z":0}],"signature":"x"}');
  assert.equal(canonicalize({ q: 'é"\n' }), '{"q":"é\\\"\\n"}');
});

// ---------------------------------------------------------------------------
console.log('healthy authorization:');
await test('root delegation, chained grant and unlock all authorized', async () => {
  const f = await makeSubjects(['root', 'A', 'B'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] });
  await b.delegate('A', { to: 'B', rights: ['UNLOCK'] }, { root: 0 });
  await b.unlock('B', { root: 0, A: 0 });
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.equal(verdict(res, 2).decision, 'AUTHORIZED');
  assert.deepEqual(verdict(res, 2).chain.map((e) => e.id), ['root#0', 'A#0']);
  assert.equal(verdict(res, 2).chain[1].rights.includes('UNLOCK'), true);
});

await test('root is intrinsically authorized to unlock without edges', async () => {
  const f = await makeSubjects(['root'], 'root');
  const b = new Builder(f);
  await b.unlock('root');
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.equal(verdict(res, 0).decision, 'AUTHORIZED');
});

// ---------------------------------------------------------------------------
console.log('revocation causality:');
await test('late-arriving revocation cannot retroactively veto an earlier visible-history verdict', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }); // root#0
  await b.unlock('A', { root: 0 }); // A#0: authorized, does not see any revoke
  await b.revoke('root', { from: 'root', seq: 0, to: 'A' }, { root: 0 }); // root#1 arrives later
  await b.unlock('A', { root: 1, A: 0 }); // A#1: now sees the revoke
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.equal(verdict(res, 1).decision, 'AUTHORIZED', 'first request keeps its verdict');
  assert.equal(verdict(res, 3).decision, 'DENIED', 'request that sees the revoke is denied');
  assert.equal(verdict(res, 3).evidence.type, 'REVOKED_EDGE');
  assert.equal(verdict(res, 3).evidence.edge.id, 'root#0');
});

await test('revocation that arrived earlier but is causally unseen does not block', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['UNLOCK'] }); // root#0
  await b.revoke('root', { from: 'root', seq: 0, to: 'A' }); // root#1, concurrent from A's view
  await b.unlock('A', { root: 0 }); // A sees only root#0
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.equal(verdict(res, 2).decision, 'AUTHORIZED');
  assert.deepEqual(res.records[2].visibleRevocations, []);
});

await test('forgetting an already-visible revocation is the first invalid record', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['UNLOCK'] }, {}); // root#0
  await b.revoke('root', { from: 'root', seq: 0, to: 'A' }, { root: 0 }); // root#1
  await b.unlock('A', { root: 1 }); // A#0 saw the revoke
  await b.unlock('A', { A: 0 }); // A#1 "forgets" root#1: regression
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 3);
  assert.equal(res.records[3].error.code, ERROR.VECTOR_REGRESSION);
});

await test('revocation cuts the edge and its descendants only, parallel independent delegation survives', async () => {
  const f = await makeSubjects(['root', 'A', 'B', 'C'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }); // root#0
  await b.delegate('root', { to: 'B', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0 }); // root#1 (parallel)
  await b.delegate('A', { to: 'C', rights: ['UNLOCK'] }, { root: 0 }); // A#0 (descendant of root#0)
  await b.delegate('B', { to: 'C', rights: ['UNLOCK'] }, { root: 1, A: 0 }); // B#0 (independent of root#0)
  await b.revoke('root', { from: 'root', seq: 0, to: 'A' }, { root: 1, A: 0, B: 0 }); // root#2 cuts root#0 subtree
  await b.unlock('A', { root: 2, A: 0, B: 0 }); // A#1 denied: own edge cut
  await b.unlock('C', { root: 2, A: 1, B: 0 }); // C#0 still authorized via root#1 -> B#0
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.equal(verdict(res, 5).decision, 'DENIED');
  assert.equal(verdict(res, 5).evidence.type, 'REVOKED_EDGE');
  assert.equal(verdict(res, 6).decision, 'AUTHORIZED');
  assert.deepEqual(verdict(res, 6).chain.map((e) => e.id), ['root#1', 'B#0']);
});

await test('middle-edge revocation leaves upstream intact but cuts downstream descendants', async () => {
  const f = await makeSubjects(['root', 'A', 'B', 'C'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }); // root#0
  await b.delegate('A', { to: 'B', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0 }); // A#0
  await b.delegate('B', { to: 'C', rights: ['UNLOCK'] }, { root: 0, A: 0 }); // B#0
  await b.revoke('A', { from: 'A', seq: 0, to: 'B' }, { root: 0, A: 0, B: 0 }); // A#1 cuts A#0
  await b.unlock('A', { root: 0, A: 1, B: 0 }); // A#2 still fine (root#0 live)
  await b.unlock('C', { root: 0, A: 1, B: 0 }); // B#1 denied
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.equal(verdict(res, 4).decision, 'AUTHORIZED');
  assert.equal(verdict(res, 5).decision, 'DENIED');
  assert.equal(verdict(res, 5).evidence.edge.id, 'A#0');
});

await test('only the edge owner can revoke', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['UNLOCK'] });
  await b.revoke('A', { from: 'root', seq: 0, to: 'A' }, { root: 0 }); // A is not the delegator
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 1);
  assert.equal(res.records[1].error.code, ERROR.REVOKE_NOT_OWNER);
});

await test('revoking an unknown or mismatched target is rejected', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const b1 = new Builder(f);
  await b1.delegate('root', { to: 'A', rights: ['UNLOCK'] });
  await b1.revoke('root', { from: 'root', seq: 7, to: 'A' }, { root: 0 });
  const r1 = await loadAndEvaluate(f, b1);
  assert.equal(r1.records[1].error.code, ERROR.REVOKE_UNKNOWN_TARGET);

  const b2 = new Builder(f);
  await b2.delegate('root', { to: 'A', rights: ['UNLOCK'] });
  await b2.revoke('root', { from: 'root', seq: 0, to: 'root' }, { root: 0 }); // wrong grantee
  const r2 = await loadAndEvaluate(f, b2);
  assert.equal(r2.records[1].error.code, ERROR.REVOKE_UNKNOWN_TARGET);
});

// ---------------------------------------------------------------------------
console.log('delegation authority & rights:');
await test('rights sets may only shrink along the chain', async () => {
  const f = await makeSubjects(['root', 'A', 'B'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['UNLOCK'] }); // root#0: no DELEGATE right
  await b.delegate('A', { to: 'B', rights: ['UNLOCK'] }, { root: 0 }); // A cannot delegate
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 1);
  assert.equal(res.records[1].error.code, ERROR.NO_DELEGATE_AUTHORITY);
});

await test('granting a right the inbound edge lacks is amplification', async () => {
  const f = await makeSubjects(['root', 'A', 'B', 'C'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }); // root#0 full
  await b.delegate('A', { to: 'B', rights: ['DELEGATE'] }, { root: 0 }); // A#0 shrink: B may delegate but never unlock
  await b.delegate('B', { to: 'C', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0, A: 0 }); // B#0 amplifies UNLOCK
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 2);
  assert.equal(res.records[2].error.code, ERROR.RIGHTS_AMPLIFICATION);
  assert.match(res.records[2].error.evidence.message, /UNLOCK/);
});

await test('terminal edge needs UNLOCK while intermediary edges need DELEGATE', async () => {
  const f = await makeSubjects(['root', 'A', 'B'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE'] }); // root#0: can pass on but not unlock
  await b.delegate('A', { to: 'B', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0 }); // A#0 amplification: root#0 lacks UNLOCK... DELEGATE-only is fine to grant DELEGATE but not UNLOCK
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.records[1].error.code, ERROR.RIGHTS_AMPLIFICATION);

  const f2 = await makeSubjects(['root', 'A', 'B', 'C'], 'root');
  const b2 = new Builder(f2);
  await b2.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] });
  await b2.delegate('A', { to: 'B', rights: ['UNLOCK'] }, { root: 0 }); // leaf: no DELEGATE
  await b2.delegate('B', { to: 'C', rights: ['UNLOCK'] }, { root: 0, A: 0 }); // B cannot redelegate
  const r2 = await loadAndEvaluate(f2, b2);
  assert.equal(r2.records[2].error.code, ERROR.NO_DELEGATE_AUTHORITY);

  // A holding DELEGATE but not UNLOCK cannot itself unlock even though it can delegate.
  const f3 = await makeSubjects(['root', 'A'], 'root');
  const b3 = new Builder(f3);
  await b3.delegate('root', { to: 'A', rights: ['DELEGATE'] });
  await b3.unlock('A', { root: 0 });
  const r3 = await loadAndEvaluate(f3, b3);
  assert.equal(verdict(r3, 1).decision, 'DENIED');
  assert.equal(verdict(r3, 1).evidence.type, 'RIGHTS_MISSING');
});

// ---------------------------------------------------------------------------
console.log('graph attacks:');
await test('delegation cycle is rejected at the closing record', async () => {
  const f = await makeSubjects(['root', 'A', 'B'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }); // root#0
  await b.delegate('A', { to: 'B', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0 }); // A#0
  await b.delegate('B', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0, A: 0 }); // B#0 closes loop
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 2);
  assert.equal(res.records[2].error.code, ERROR.CYCLE);
});

await test('forged signature is the first invalid record', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const f2 = await makeSubjects(['attacker'], 'attacker');
  const b = new Builder(f);
  const ev = await b.delegate('root', { to: 'A', rights: ['UNLOCK'] });
  // Re-sign with an unimported attacker key.
  const { canonicalBytes } = await import('../core/canonical.js');
  const { b64encode } = await import('../core/codec.js');
  const stripped = { ...ev };
  delete stripped.signature;
  ev.signature = b64encode(await ed.sign(canonicalBytes(stripped), f2.priv.get('attacker')));
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 0);
  assert.equal(res.records[0].error.code, ERROR.FORGED_SIGNATURE);
});

await test('tampered body after signing is detected', async () => {
  const f = await makeSubjects(['root', 'A', 'B'], 'root');
  const b = new Builder(f);
  const ev = await b.delegate('root', { to: 'A', rights: ['UNLOCK'] });
  ev.to = 'B'; // mutate without re-signing
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.records[0].error.code, ERROR.FORGED_SIGNATURE);
});

await test('counter gaps are located at the skipping record', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['UNLOCK'] }); // root#0
  // Craft root#2 directly (skip root#1), valid signature.
  const { canonicalBytes } = await import('../core/canonical.js');
  const { b64encode } = await import('../core/codec.js');
  const ev = { kind: 'revoke', author: 'root', seq: 2, seen: { root: 0 }, target: { from: 'root', to: 'A', seq: 0 } };
  ev.signature = b64encode(await ed.sign(canonicalBytes(ev), f.priv.get('root')));
  b.raw('root', 2, ev);
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, 1);
  assert.equal(res.records[1].error.code, ERROR.SEQ_SKIP);
});

await test('unknown predecessors (missing, future, invalid) are located', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const { canonicalBytes } = await import('../core/canonical.js');
  const { b64encode } = await import('../core/codec.js');

  const b1 = new Builder(f);
  const ev1 = { kind: 'unlock', author: 'A', seq: 0, seen: { root: 3 } };
  ev1.signature = b64encode(await ed.sign(canonicalBytes(ev1), f.priv.get('A')));
  b1.raw('A', 0, ev1);
  const r1 = await loadAndEvaluate(f, b1);
  assert.equal(r1.records[0].error.code, ERROR.UNKNOWN_PREDECESSOR);

  // Pointing at an earlier invalid record is itself an unknown predecessor.
  const b2 = new Builder(f);
  const d = await b2.delegate('root', { to: 'A', rights: ['UNLOCK'] });
  d.signature = d.signature.slice(0, 40) + (d.signature[40] === 'A' ? 'B' : 'A') + d.signature.slice(41); // flip one char, keep 64 bytes
  await b2.unlock('A', { root: 0 });
  const r2 = await loadAndEvaluate(f, b2);
  assert.equal(r2.records[0].error.code, ERROR.FORGED_SIGNATURE);
  assert.equal(r2.records[1].error.code, ERROR.UNKNOWN_PREDECESSOR);
  assert.equal(r2.firstInvalidRecord, 0);
});

// ---------------------------------------------------------------------------
console.log('import limits:');
await test('at most 8 subjects and 24 events', async () => {
  const ids = ['r', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8'];
  const f = await makeSubjects(ids, 'r');
  const dir = loadSubjects(f.directory);
  assert.equal(dir.error.code, ERROR.LIMIT);

  const f2 = await makeSubjects(['r'], 'r');
  const dir2 = loadSubjects(f2.directory);
  const events = [];
  for (let i = 0; i < LIMITS.maxEvents + 1; i++) {
    events.push({ kind: 'unlock', author: 'r', seq: i, seen: i ? { r: i - 1 } : {} });
  }
  for (const e of events) e.signature = b64encode(await ed.sign(canonicalBytes(e), f2.priv.get('r')));
  const res = await evaluateLog(dir2, events);
  assert.equal(res.ok, false);
  assert.equal(res.error.code, ERROR.LIMIT);
});

await test('malformed import (unknown root, bad key, duplicate id) is rejected', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const dir1 = loadSubjects({ subjects: f.directory.subjects, rootSubject: 'ghost' });
  assert.equal(dir1.error.code, ERROR.UNKNOWN_SUBJECT);
  const dir2 = loadSubjects({
    subjects: [{ id: 'root', publicKey: f.directory.subjects[0].publicKey.slice(0, -4) }],
    rootSubject: 'root'
  });
  assert.equal(dir2.error.code, ERROR.UNKNOWN_KEY);
  const dup = { subjects: [...f.directory.subjects, { id: 'A', publicKey: f.directory.subjects[0].publicKey }], rootSubject: 'root' };
  assert.equal(loadSubjects(dup).error.code, ERROR.SCHEMA);
});

// ---------------------------------------------------------------------------
console.log('structural validity:');
await test('malformed records are invalid at their own position and do not poison the run', async () => {
  const f = await makeSubjects(['root', 'A'], 'root');
  const { canonicalBytes } = await import('../core/canonical.js');
  const { b64encode } = await import('../core/codec.js');
  const mk = async (event) => ({ ...event, signature: b64encode(await ed.sign(canonicalBytes(event), f.priv.get(event.author))) });

  // bad rights, unknown kind, unlock naming another subject, bad Base64 signature
  const e0 = await mk({ kind: 'delegate', author: 'root', seq: 0, seen: {}, from: 'root', to: 'A', rights: ['ROOT'] });
  const e1 = await mk({ kind: 'teleport', author: 'root', seq: 1, seen: { root: 0 } });
  const e2 = await mk({ kind: 'unlock', author: 'A', seq: 0, seen: {}, target: 'root' });
  const e3 = await mk({ kind: 'unlock', author: 'root', seq: 2, seen: { root: 1 } });
  e3.signature = 'not base64!!!';
  const dir = loadSubjects(f.directory);
  const res = await evaluateLog(dir, [e0, e1, e2, e3]);
  assert.equal(res.firstInvalidRecord, 0);
  assert.equal(res.records[0].error.code, ERROR.BAD_DELEGATION);
  assert.equal(res.records[1].error.code, ERROR.SCHEMA);
  assert.equal(res.records[2].error.code, ERROR.BAD_UNLOCK);
  assert.equal(res.records[3].error.code, ERROR.SCHEMA);
  // A later well-formed record after the invalid run still evaluates on its own merits.
  const good = await mk({ kind: 'unlock', author: 'root', seq: 1, seen: {} });
  const res2 = await evaluateLog(dir, [e0, good]);
  assert.equal(res2.records[1].verdict.decision, 'AUTHORIZED');
});

// ---------------------------------------------------------------------------
console.log('canonical shortest evidence:');
await test('authorized chain is canonical shortest; evidence gives nominal chain', async () => {
  const f = await makeSubjects(['root', 'A', 'B'], 'root');
  const b = new Builder(f);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }); // root#0
  await b.delegate('root', { to: 'B', rights: ['UNLOCK'] }, { root: 0 }); // root#1 direct
  await b.delegate('A', { to: 'B', rights: ['UNLOCK'] }, { root: 1 }); // A#0 longer route
  await b.unlock('B', { root: 1, A: 0 });
  const res = await loadAndEvaluate(f, b);
  assert.equal(res.firstInvalidRecord, null);
  assert.deepEqual(verdict(res, 3).chain.map((e) => e.id), ['root#1']);

  // Cut the direct edge: shortest surviving path is used; then cut both -> evidence.
  const b2 = new Builder(f);
  await b2.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] });
  await b2.delegate('root', { to: 'B', rights: ['UNLOCK'] }, { root: 0 });
  await b2.delegate('A', { to: 'B', rights: ['UNLOCK'] }, { root: 1 });
  await b2.revoke('root', { from: 'root', seq: 1, to: 'B' }, { root: 1, A: 0 }); // root#2
  await b2.unlock('B', { root: 2, A: 0 });
  const r2 = await loadAndEvaluate(f, b2);
  assert.deepEqual(verdict(r2, 4).chain.map((e) => e.id), ['root#0', 'A#0']);
  await b2.revoke('root', { from: 'root', seq: 0, to: 'A' }, { root: 2, A: 0 }); // root#3
  await b2.unlock('B', { root: 3, A: 0, B: 0 });
  const r3 = await loadAndEvaluate(f, b2);
  assert.equal(verdict(r3, 6).decision, 'DENIED');
  assert.equal(verdict(r3, 6).evidence.type, 'REVOKED_EDGE');
  assert.deepEqual(verdict(r3, 6).evidence.nominalChain.map((e) => e.id), ['root#1']);
});

// ---------------------------------------------------------------------------
console.log('');
console.log(`rules: ${passed} passed, ${failures.length} failed`);
if (failures.length) process.exit(1);
