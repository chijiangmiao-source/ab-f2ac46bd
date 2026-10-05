// Causal authorization-log model.
//
// Records arrive offline in array order. Every record is judged against
// its own causal past: the transitive closure reached through its "seen"
// vector of (author, seq) pointers. A later-arriving revocation is
// therefore invisible to an unlock whose vector does not see it, and a
// revocation that IS seen cannot be ignored merely because of arrival
// position.
//
// Kinds:
//   delegate { author, seq, seen, from, to, rights:[UNLOCK|DELEGATE], signature }
//   revoke   { author, seq, seen, target:{from,to,seq}, signature }
//   unlock   { author, seq, seen, target?, signature }
//
// Edge identity is "<delegator>#<delegator-seq>". Revoking an edge cuts
// exactly chains that must pass through it; parallel independent
// delegations remain usable as alternative chains.

import { verify } from './crypto.js';
import { signingBytes } from './canonical.js';
import { b64decode } from './codec.js';

export const FULL_RIGHTS = ['DELEGATE', 'UNLOCK'];
export const LIMITS = { maxSubjects: 8, maxEvents: 24 };

export const ERROR = {
  SCHEMA: 'SCHEMA_ERROR',
  LIMIT: 'LIMIT_EXCEEDED',
  UNKNOWN_SUBJECT: 'UNKNOWN_SUBJECT',
  UNKNOWN_KEY: 'MALFORMED_PUBLIC_KEY',
  FORGED_SIGNATURE: 'FORGED_SIGNATURE',
  SEQ_SKIP: 'SEQUENCE_SKIP',
  UNKNOWN_PREDECESSOR: 'UNKNOWN_PREDECESSOR',
  BAD_DELEGATION: 'MALFORMED_DELEGATION',
  CYCLE: 'DELEGATION_CYCLE',
  NO_DELEGATE_AUTHORITY: 'NO_DELEGATE_AUTHORITY',
  RIGHTS_AMPLIFICATION: 'RIGHTS_AMPLIFICATION',
  BAD_REVOCATION: 'MALFORMED_REVOCATION',
  REVOKE_UNKNOWN_TARGET: 'REVOKE_UNKNOWN_TARGET',
  REVOKE_NOT_OWNER: 'REVOKE_NOT_OWNER',
  BAD_UNLOCK: 'MALFORMED_UNLOCK',
  VECTOR_REGRESSION: 'SEEN_VECTOR_REGRESSION'
};

function isNonNegInt(x) {
  return Number.isInteger(x) && x >= 0 && x <= Number.MAX_SAFE_INTEGER;
}

function fail(code, message, extra = {}) {
  return { code, message, ...extra };
}

/**
 * Validate the imported subject directory.
 * @returns {{subjects: Map<string, Uint8Array>, root: string}|{error: object}}
 */
export function loadSubjects(input) {
  if (!input || typeof input !== 'object') return { error: fail(ERROR.SCHEMA, 'subject import must be an object') };
  const rawSubjects = input.subjects;
  const root = input.rootSubject;
  if (!Array.isArray(rawSubjects)) return { error: fail(ERROR.SCHEMA, 'subjects must be an array') };
  if (rawSubjects.length === 0) return { error: fail(ERROR.SCHEMA, 'at least one subject is required') };
  if (rawSubjects.length > LIMITS.maxSubjects) {
    return { error: fail(ERROR.LIMIT, `at most ${LIMITS.maxSubjects} subjects allowed`, { limit: LIMITS.maxSubjects }) };
  }
  if (typeof root !== 'string' || root.length === 0) {
    return { error: fail(ERROR.SCHEMA, 'rootSubject must be a non-empty subject id') };
  }
  const subjects = new Map();
  const seenKeys = new Set();
  for (const s of rawSubjects) {
    if (!s || typeof s !== 'object') return { error: fail(ERROR.SCHEMA, 'each subject must be an object') };
    if (typeof s.id !== 'string' || !/^[A-Za-z0-9_.@-]+$/.test(s.id)) {
      return { error: fail(ERROR.SCHEMA, 'subject id must be a non-empty token of [A-Za-z0-9_.@-]') };
    }
    if (subjects.has(s.id)) return { error: fail(ERROR.SCHEMA, `duplicate subject id: ${s.id}`) };
    if (typeof s.publicKey !== 'string') return { error: fail(ERROR.UNKNOWN_KEY, `subject ${s.id}: publicKey must be Base64`) };
    let key;
    try {
      key = b64decode(s.publicKey);
    } catch (e) {
      return { error: fail(ERROR.UNKNOWN_KEY, `subject ${s.id}: ${e.message}`) };
    }
    if (key.length !== 32) return { error: fail(ERROR.UNKNOWN_KEY, `subject ${s.id}: Ed25519 key must decode to 32 bytes`) };
    const keyHex = hexKey(key);
    if (seenKeys.has(keyHex)) return { error: fail(ERROR.SCHEMA, `subject ${s.id}: duplicate public key`) };
    seenKeys.add(keyHex);
    subjects.set(s.id, key);
  }
  if (!subjects.has(root)) return { error: fail(ERROR.UNKNOWN_SUBJECT, `rootSubject ${root} is not among the imported subjects`) };
  return { subjects, root };
}

function hexKey(bytes) {
  let h = '';
  for (const b of bytes) h += b.toString(16).padStart(2, '0');
  return h;
}

function validateSeenVector(raw, subjects) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const out = [];
  for (const a of Object.keys(raw)) {
    if (!subjects.has(a)) return { bad: `seen vector names unknown subject ${a}` };
    if (!isNonNegInt(raw[a])) return { bad: `seen[${a}] must be a non-negative integer` };
    out.push([a, raw[a]]);
  }
  return { ok: out };
}

function validateRights(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const set = new Set();
  for (const r of raw) {
    if (r !== 'UNLOCK' && r !== 'DELEGATE') return null;
    if (set.has(r)) return null;
    set.add(r);
  }
  return [...set].sort();
}

/**
 * Structural validation of one record (no signature, no graph checks).
 */
function structuralCheck(ev, subjects) {
  if (!ev || typeof ev !== 'object' || Array.isArray(ev)) {
    return fail(ERROR.SCHEMA, 'event must be a JSON object');
  }
  if (typeof ev.author !== 'string' || !subjects.has(ev.author)) {
    return fail(ERROR.UNKNOWN_SUBJECT, `unknown or missing author ${JSON.stringify(ev.author)}`);
  }
  if (!isNonNegInt(ev.seq)) return fail(ERROR.SCHEMA, 'seq must be a non-negative integer');
  const seen = validateSeenVector(ev.seen, subjects);
  if (seen === null) return fail(ERROR.SCHEMA, 'seen must be an object mapping subject id to seq');
  if ('bad' in seen) return fail(ERROR.SCHEMA, seen.bad);
  if (typeof ev.signature !== 'string' || ev.signature.length === 0) {
    return fail(ERROR.SCHEMA, 'missing Base64 signature');
  }
  let sigBytes;
  try {
    sigBytes = b64decode(ev.signature);
  } catch (e) {
    return fail(ERROR.SCHEMA, `malformed signature Base64: ${e.message}`);
  }
  if (sigBytes.length !== 64) return fail(ERROR.SCHEMA, 'Ed25519 signature must decode to 64 bytes');

  if (ev.kind === 'delegate') {
    if (ev.from !== ev.author) return fail(ERROR.BAD_DELEGATION, 'delegation from must equal its signing author');
    if (typeof ev.to !== 'string' || !subjects.has(ev.to)) return fail(ERROR.UNKNOWN_SUBJECT, `delegation target ${JSON.stringify(ev.to)} is unknown`);
    if (ev.to === ev.from) return fail(ERROR.CYCLE, 'self-delegation is a cycle');
    const rights = validateRights(ev.rights);
    if (!rights) return fail(ERROR.BAD_DELEGATION, 'rights must be a non-empty list without duplicates, each UNLOCK or DELEGATE');
    return { ok: true, kind: 'delegate', seen: seen.ok, sig: sigBytes, rights };
  }
  if (ev.kind === 'revoke') {
    const t = ev.target;
    if (!t || typeof t !== 'object') return fail(ERROR.BAD_REVOCATION, 'revoke requires target {from,to,seq}');
    if (typeof t.from !== 'string' || !subjects.has(t.from)) return fail(ERROR.UNKNOWN_SUBJECT, 'revocation target from unknown');
    if (typeof t.to !== 'string' || !subjects.has(t.to)) return fail(ERROR.UNKNOWN_SUBJECT, 'revocation target to unknown');
    if (!isNonNegInt(t.seq)) return fail(ERROR.BAD_REVOCATION, 'revocation target seq must be a non-negative integer');
    return { ok: true, kind: 'revoke', seen: seen.ok, sig: sigBytes };
  }
  if (ev.kind === 'unlock') {
    // The requester is the signing subject itself; an explicit target may
    // restate that but may not name some other subject.
    const target = ev.target === undefined ? ev.author : ev.target;
    if (target !== ev.author) {
      return fail(ERROR.BAD_UNLOCK, `unlock target ${target} must equal its signing author ${ev.author}`);
    }
    return { ok: true, kind: 'unlock', seen: seen.ok, sig: sigBytes, target };
  }
  return fail(ERROR.SCHEMA, `unknown event kind ${JSON.stringify(ev.kind)}`);
}

// --- graph helpers operating on a closed causal slice ---------------------

function buildSlice(records, closure) {
  const edges = [];
  const edgeById = new Map();
  const revocations = []; // {edgeId, record}
  for (const i of closure) {
    const r = records[i];
    if (r.kind === 'delegate' && r.valid) {
      edges.push(r.edge);
      edgeById.set(r.edge.id, r.edge);
    } else if (r.kind === 'revoke' && r.valid) {
      revocations.push({ edgeId: r.revocation.edgeId, recordIndex: i });
    }
  }
  return { edges, edgeById, revocations };
}

function adjacency(edges, revokedIds) {
  const adj = new Map();
  for (const e of edges) {
    if (revokedIds && revokedIds.has(e.id)) continue;
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e);
  }
  for (const list of adj.values()) list.sort((a, b) => (a.to < b.to ? -1 : a.to > b.to ? 1 : a.seq - b.seq));
  return adj;
}

/**
 * Shortest canonical root->goal chain. An edge may be used if
 * accept(edge, isTerminalEdge) returns true. BFS with lexicographic tie
 * break yields the canonical shortest chain. Returns edge[] or null.
 */
function findChain(root, goal, edges, revokedIds, accept) {
  if (root === goal) return [];
  const adj = adjacency(edges, revokedIds);
  const prev = new Map(); // node -> {edge, from}
  const visited = new Set([root]);
  const queue = [root];
  while (queue.length) {
    const cur = queue.shift();
    for (const e of adj.get(cur) || []) {
      if (visited.has(e.to)) continue;
      if (!accept(e, e.to === goal)) continue;
      visited.add(e.to);
      prev.set(e.to, { edge: e, from: cur });
      if (e.to === goal) {
        const chain = [];
        let node = goal;
        while (node !== root) {
          const p = prev.get(node);
          chain.unshift(p.edge);
          node = p.from;
        }
        return chain;
      }
      queue.push(e.to);
    }
  }
  return null;
}

function hasPath(edges, revokedIds, from, to) {
  if (from === to) return true;
  const adj = adjacency(edges, revokedIds);
  const seen = new Set([from]);
  const stack = [from];
  while (stack.length) {
    const cur = stack.pop();
    for (const e of adj.get(cur) || []) {
      if (seen.has(e.to)) continue;
      if (e.to === to) return true;
      seen.add(e.to);
      stack.push(e.to);
    }
  }
  return false;
}

function rightsCover(have, need) {
  return need.every((r) => have.includes(r));
}

/**
 * Failure witness for a requested root->goal chain. Finds the shortest
 * structural chain that nominally reaches the goal, then pinpoints its
 * first unusable edge (revoked cut, or rights shrunk away). If no
 * structural chain exists at all, reports the reachable frontier.
 *
 * needAt(edgeIndex, chain) returns the right set required on that edge.
 */
function failureEvidence(root, goal, slice, needAt) {
  const revokedIds = new Set(slice.revocations.map((r) => r.edgeId));
  const revokerByEdge = new Map();
  for (const r of slice.revocations) {
    if (!revokerByEdge.has(r.edgeId)) revokerByEdge.set(r.edgeId, []);
    revokerByEdge.get(r.edgeId).push(r.recordIndex);
  }
  const structural = findChain(root, goal, slice.edges, null, () => true);
  if (!structural) {
    const adj = adjacency(slice.edges, null);
    const reachable = new Set([root]);
    const stack = [root];
    while (stack.length) {
      const cur = stack.pop();
      for (const e of adj.get(cur) || []) {
        if (!reachable.has(e.to)) {
          reachable.add(e.to);
          stack.push(e.to);
        }
      }
    }
    reachable.delete(goal);
    return {
      type: 'NO_CHAIN',
      message: `no delegation chain structurally reaches ${goal}`,
      reachable: [...reachable].sort()
    };
  }
  for (let k = 0; k < structural.length; k++) {
    const e = structural[k];
    const needs = needAt(k, structural);
    const missing = needs.filter((x) => !e.rights.includes(x));
    if (revokedIds.has(e.id)) {
      return {
        type: 'REVOKED_EDGE',
        message: `shortest chain is cut at revoked delegation ${e.id} (${e.from}->${e.to}); parallel independent delegations, if any, were also searched`,
        edge: edgeRef(e),
        revokedBy: revokerByEdge.get(e.id),
        nominalChain: structural.map(edgeRef)
      };
    }
    if (missing.length) {
      return {
        type: 'RIGHTS_MISSING',
        message: `delegation ${e.id} (${e.from}->${e.to}) carries [${e.rights.join(',')}] but the chain position requires ${missing.join('+')}`,
        edge: edgeRef(e),
        missing: missing.join('+'),
        nominalChain: structural.map(edgeRef)
      };
    }
  }
  return { type: 'NO_CHAIN', message: 'no usable chain', reachable: [] };
}

function edgeRef(e) {
  return { id: e.id, from: e.from, to: e.to, seq: e.seq, rights: e.rights, record: e.index };
}

/**
 * Evaluate an entire imported log.
 * @param {{subjects: Map, root: string}} dir loaded subject directory
 * @param {Array} events raw event objects in arrival order
 */
export async function evaluateLog(dir, events) {
  const { subjects, root } = dir;
  if (!Array.isArray(events)) return { ok: false, error: fail(ERROR.SCHEMA, 'events must be an array') };
  if (events.length > LIMITS.maxEvents) {
    return { ok: false, error: fail(ERROR.LIMIT, `at most ${LIMITS.maxEvents} events allowed`, { limit: LIMITS.maxEvents }) };
  }

  const records = [];
  const byAuthorCount = new Map(); // arrival-slot counter (every record occupies a seq)
  const refIndex = new Map(); // "author#seq" -> record index

  for (let i = 0; i < events.length; i++) {
    const raw = events[i];
    const base = { index: i, raw, valid: false, closure: null, kind: null };
    const check = structuralCheck(raw, subjects);
    if (!check.ok) {
      records.push({
        ...base,
        error: check,
        kind: raw && typeof raw.kind === 'string' ? raw.kind : null,
        author: raw && typeof raw.author === 'string' ? raw.author : null,
        seq: Number.isInteger(raw && raw.seq) ? raw.seq : null
      });
      continue;
    }
    records.push({ ...base, kind: check.kind, author: raw.author, seq: raw.seq, seen: check.seen, sig: check.sig, check });
  }

  // Register arrival slots and sequence numbers first so counter /
  // predecessor errors are attributable independently of signatures.
  // An earlier structural error takes precedence and is not overwritten.
  for (const r of records) {
    if (r.author == null || r.seq == null) continue;
    const expected = byAuthorCount.get(r.author) || 0;
    if (r.seq !== expected && !r.error) {
      r.valid = false;
      r.error = fail(ERROR.SEQ_SKIP, `${r.author}#${r.seq}: expected counter ${expected}`);
    }
    byAuthorCount.set(r.author, expected + 1);
    refIndex.set(`${r.author}#${r.seq}`, r.index);
  }

  // Signature verification (Ed25519 over canonical JSON sans signature).
  await Promise.all(
    records.map(async (r) => {
      if (r.error || r.author == null) return;
      let bytes;
      try {
        bytes = signingBytes(r.raw);
      } catch (e) {
        r.error = fail(ERROR.SCHEMA, `cannot canonicalize event: ${e.message}`);
        return;
      }
      const ok = await verify(r.sig, bytes, subjects.get(r.author));
      if (!ok) r.error = fail(ERROR.FORGED_SIGNATURE, `signature does not verify under ${r.author}'s imported public key`);
    })
  );

  // Causal closure + kind-specific rules, in arrival order.
  const frontier = new Map(); // author -> Map(otherAuthor -> highest seen seq among that author's valid records)
  for (const r of records) {
    if (r.error) continue;
    const seenMap = new Map(r.seen);
    const closure = new Set();
    let badRef = null;
    for (const [a, n] of r.seen) {
      const j = refIndex.get(`${a}#${n}`);
      if (j === undefined || j >= r.index) {
        badRef = `${a}#${n}`;
        break;
      }
      const target = records[j];
      if (!target.valid) {
        // Referencing a forged/ill-formed record is itself an unknown predecessor.
        badRef = `${a}#${n}`;
        break;
      }
      closure.add(j);
    }
    if (badRef) {
      r.error = fail(ERROR.UNKNOWN_PREDECESSOR, `seen vector points at event ${badRef} that does not exist as a valid prior record`, { reference: badRef });
      continue;
    }
    // A subject cannot forget what one of its own earlier records already
    // saw: vectors of the same author must be pointwise non-decreasing.
    const prior = frontier.get(r.author);
    if (prior) {
      for (const [a, n] of prior) {
        if ((seenMap.get(a) ?? -1) < n) {
          r.error = fail(
            ERROR.VECTOR_REGRESSION,
            `${r.author}#${r.seq} reports seen[${a}]=${seenMap.get(a) ?? 'absent'} but its earlier record already saw ${a}#${n}; visible history cannot be forgotten`
          );
          break;
        }
      }
      if (r.error) continue;
    }
    // Transitive closure of causally-seen valid events.
    const stack = [...closure];
    while (stack.length) {
      const j = stack.pop();
      for (const k of records[j].closure) if (!closure.has(k)) { closure.add(k); stack.push(k); }
    }
    r.closure = closure;
    const slice = buildSlice(records, closure);

    if (r.kind === 'delegate') applyDelegate(r, records, slice, root);
    else if (r.kind === 'revoke') applyRevoke(r, slice);
    else if (r.kind === 'unlock') applyUnlock(r, slice, root, r.check.target);

    if (r.valid) {
      const f = frontier.get(r.author) || new Map();
      for (const [a, n] of seenMap) if ((f.get(a) ?? -1) < n) f.set(a, n);
      // The just-issued record itself is known to this author afterwards.
      if ((f.get(r.author) ?? -1) < r.seq) f.set(r.author, r.seq);
      frontier.set(r.author, f);
    }
  }

  // Assemble per-record views for the page and the first-offender summary.
  const steps = records.map((r) => present(r, records, root));
  let firstInvalid = null;
  records.forEach((r, i) => {
    if (r.error && firstInvalid === null) firstInvalid = i;
  });

  return {
    ok: true,
    root,
    records: steps,
    firstInvalidRecord: firstInvalid,
    summary: {
      total: records.length,
      delegates: records.filter((r) => r.kind === 'delegate').length,
      revokes: records.filter((r) => r.kind === 'revoke').length,
      unlocks: records.filter((r) => r.kind === 'unlock').length,
      invalid: records.filter((r) => r.error).length,
      authorized: records.filter((r) => r.verdict && r.verdict.decision === 'AUTHORIZED').length,
      denied: records.filter((r) => r.verdict && r.verdict.decision === 'DENIED').length
    }
  };
}

function applyDelegate(r, records, slice, root) {
  const rights = r.check.rights;
  const edge = { id: `${r.author}#${r.seq}`, from: r.raw.from, to: r.raw.to, seq: r.seq, rights, index: r.index };

  // Cycle: adding from->to must not close a directed loop in the known graph.
  if (hasPath(slice.edges, null, edge.to, edge.from)) {
    r.error = fail(ERROR.CYCLE, `delegation ${edge.id} would create a cycle: ${edge.to} already reaches ${edge.from}`);
    return;
  }

  // Authority at issuance: a live chain from root. Every edge on it must
  // carry DELEGATE (only a subject with re-delegation authority may
  // delegate) and its rights must cover the rights being granted
  // (sets can only shrink).
  const revokedIds = new Set(slice.revocations.map((x) => x.edgeId));
  const needs = ['DELEGATE', ...rights];
  const chain = findChain(
    root,
    edge.from,
    slice.edges,
    revokedIds,
    (e) => e.rights.includes('DELEGATE') && rightsCover(e.rights, rights)
  );

  if (edge.from === root) {
    // Root holds the full right set intrinsically.
    r.valid = true;
    r.edge = edge;
    return;
  }
  if (!chain) {
    const witness = failureEvidence(root, edge.from, slice, () => needs);
    let code = ERROR.NO_DELEGATE_AUTHORITY;
    if (witness.type === 'RIGHTS_MISSING') {
      const missing = witness.missing.split('+');
      const amplified = missing.filter((x) => x !== 'DELEGATE');
      if (amplified.length) {
        code = ERROR.RIGHTS_AMPLIFICATION;
        witness.type = 'RIGHTS_AMPLIFICATION';
        witness.message = `rights [${amplified.join(',')}] are not present on inbound edge ${witness.edge.id}; right sets may only shrink`;
      }
    }
    r.error = fail(code, `${edge.from} lacked a live, sufficient redelegation chain at ${edge.id}'s causal past`, { evidence: witness });
    return;
  }
  r.valid = true;
  r.edge = edge;
  r.authorityChain = chain.map(edgeRef);
}

function applyRevoke(r, slice) {
  const t = r.raw.target;
  const edge = slice.edgeById.get(`${t.from}#${t.seq}`);
  if (!edge) {
    r.error = fail(
      ERROR.REVOKE_UNKNOWN_TARGET,
      `revocation targets ${t.from}#${t.seq}, which is not a delegation visible in its causal past`
    );
    return;
  }
  if (edge.to !== t.to) {
    r.error = fail(ERROR.REVOKE_UNKNOWN_TARGET, `target ${t.from}#${t.seq} delegates to ${edge.to}, not ${t.to}`);
    return;
  }
  if (r.author !== edge.from) {
    r.error = fail(ERROR.REVOKE_NOT_OWNER, `only the delegator ${edge.from} may revoke ${edge.id}; ${r.author} signed`);
    return;
  }
  r.valid = true;
  r.revocation = { edgeId: edge.id };
}

function applyUnlock(r, slice, root, goal) {
  const revokedIds = new Set(slice.revocations.map((x) => x.edgeId));
  const chain = findChain(root, goal, slice.edges, revokedIds, (e, terminal) => {
    return e.rights.includes(terminal ? 'UNLOCK' : 'DELEGATE');
  });
  r.valid = true; // a denied request is still a well-formed request
  if (root === goal) {
    r.verdict = { decision: 'AUTHORIZED', target: goal, chain: [], note: 'root is intrinsically authorized' };
    return;
  }
  if (chain) {
    r.verdict = { decision: 'AUTHORIZED', target: goal, chain: chain.map(edgeRef) };
  } else {
    r.verdict = {
      decision: 'DENIED',
      target: goal,
      evidence: failureEvidence(root, goal, slice, (k, c) => (k === c.length - 1 ? ['UNLOCK'] : ['DELEGATE']))
    };
  }
}

function present(r, records, root) {
  const out = {
    index: r.index,
    kind: r.kind,
    author: r.author,
    seq: r.seq,
    ref: r.author != null && r.seq != null ? `${r.author}#${r.seq}` : `#${r.index}`,
    valid: !!r.valid && !r.error,
    error: r.error || null
  };
  if (r.kind === 'delegate' && r.raw) {
    out.delegation = { from: r.raw.from, to: r.raw.to, rights: r.check ? r.check.rights : r.raw.rights, id: `${r.author}#${r.seq}` };
    if (r.authorityChain) out.authorityChain = r.authorityChain;
  }
  if (r.kind === 'revoke' && r.raw) {
    out.revocation = { target: `${r.raw.target.from}#${r.raw.target.seq}`, to: r.raw.target.to };
  }
  if (r.verdict) out.verdict = r.verdict;
  if (r.closure) {
    // The retained per-step view reflects the state AFTER applying this
    // record: closure (causal past) plus the record itself when valid.
    // The verdict above is still computed from the past alone.
    const stateClosure = new Set(r.closure);
    if (r.valid) stateClosure.add(r.index);
    const slice = buildSlice(records, stateClosure);
    const revokedIds = new Set(slice.revocations.map((x) => x.edgeId));
    out.visibleEdges = slice.edges.map((e) => ({
      ...edgeRef(e),
      active: !revokedIds.has(e.id),
      revokedBy: revokedIds.has(e.id)
        ? slice.revocations.filter((x) => x.edgeId === e.id).map((x) => records[x.recordIndex].author + '#' + records[x.recordIndex].seq)
        : []
    }));
    out.visibleRevocations = slice.revocations.map((x) => {
      const rr = records[x.recordIndex];
      return { edgeId: x.edgeId, record: rr.author + '#' + rr.seq, recordIndex: x.recordIndex };
    });
  } else {
    out.visibleEdges = [];
    out.visibleRevocations = [];
  }
  return out;
}
