// Deterministic (WebCrypto-seeded) fixture builders, usable both in the
// browser demo page and in Node tests.
import { generatePrivateKey, getPublicKey, sign } from './crypto.js';
import { canonicalBytes } from './canonical.js';
import { b64encode } from './codec.js';

export async function makeSubjects(ids) {
  const priv = new Map();
  const subjects = [];
  for (const id of ids) {
    const sk = await generatePrivateKey();
    const pk = await getPublicKey(sk);
    priv.set(id, sk);
    subjects.push({ id, publicKey: b64encode(pk) });
  }
  return { subjects, priv, ids };
}

/**
 * Signed-event builder. Per-author counters are automatic and each new
 * record causally extends the author's previous record; the caller passes
 * any additional seen entries explicitly.
 */
export class Builder {
  constructor(fixture) {
    this.fixture = fixture;
    this.seq = new Map();
    this.events = [];
  }

  async _emit(author, body, seen = {}, { extend = true } = {}) {
    const s = this.seq.get(author) || 0;
    const seenObj = {};
    if (extend && s > 0) seenObj[author] = s - 1;
    Object.assign(seenObj, seen);
    const event = { ...body, author, seq: s, seen: seenObj };
    event.signature = b64encode(await sign(canonicalBytes(stripSig(event)), this.fixture.priv.get(author)));
    this.seq.set(author, s + 1);
    this.events.push(event);
    return event;
  }

  delegate(author, { to, rights }, seen, opts) {
    return this._emit(author, { kind: 'delegate', from: author, to, rights }, seen, opts);
  }
  revoke(author, { from, seq, to }, seen, opts) {
    return this._emit(author, { kind: 'revoke', target: { from, to, seq } }, seen, opts);
  }
  unlock(author, seen, opts) {
    return this._emit(author, { kind: 'unlock' }, seen, opts);
  }

  /** Push an already-built event without touching counters (negative tests). */
  raw(_author, _seq, event) {
    this.events.push(event);
    return event;
  }
}

function stripSig(e) {
  const o = {};
  for (const k of Object.keys(e)) if (k !== 'signature') o[k] = e[k];
  return o;
}

export async function signEvent(fixture, event) {
  const sig = await sign(canonicalBytes(stripSig(event)), fixture.priv.get(event.author));
  return { ...event, signature: b64encode(sig) };
}
