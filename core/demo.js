// Ready-made, correctly signed review scenarios, generated in the browser
// with fresh Ed25519 keys. The same scenarios are served by the verify
// container for HTTP smoke tests.
import { makeSubjects, Builder, signEvent } from './fixture.js';
import { canonicalBytes } from './canonical.js';
import { b64encode } from './codec.js';
import * as ed from '@noble/ed25519';

function documentOf(root, fixture, events) {
  return { rootSubject: root, subjects: fixture.subjects, events };
}

/** Healthy parallel chains; the canonical shortest authorized chain wins. */
export async function healthyScenario() {
  const fixture = await makeSubjects(['root', 'A', 'B', 'C']);
  const b = new Builder(fixture);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }, {}); // root#0
  await b.delegate('root', { to: 'B', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0 }); // root#1
  await b.delegate('A', { to: 'C', rights: ['UNLOCK'] }, { root: 1 }); // A#0
  await b.delegate('B', { to: 'C', rights: ['UNLOCK'] }, { root: 1, A: 0 }); // B#0
  await b.unlock('C', { root: 1, A: 0, B: 0 }); // C#0 -> canonical shortest chain
  await b.unlock('A', { root: 1, A: 0, B: 0, C: 0 }); // A#1 -> authorized via root#0
  return documentOf('root', fixture, b.events);
}

/**
 * Revocation review: an unlock decided before the revoke arrived keeps
 * its verdict; requests that see the revoke are denied via the cut edge,
 * while a parallel independent delegation restores authorization.
 */
export async function revokeScenario() {
  const fixture = await makeSubjects(['root', 'A', 'B', 'C']);
  const b = new Builder(fixture);
  await b.delegate('root', { to: 'A', rights: ['DELEGATE', 'UNLOCK'] }, {}); // root#0
  await b.delegate('A', { to: 'B', rights: ['DELEGATE', 'UNLOCK'] }, { root: 0 }); // A#0
  await b.delegate('B', { to: 'C', rights: ['UNLOCK'] }, { root: 0, A: 0 }); // B#0
  await b.unlock('A', { root: 0, A: 0, B: 0 }); // A#1: authorized before the revoke exists
  await b.revoke('root', { from: 'root', seq: 0, to: 'A' }, { root: 0, A: 1, B: 0 }); // root#1 cuts root#0 subtree
  await b.unlock('A', { root: 1, A: 1, B: 0 }); // A#2: denied, its own edge is revoked
  await b.unlock('C', { root: 1, A: 1, B: 0 }); // C#0: denied, cut at root#0
  await b.delegate('root', { to: 'C', rights: ['UNLOCK'] }, { root: 1, A: 1, B: 0 }); // root#2: parallel independent edge
  await b.unlock('C', { root: 2, A: 1, B: 0, C: 0 }); // C#1: authorized via the parallel edge
  return documentOf('root', fixture, b.events);
}

/** A forged root signature is the first invalid record; its dependent request is an unknown predecessor. */
export async function forgeryScenario() {
  const fixture = await makeSubjects(['root', 'A']);
  const attacker = await makeSubjects(['mallory']);
  const b = new Builder(fixture);
  const forged = {
    kind: 'delegate',
    author: 'root',
    seq: 0,
    seen: {},
    from: 'root',
    to: 'A',
    rights: ['UNLOCK']
  };
  forged.signature = b64encode(await ed.sign(canonicalBytes(forged), attacker.priv.get('mallory')));
  b.raw('root', 0, forged);
  await b.unlock('A', { root: 0 }); // depends on the forged record
  return documentOf('root', fixture, b.events);
}

/** Counter gap: root#0 then a signed root#2 (root#1 missing). */
export async function counterSkipScenario() {
  const fixture = await makeSubjects(['root', 'A']);
  const b = new Builder(fixture);
  await b.delegate('root', { to: 'A', rights: ['UNLOCK'] }, {});
  const skipped = {
    kind: 'revoke',
    author: 'root',
    seq: 2,
    seen: { root: 0 },
    target: { from: 'root', to: 'A', seq: 0 }
  };
  skipped.signature = b64encode(await ed.sign(canonicalBytes(skipped), fixture.priv.get('root')));
  b.raw('root', 2, skipped);
  return documentOf('root', fixture, b.events);
}

export const SCENARIOS = {
  healthy: healthyScenario,
  revoke: revokeScenario,
  forgery: forgeryScenario,
  'counter-skip': counterSkipScenario
};

export async function buildScenario(name) {
  const fn = SCENARIOS[name];
  if (!fn) throw new Error('unknown scenario ' + name);
  return fn();
}

export { signEvent };
