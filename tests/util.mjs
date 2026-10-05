// Node test helpers: core fixture builders wrapped in the shape used by tests.
import { makeSubjects as makeFixture, Builder as CoreBuilder, signEvent as coreSignEvent } from '../core/fixture.js';
import { loadSubjects, evaluateLog } from '../core/model.js';

export { coreSignEvent as signEvent };

export async function makeSubjects(ids, root) {
  const fixture = await makeFixture(ids);
  return { fixture, directory: { subjects: fixture.subjects, rootSubject: root }, priv: fixture.priv, ids };
}
export class Builder extends CoreBuilder {}

export async function loadAndEvaluate(fixtureLike, builder) {
  const dir = loadSubjects(fixtureLike.directory);
  if (dir.error) throw new Error('bad fixture directory: ' + JSON.stringify(dir.error));
  return evaluateLog(dir, builder.events);
}
