// Canonical JSON: object keys sorted lexicographically by field name,
// no insignificant whitespace, non-ASCII emitted literally so the only
// byte-level representation is the UTF-8 encoding of that string.
// The signature of an event covers exactly this serialization of the
// event with its "signature" field removed.

export class CanonicalError extends Error {}

function escapeString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x22: out += '\\"'; break;
      case 0x5c: out += '\\\\'; break;
      case 0x08: out += '\\b'; break;
      case 0x0c: out += '\\f'; break;
      case 0x0a: out += '\\n'; break;
      case 0x0d: out += '\\r'; break;
      case 0x09: out += '\\t'; break;
      default:
        if (c < 0x20) {
          out += '\\u' + c.toString(16).padStart(4, '0');
        } else {
          out += s[i];
        }
    }
  }
  return out + '"';
}

function serialize(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'string') return escapeString(value);
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalError('non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(serialize).join(',') + ']';
  }
  if (t === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => escapeString(k) + ':' + serialize(value[k])).join(',') + '}';
  }
  throw new CanonicalError('unsupported JSON value: ' + t);
}

/** Canonical JSON string (keys sorted, compact). */
export function canonicalize(value) {
  return serialize(value);
}

/** UTF-8 bytes of the canonical JSON representation. */
export function canonicalBytes(value) {
  return new TextEncoder().encode(serialize(value));
}

/**
 * Bytes signed/verified for an event: canonical JSON of the event after
 * deleting its "signature" field, regardless of where it appears.
 */
export function signingBytes(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new CanonicalError('event must be a JSON object');
  }
  const reduced = {};
  for (const k of Object.keys(event)) {
    if (k !== 'signature') reduced[k] = event[k];
  }
  return canonicalBytes(reduced);
}
