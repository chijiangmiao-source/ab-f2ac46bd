// Environment-independent standard Base64 codec (works in browser and Node).
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const DECODE = new Int16Array(256).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) DECODE[ALPHABET.charCodeAt(i)] = i;

export class Base64Error extends Error {}

/**
 * @param {string} input
 * @returns {Uint8Array}
 */
export function b64decode(input) {
  if (typeof input !== 'string') throw new Base64Error('Base64 value must be a string');
  const s = input.trim();
  if (s.length === 0) throw new Base64Error('empty Base64 value');
  let pad = 0;
  if (s.endsWith('==')) pad = 2;
  else if (s.endsWith('=')) pad = 1;
  const core = pad ? s.slice(0, s.length - pad) : s;
  if (core.length % 4 === 1) throw new Base64Error('invalid Base64 length');
  if (pad && s.length % 4 !== 0) throw new Base64Error('invalid Base64 padding');
  if (!/^[A-Za-z0-9+/]*$/.test(core)) throw new Base64Error('invalid Base64 character');

  const outLen = Math.floor((core.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let o = 0;
  for (let i = 0; i < core.length; i += 4) {
    const c0 = DECODE[core.charCodeAt(i)];
    const c1 = DECODE[core.charCodeAt(i + 1)];
    const has2 = i + 2 < core.length;
    const has3 = i + 3 < core.length;
    const c2 = has2 ? DECODE[core.charCodeAt(i + 2)] : 0;
    const c3 = has3 ? DECODE[core.charCodeAt(i + 3)] : 0;
    if ((c0 | c1 | c2 | c3) < 0) throw new Base64Error('invalid Base64 character');
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    out[o++] = (triple >> 16) & 0xff;
    if (has2) out[o++] = (triple >> 8) & 0xff;
    if (has3) out[o++] = triple & 0xff;
  }
  return out;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    s += ALPHABET[(triple >> 18) & 63];
    s += ALPHABET[(triple >> 12) & 63];
    s += i + 1 < bytes.length ? ALPHABET[(triple >> 6) & 63] : '=';
    s += i + 2 < bytes.length ? ALPHABET[triple & 63] : '=';
  }
  return s;
}
