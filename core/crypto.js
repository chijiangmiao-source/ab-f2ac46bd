// Ed25519 wrapper around @noble/ed25519. The library is hash-agnostic:
// we wire SHA-512 to the platform WebCrypto subtle digest, which exists
// both in browsers and in Node >= 18 as globalThis.crypto.
import * as ed from '@noble/ed25519';

function concatBytes(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

const subtle = globalThis.crypto && globalThis.crypto.subtle;
if (!subtle) throw new Error('WebCrypto subtle API is required');

ed.utils.sha512 = async (...messages) => {
  const data = messages.length === 1 ? messages[0] : concatBytes(messages);
  return new Uint8Array(await subtle.digest('SHA-512', data));
};
ed.utils.randomBytes = (length = 32) => {
  const out = new Uint8Array(length);
  globalThis.crypto.getRandomValues(out);
  return out;
};

export const KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;

/** @returns {Promise<Uint8Array>} 32-byte private seed */
export function generatePrivateKey() {
  return ed.utils.randomPrivateKey();
}

/** @param {Uint8Array} privateKey @returns {Promise<Uint8Array>} 32-byte public key */
export function getPublicKey(privateKey) {
  return ed.getPublicKey(privateKey);
}

/** @returns {Promise<Uint8Array>} 64-byte signature */
export function sign(message, privateKey) {
  return ed.sign(message, privateKey);
}

/** @returns {Promise<boolean>} */
export async function verify(signature, message, publicKey) {
  try {
    return await ed.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
