/**
 * 签名与规范序列化。
 *
 * 签名覆盖：除 `signature` 字段外、按字段名（UTF-16 码元序，即 JS 默认排序）
 * 递归排序后序列化的 UTF-8 JSON。签名与公钥均为 Base64（标准 Base64，含填充）。
 */
import * as ed from '@noble/ed25519';
export function base64ToBytes(b64) {
    const clean = b64.trim();
    if (clean.length === 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) {
        throw new Error(`非法 Base64: "${b64.slice(0, 24)}…"`);
    }
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
export function bytesToBase64(bytes) {
    let bin = '';
    for (const b of bytes)
        bin += String.fromCharCode(b);
    return btoa(bin);
}
function stableStringify(value) {
    if (value === null || typeof value !== 'object') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return '[' + value.map(stableStringify).join(',') + ']';
    }
    const keys = Object.keys(value).sort();
    const parts = keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k]));
    return '{' + parts.join(',') + '}';
}
/** 返回用于签名/验签的规范字节（去掉 signature 字段，键名排序）。 */
export function signingPayload(event) {
    const clone = { ...event };
    delete clone.signature;
    // recordIndex 是接收方追加的元数据，不参与作者签名。
    delete clone.recordIndex;
    return new TextEncoder().encode(stableStringify(clone));
}
export async function verifySignature(event, subjects) {
    const author = String(event.author ?? '');
    const pubB64 = subjects[author];
    if (pubB64 === undefined)
        return { ok: false, reason: 'unknown-key' };
    let pub;
    let sig;
    try {
        pub = base64ToBytes(pubB64);
    }
    catch {
        return { ok: false, reason: 'bad-key-encoding' };
    }
    if (pub.length !== 32)
        return { ok: false, reason: 'bad-key-encoding' };
    try {
        sig = base64ToBytes(String(event.signature ?? ''));
    }
    catch {
        return { ok: false, reason: 'bad-signature-encoding' };
    }
    if (sig.length !== 64)
        return { ok: false, reason: 'bad-signature' };
    try {
        const ok = await ed.verifyAsync(sig, signingPayload(event), pub);
        return ok ? { ok: true } : { ok: false, reason: 'bad-signature' };
    }
    catch {
        return { ok: false, reason: 'bad-signature' };
    }
}
/** 供测试/示例生成签名：私钥为 32 字节。 */
export async function signEvent(event, privateKey) {
    const sig = await ed.signAsync(signingPayload(event), privateKey);
    return bytesToBase64(sig);
}
