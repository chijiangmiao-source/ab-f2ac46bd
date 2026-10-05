/**
 * 测试夹具：生成主体密钥、按规则签名事件。
 */
import * as ed from '@noble/ed25519';
import { signEvent, bytesToBase64 } from '../dist/signing.js';

export async function makeSubjects(names) {
  const subjects = {};
  const priv = {};
  for (const name of names) {
    const sk = ed.utils.randomPrivateKey();
    subjects[name] = bytesToBase64(await ed.getPublicKeyAsync(sk));
    priv[name] = sk;
  }
  return { subjects, priv };
}

let counter = 0;

/** 以 author 私钥签名事件（自动剥离既有 signature）。 */
export async function signed(priv, ev) {
  const { signature, ...unsigned } = ev;
  return { ...unsigned, signature: await signEvent(unsigned, priv[ev.author]) };
}

/** 便捷构造器：seq 与 seen 由 buildRecord 按顺序自动补全。 */
export function delegation(author, { edgeId, from, to, perms }, seen) {
  return { kind: 'delegation', author, seq: 0, seen: seen ?? {}, edgeId, from, to, perms, signature: '' };
}
export function revocation(author, edgeId, seen) {
  return { kind: 'revocation', author, seq: 0, seen: seen ?? {}, edgeId, signature: '' };
}
export function unlock(author, { unlockId, requester, target }, seen) {
  return { kind: 'unlock', author, seq: 0, seen: seen ?? {}, unlockId, requester, target, signature: '' };
}

/**
 * 将未签名事件按作者自动编号 seq（从 1 起），seen 可省略——省略时自动填该
 * 作者在本事件之前已知的全局计数（测试用“全知”视图）。需要精确向量的用例
 * 自行提供 seen。
 */
export async function buildRecord(subjects, priv, root, drafts) {
  const maxSeq = Object.fromEntries(Object.keys(subjects).map((k) => [k, 0]));
  const events = [];
  for (const d of drafts) {
    const ev = { ...d };
    ev.seq = (maxSeq[ev.author] ?? 0) + 1;
    maxSeq[ev.author] = ev.seq;
    if (ev.seen && Object.keys(ev.seen).length === 0 && ev.seen.__auto !== true) {
      ev.seen = { ...maxSeq, [ev.author]: ev.seq };
    }
    delete ev.seen.__auto;
    events.push(await signed(priv, ev));
  }
  return { subjects: { ...subjects }, root, events };
}

export function v(obj) {
  return obj;
}

export function freshId(prefix) {
  counter += 1;
  return `${prefix}-${counter}`;
}
