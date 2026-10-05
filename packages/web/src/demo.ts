/**
 * 浏览器端示例记录生成器：全部在本地用 Ed25519 生成密钥并签名，
 * 覆盖委托、再委托、解锁、撤销（含后代切断与并列独立委托不受误伤）。
 */
import * as ed from '@noble/ed25519';
import { signEvent, bytesToBase64 } from '@offline/core';
import type { RecordFile } from '@offline/core';

type Draft = Record<string, unknown>;

export interface DemoBundle {
  record: RecordFile;
  /** 示例私钥（仅演示用）：主体标识 → Base64 私钥。 */
  privateKeys: Record<string, string>;
}

export async function buildDemoRecord(): Promise<DemoBundle> {
  const names = ['root', 'sat', 'ops', 'peer'];
  const subjects: Record<string, string> = {};
  const priv: Record<string, Uint8Array> = {};
  for (const n of names) {
    const sk = ed.utils.randomPrivateKey();
    priv[n] = sk;
    subjects[n] = bytesToBase64(await ed.getPublicKeyAsync(sk));
  }

  const drafts: Draft[] = [
    {
      kind: 'delegation', author: 'root', edgeId: 'e-root-sat', from: 'root', to: 'sat',
      perms: ['delegate', 'unlock', 'revoke'],
    },
    {
      kind: 'delegation', author: 'root', edgeId: 'e-root-peer', from: 'root', to: 'peer',
      perms: ['unlock'],
    },
    {
      kind: 'delegation', author: 'sat', edgeId: 'e-sat-ops', from: 'sat', to: 'ops',
      perms: ['unlock'],
    },
    {
      kind: 'unlock', author: 'ops', unlockId: 'u-ops-1', requester: 'ops', target: 'SOLAR-PANEL-A',
    },
    { kind: 'revocation', author: 'sat', edgeId: 'e-sat-ops' },
    {
      kind: 'unlock', author: 'ops', unlockId: 'u-ops-2', requester: 'ops', target: 'SOLAR-PANEL-A',
    },
    {
      kind: 'unlock', author: 'peer', unlockId: 'u-peer-1', requester: 'peer', target: 'SOLAR-PANEL-B',
    },
    { kind: 'revocation', author: 'root', edgeId: 'e-root-sat' },
  ];

  const maxSeq: Record<string, number> = Object.fromEntries(names.map((n) => [n, 0]));
  const events: Draft[] = [];
  for (const d of drafts) {
    const author = String(d.author);
    maxSeq[author] += 1;
    const unsigned = { ...d, seq: maxSeq[author], seen: { ...maxSeq } };
    const signature = await signEvent(unsigned, priv[author]);
    events.push({ ...unsigned, signature });
  }

  const privateKeys: Record<string, string> = {};
  for (const n of names) privateKeys[n] = bytesToBase64(priv[n]);

  return { record: { subjects, root: 'root', events: events as unknown as RecordFile['events'] }, privateKeys };
}
