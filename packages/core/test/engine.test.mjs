import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import { reviewRecord, validateRecordFile, signEvent, bytesToBase64, signingPayload } from '../dist/index.js';
import { makeSubjects, buildRecord, delegation as dl, revocation as rv, unlock as ul, signed } from './helpers.mjs';

const ALL = ['delegate', 'unlock', 'revoke'];

async function setup(names) {
  const { subjects, priv } = await makeSubjects(names);
  return { subjects, priv };
}

test('文件级约束：主体上限 8、事件上限 24、根必须已知', () => {
  assert.deepEqual(validateRecordFile({ subjects: {}, root: 'r', events: [] }).ok, false);
  const many = Object.fromEntries(Array.from({ length: 9 }, (_, i) => ['s' + i, 'x']));
  assert.ok(validateRecordFile({ subjects: many, root: 's0', events: [] }).errors.join().includes('8'));
  assert.ok(
    validateRecordFile({ subjects: { r: 'x' }, root: 'r', events: Array(25).fill({}) }).errors.join().includes('24'),
  );
  assert.equal(validateRecordFile({ subjects: { r: 'x' }, root: 'r', events: [] }).ok, true);
});

test('健康路径：根委托再委托/解锁，二级主体解锁给出规范链', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    ul('A', { unlockId: 'u1', requester: 'A', target: 'safe-1' }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure, null);
  assert.equal(r.verdicts.length, 1);
  assert.equal(r.verdicts[0].authorized, true);
  assert.deepEqual(r.verdicts[0].chain.edges, ['e1']);
  assert.deepEqual(r.verdicts[0].chain.path, ['root', 'A']);
  assert.ok(r.verdicts[0].chain.perms.includes('unlock'));
});

test('权限只能缩小：缩小合法，放大定位为越权记录', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const ok = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock', 'delegate'] }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ['unlock'] }),
  ]);
  assert.equal((await reviewRecord(ok)).firstFailure, null);

  // A 持有 delegate 但不持有 revoke：放大权限集合
  const bad = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock', 'delegate'] }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ['revoke'] }),
  ]);
  const r = await reviewRecord(bad);
  assert.equal(r.firstFailure.kind, 'privilege-escalation');
  assert.equal(r.firstFailure.recordIndex, 1);
  assert.deepEqual(r.firstFailure.granted, ['revoke']);
});

test('无再委托权限的主体签发委托：定位 not-delegator', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'] }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ['unlock'] }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'not-delegator');
  assert.equal(r.firstFailure.recordIndex, 1);
});

test('成环定位首个成环记录并给出环上边', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ALL }),
    dl('B', { edgeId: 'e3', from: 'B', to: 'A', perms: ALL }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'cycle');
  assert.equal(r.firstFailure.recordIndex, 2);
  assert.ok(r.firstFailure.cycle.includes('e3'));
});

test('自环即一环', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'A', perms: ALL }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'cycle');
  assert.equal(r.firstFailure.recordIndex, 1);
});

test('伪造签名定位首个记录', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('root', { edgeId: 'e2', from: 'root', to: 'A', perms: ['unlock'] }),
  ]);
  rec.events[1].signature = rec.events[0].signature; // 复用他事件签名
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'bad-signature');
  assert.equal(r.firstFailure.recordIndex, 1);
});

test('未知作者即未知公钥', async () => {
  const { subjects } = await setup(['root', 'A']);
  const zeros = 'A'.repeat(86) + '='; // 64 字节零签名的 Base64 形式占位
  const rec = {
    subjects,
    root: 'root',
    events: [
      { kind: 'revocation', author: 'ghost', seq: 1, seen: {}, edgeId: 'e1', signature: zeros },
    ],
  };
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'unknown-key');
  assert.equal(r.firstFailure.recordIndex, 0);
});

test('计数跳跃：期望 2 实际 3', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const e1 = await signed(priv, {
    ...dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }, {}),
    seq: 1,
  });
  const e2 = await signed(priv, {
    ...dl('root', { edgeId: 'e2', from: 'root', to: 'A', perms: ['unlock'] }, { root: 1 }),
    seq: 3,
  });
  const r = await reviewRecord({ subjects, root: 'root', events: [e1, e2] });
  assert.equal(r.firstFailure.kind, 'seq-jump');
  assert.equal(r.firstFailure.recordIndex, 1);
  assert.equal(r.firstFailure.expected, 2);
  assert.equal(r.firstFailure.actual, 3);
});

test('未知前驱：seen 引用尚未接收的计数', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const e0 = await signed(priv, dl('A', { edgeId: 'e1', from: 'A', to: 'A', perms: ALL }, { root: 1 }));
  e0.seq = 1;
  // 重新签名 seq=1 版本
  const e0s = await signed(priv, { ...e0, seq: 1 });
  const rec = { subjects, root: 'root', events: [e0s] };
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'unknown-predecessor');
  assert.equal(r.firstFailure.subject, 'root');
  assert.equal(r.firstFailure.referenced, 1);
  assert.equal(r.firstFailure.known, 0);
});

test('seen 引用未知主体', async () => {
  const { subjects, priv } = await setup(['root']);
  const ev = await signed(priv, {
    kind: 'revocation', author: 'root', seq: 1, seen: { stranger: 1 }, edgeId: 'x',
  });
  const r = await reviewRecord({ subjects, root: 'root', events: [ev] });
  assert.equal(r.firstFailure.kind, 'unknown-predecessor');
  assert.equal(r.firstFailure.subject, 'stranger');
});

test('撤销切断被撤销边及其唯一后代，但不误伤并列独立委托', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B', 'C', 'D']);
  // root→A (ALL), root→C (ALL); A→B(unlock); C→D(unlock)；撤销 e1 后 B 失效、D 存活
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('root', { edgeId: 'e3', from: 'root', to: 'C', perms: ALL }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ['unlock'] }),
    dl('C', { edgeId: 'e4', from: 'C', to: 'D', perms: ['unlock'] }),
    rv('root', 'e1'),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure, null);
  const last = r.snapshots[4];
  const live = last.activeEdges.map((e) => e.edgeId).sort();
  assert.deepEqual(live, ['e3', 'e4']);
  assert.equal(last.visibleRevocations[0].edgeId, 'e1');
});

test('后代另有并列路径时撤销不切断它', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  // root→A(unlock,delegate), root→B(unlock), A→B(delegate)；撤销 e1 后
  // B 仍经 e2 直接持有 unlock。
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('root', { edgeId: 'e2', from: 'root', to: 'B', perms: ['unlock'] }),
    dl('A', { edgeId: 'e3', from: 'A', to: 'B', perms: ['unlock'] }),
    rv('root', 'e1'),
    ul('B', { unlockId: 'u1', requester: 'B', target: 't' }, { root: 2 }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure, null);
  assert.equal(r.verdicts[0].authorized, true);
  assert.deepEqual(r.verdicts[0].chain.edges, ['e2']);
});

test('后来抵达的撤销不追溯否决先前解锁；其后的解锁受已见撤销约束', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'] }),
    // u1 在撤销之前，seen 只见 e1
    ul('A', { unlockId: 'u1', requester: 'A', target: 't1' }, { root: 1, A: 1 }),
    rv('root', 'e1'),
    // u2 已见撤销（root:2 即撤销记录）→ 必须拒绝
    ul('A', { unlockId: 'u2', requester: 'A', target: 't2' }, { root: 2, A: 1 }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure, null);
  assert.equal(r.verdicts[0].authorized, true, '先前解锁维持授权');
  assert.equal(r.snapshots[1].verdict.authorized, true);
  assert.equal(r.verdicts[1].authorized, false, '已见撤销后解锁被拒绝');
  assert.equal(r.verdicts[1].evidence.kind, 'unlock-no-chain');
  assert.ok(r.verdicts[1].evidence.witness.join('|').includes('e1'));
});

test('物理已抵达但不在 seen 中的撤销对请求不可见：授权成立', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'] }),
    rv('root', 'e1'),
    // A 的向量停留在 root:1（只见委托，未见撤销）
    ul('A', { unlockId: 'u1', requester: 'A', target: 't' }, { root: 1, A: 0 }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure, null);
  assert.equal(r.verdicts[0].authorized, true);
});

test('seen 中缺少委托边作者计数：该边不可用于链', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'] }),
    // A 只见 root:0 → e1 对其不可见
    ul('A', { unlockId: 'u1', requester: 'A', target: 't' }, { root: 0, A: 0 }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.verdicts[0].authorized, false);
  assert.ok(r.verdicts[0].evidence.witness.join().includes('未见任何委托边'));
});

test('无授权主体的解锁给出最短失效证据', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'] }),
    ul('B', { unlockId: 'u1', requester: 'B', target: 't' }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.verdicts[0].authorized, false);
  assert.ok(r.verdicts[0].evidence.witness.join().includes('root'));
});

test('非下游/无 revoke 权限主体撤销被拒', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('root', { edgeId: 'e2', from: 'root', to: 'B', perms: ['unlock'] }),
    // A 虽持有 revoke，但 e2 不在 A 的下游
    rv('A', 'e2'),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'revoke-not-reachable');
  assert.equal(r.firstFailure.recordIndex, 2);
});

test('下游持有者可撤销下游边；重复撤销被拒', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ['unlock'] }),
    rv('A', 'e2'),
    rv('root', 'e2'),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'revoke-not-reachable');
  assert.equal(r.firstFailure.recordIndex, 3);
});

test('撤销未知边被定位', async () => {
  const { subjects, priv } = await setup(['root']);
  const rec = await buildRecord(subjects, priv, 'root', [rv('root', 'nope')]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'revoke-unknown');
});

test('重复边编号被定位', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'] }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'duplicate-edge');
  assert.equal(r.firstFailure.recordIndex, 1);
});

test('解锁作者与请求者不一致被定位', async () => {
  const { subjects, priv } = await setup(['root', 'A']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    ul('A', { unlockId: 'u1', requester: 'root', target: 't' }, { root: 1 }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.firstFailure.kind, 'unlock-bad-author');
});

test('三级链：交集权限随链缩小，缺 unlock 的末段拒绝', async () => {
  const { subjects, priv } = await setup(['root', 'A', 'B']);
  const rec = await buildRecord(subjects, priv, 'root', [
    dl('root', { edgeId: 'e1', from: 'root', to: 'A', perms: ALL }),
    dl('A', { edgeId: 'e2', from: 'A', to: 'B', perms: ['delegate'] }),
    ul('B', { unlockId: 'u1', requester: 'B', target: 't' }),
  ]);
  const r = await reviewRecord(rec);
  assert.equal(r.verdicts[0].authorized, false);
});

test('规范序列化：签名载荷按键名排序且排除 signature/recordIndex', async () => {
  const ev = {
    kind: 'unlock',
    author: 'A',
    seq: 2,
    seen: { root: 1 },
    unlockId: 'u',
    requester: 'A',
    target: 't',
    recordIndex: 5,
    signature: 'zzz',
  };
  const payload = new TextDecoder().decode(signingPayload(ev));
  assert.equal(
    payload,
    '{"author":"A","kind":"unlock","requester":"A","seen":{"root":1},"seq":2,"target":"t","unlockId":"u"}',
  );
});

test('端到端签名兼容：signEvent 产物可通过验签后进入语义判定', async () => {
  const sk = ed.utils.randomPrivateKey();
  const pub = bytesToBase64(await ed.getPublicKeyAsync(sk));
  const ev = { kind: 'revocation', author: 'r', seq: 1, seen: {}, edgeId: 'nope' };
  const signature = await signEvent(ev, sk);
  const r = await reviewRecord({ subjects: { r: pub }, root: 'r', events: [{ ...ev, signature }] });
  assert.equal(r.firstFailure.kind, 'revoke-unknown'); // 签名有效，语义失败在后
});
