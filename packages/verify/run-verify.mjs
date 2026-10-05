/**
 * verify 一次性入口（执行一次后以退出码结束）：
 *  1) 内核规则测试（node --test）
 *  2) 页面生产构建核对（vite build）
 *  3) 启动 HTTP 服务并冒烟：
 *       GET  /health
 *       GET  /api/health-path                 健康授权链必须授权
 *       POST /api/review（撤销复核样本）       先解锁维持授权、已见撤销后拒绝、
 *                                             并列独立委托不受误伤
 *  4) 关闭服务，按全部步骤结果输出退出码（0 成功 / 1 失败）。
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as ed from '@noble/ed25519';
import { signEvent, bytesToBase64 } from '@offline/core';
import { server, listen } from './server.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

const steps = [];
function record(name, ok, detail = '') {
  steps.push({ name, ok, detail });
  console.log(`${ok ? '✅' : '❌'} ${name}${detail ? ' — ' + detail : ''}`);
}

function run(cmd, args, label) {
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit' });
  record(label, r.status === 0, r.status === 0 ? '' : `退出码 ${r.status}`);
  return r.status === 0;
}

async function buildRevocationSample() {
  const mk = async (name) => {
    const sk = ed.utils.randomPrivateKey();
    return [name, { sk, pk: bytesToBase64(await ed.getPublicKeyAsync(sk)) }];
  };
  const [R, A, B] = await Promise.all([mk('root'), mk('A'), mk('B')]);
  const subjects = { root: R[1].pk, A: A[1].pk, B: B[1].pk };
  const priv = { root: R[1].sk, A: A[1].sk, B: B[1].sk };

  const mkEv = async (author, seq, seen, fields) => {
    const unsigned = { ...fields, author, seq, seen };
    return { ...unsigned, signature: await signEvent(unsigned, priv[author]) };
  };

  const events = [
    await mkEv('root', 1, {}, {
      kind: 'delegation', edgeId: 'e1', from: 'root', to: 'A', perms: ['unlock'],
    }),
    await mkEv('root', 2, {}, {
      kind: 'delegation', edgeId: 'e2', from: 'root', to: 'B', perms: ['unlock'],
    }),
    // u1：撤销前解锁，A 只见 root:1
    await mkEv('A', 1, { root: 1, A: 1 }, {
      kind: 'unlock', unlockId: 'u-before', requester: 'A', target: 'T',
    }),
    // 撤销 e1（不触及并列边 e2）
    await mkEv('root', 3, { root: 2, A: 1 }, { kind: 'revocation', edgeId: 'e1' }),
    // u2：A 已见撤销（root:3）→ 拒绝
    await mkEv('A', 2, { root: 3, A: 1 }, {
      kind: 'unlock', unlockId: 'u-after', requester: 'A', target: 'T',
    }),
    // u3：并列主体 B 的独立委托未受影响 → 授权
    await mkEv('B', 1, { root: 2, B: 1 }, {
      kind: 'unlock', unlockId: 'u-parallel', requester: 'B', target: 'T',
    }),
  ];
  return { subjects, root: 'root', events };
}

async function main() {
  console.log('── 1/4 规则测试 ──');
  run('npm', ['run', 'build:core'], '构建规则内核');
  const testsOk = run(process.execPath, ['--test', 'packages/core/test/'], '内核规则测试（node --test）');

  console.log('── 2/4 页面构建核对 ──');
  const buildOk = run('npm', ['run', 'build:web', '--silent'], 'Vite 生产构建页面');

  console.log('── 3/4 HTTP 冒烟 ──');
  let smokeOk = false;
  let port = 0;
  try {
    port = await listen(0);
    const base = `http://127.0.0.1:${port}`;

    const h = await fetch(`${base}/health`);
    const hb = await h.json();
    record('GET /health', h.status === 200 && hb.ok === true);

    const hp = await fetch(`${base}/api/health-path`);
    const hpj = await hp.json();
    const hv = hpj.review?.verdicts?.[0];
    record(
      'GET /api/health-path 健康链授权',
      hp.status === 200 && hv?.authorized === true &&
      Array.isArray(hv?.chain?.edges) && hv.chain.edges.length === 2 &&
      hpj.review.firstFailure === null,
      `链 ${hv?.chain?.edges?.join(' → ')}`,
    );

    const sample = await buildRevocationSample();
    const rv = await fetch(`${base}/api/review`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(sample),
    });
    const rvj = await rv.json();
    const verdicts = rvj.review?.verdicts ?? [];
    const byId = Object.fromEntries(verdicts.map((v) => [v.unlockId, v]));
    const revOk =
      rv.status === 200 &&
      rvj.review.firstFailure === null &&
      byId['u-before']?.authorized === true &&
      byId['u-after']?.authorized === false &&
      byId['u-after']?.evidence?.kind === 'unlock-no-chain' &&
      byId['u-after']?.evidence?.witness?.join('|').includes('e1') === true &&
      byId['u-parallel']?.authorized === true;
    record(
      'POST /api/review 撤销复核（不追溯/不漏判/不误伤并列）',
      revOk,
      `before=${byId['u-before']?.authorized} after=${byId['u-after']?.authorized} parallel=${byId['u-parallel']?.authorized}`,
    );

    const index = await fetch(`${base}/`);
    const indexHtml = await index.text();
    record('GET / 页面产物可服务', index.status === 200 && indexHtml.includes('离线委托'));

    smokeOk = h.ok && hp.ok && revOk && index.ok;
  } catch (e) {
    record('HTTP 冒烟', false, e.message);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  console.log('── 4/4 汇总 ──');
  const ok = testsOk && buildOk && smokeOk;
  console.log(ok ? '\nVERIFY PASS：规则测试、页面构建与 HTTP 冒烟全部通过。' : '\nVERIFY FAIL：见上方 ❌ 项。');
  process.exitCode = ok ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
