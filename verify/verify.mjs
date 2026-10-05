// One-shot verification job:
//   1. rule tests (node tests/model.test.mjs)
//   2. page build + artifact checks
//   3. HTTP smoke against health, revocation review and the healthy path
// Runs exactly once and exits with code 0 (success) or 1 (failure).
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildPage, checkBuildArtifacts } from '../tools/build.mjs';
import { startServer } from './server.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function run(cmd, args) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: root, stdio: 'inherit' });
    child.on('exit', (code) => resolve(code || 0));
  });
}

async function httpJson(base, path) {
  const res = await fetch(base + path);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* non-json route */ }
  return { status: res.status, json, text, headers: res.headers };
}

function assert(cond, message, failures) {
  if (cond) {
    console.log('   ✓', message);
  } else {
    console.log('   ✗', message);
    failures.push(message);
  }
}

function verdicts(result) {
  return result.records.filter((r) => r.verdict).map((r) => ({ ref: r.ref, ...r.verdict }));
}

async function main() {
  const failures = [];
  console.log('== 1/3 规则测试 ==');
  const testCode = await run(process.execPath, ['tests/model.test.mjs']);
  assert(testCode === 0, `规则测试退出码为 0（实际 ${testCode}）`, failures);
  if (testCode !== 0) {
    console.error('\nVERIFY FAILED at rule tests');
    process.exit(1);
  }

  console.log('== 2/3 页面构建 ==');
  const dist = await buildPage();
  const artifactProblems = await checkBuildArtifacts(dist);
  assert(artifactProblems.length === 0, '构建产物完整（' + (artifactProblems.join('; ') || 'index.html / styles.css / app.js') + '）', failures);
  const pageCode = await run(process.execPath, ['tests/page.test.mjs']);
  assert(pageCode === 0, `页面渲染冒烟（jsdom 单步/复核/场景切换）退出码为 0（实际 ${pageCode}）`, failures);
  if (pageCode !== 0) {
    console.error('\nVERIFY FAILED at page smoke');
    process.exit(1);
  }

  console.log('== 3/3 HTTP 冒烟（复核结果） ==');
  const port = Number(process.env.PORT) || 0;
  const { app, port: actualPort } = await startServer(dist, port);
  const base = `http://127.0.0.1:${actualPort}`;
  console.log(`   服务已启动：${base}`);
  try {
    const health = await httpJson(base, '/healthz');
    assert(health.status === 200 && health.json && health.json.status === 'ok', 'GET /healthz 返回 200 ok', failures);

    for (const asset of ['/', '/styles.css', '/app.js']) {
      const r = await httpJson(base, asset);
      assert(r.status === 200 && r.text.length > 0, `静态资源 ${asset} 返回 200 且非空`, failures);
    }
    const escape = await httpJson(base, '/..%2fpackage.json');
    assert(escape.status === 404 || escape.status === 403, '路径越权访问不泄露 dist 之外的文件（' + escape.status + '）', failures);

    // Revocation review: the crux scenario.
    const rev = await httpJson(base, '/api/review/revoke');
    assert(rev.status === 200 && rev.json.ok, 'GET /api/review/revoke 返回 200', failures);
    if (rev.json.ok) {
      const vs = verdicts(rev.json.result);
      const decisions = vs.map((v) => v.decision);
      assert(decisions[0] === 'AUTHORIZED', '撤销到达前的解锁 A#1 保持 AUTHORIZED（后到撤销不溯及既往）', failures);
      assert(decisions[1] === 'DENIED', '见到撤销后的 A#2 被拒绝', failures);
      const deniedA = vs[1];
      assert(deniedA.evidence && deniedA.evidence.type === 'REVOKED_EDGE' && deniedA.evidence.edge.id === 'root#0',
        'A#2 的最短失效证据定位到被撤销边 root#0', failures);
      assert(decisions[2] === 'DENIED', '后代 C#0 经同一切断边被拒绝', failures);
      const laterC = vs[3];
      assert(decisions[3] === 'AUTHORIZED' && laterC.chain && laterC.chain.length === 1 && laterC.chain[0].id === 'root#2',
        '并列独立委托 root#2 恢复 C#1 授权（撤销不误伤并列边）', failures);
      assert(rev.json.result.firstInvalidRecord === null, '撤销复核记录无任何无效记录', failures);
    }

    // Healthy path.
    const healthy = await httpJson(base, '/api/review/healthy');
    assert(healthy.status === 200 && healthy.json.ok, 'GET /api/review/healthy 返回 200', failures);
    if (healthy.json.ok) {
      assert(healthy.json.result.firstInvalidRecord === null, '健康路径无无效记录', failures);
      const vs = verdicts(healthy.json.result);
      assert(vs.length === 2 && vs.every((v) => v.decision === 'AUTHORIZED'), '健康路径全部解锁裁决 AUTHORIZED', failures);
      assert(vs[0].chain && vs[0].chain.length === 2 && vs[0].chain[1].rights.includes('UNLOCK'),
        'C 的规范授权链为两跳且末边携带 UNLOCK: ' + (vs[0] && vs[0].chain.map((e) => e.id).join(' -> ')), failures);
    }

    // Attack samples stay correctly classified over HTTP.
    const forgery = await httpJson(base, '/api/review/forgery');
    assert(forgery.json.ok && forgery.json.result.firstInvalidRecord === 0,
      '伪造签名样本首个无效记录定位在第 1 条', failures);
    const skip = await httpJson(base, '/api/review/counter-skip');
    assert(skip.json.ok && skip.json.result.firstInvalidRecord === 1,
      '计数跳跃样本首个无效记录定位在第 2 条', failures);
  } catch (e) {
    assert(false, 'HTTP 冒烟发生异常：' + (e && e.stack ? e.stack : e), failures);
  } finally {
    await new Promise((resolve) => app.close(resolve));
  }

  console.log('');
  if (failures.length) {
    console.error(`VERIFY FAILED：${failures.length} 项断言失败`);
    process.exit(1);
  }
  console.log('VERIFY OK：规则测试、页面构建与 HTTP 冒烟（撤销复核 + 健康路径）全部通过');
  process.exit(0);
}

main();
