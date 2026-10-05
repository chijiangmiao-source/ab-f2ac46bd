/**
 * verify 用 HTTP 服务：
 *  - GET  /health            健康检查
 *  - GET  /                  复核页面（packages/web/dist 静态产物）
 *  - POST /api/review        接收记录 JSON，返回因果复核结果
 *  - GET  /api/health-path   返回一段内置健康授权链的复核结果（冒烟用）
 */
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize } from 'node:path';
import * as ed from '@noble/ed25519';
import { reviewRecord, validateRecordFile, signEvent, bytesToBase64 } from '@offline/core';

const here = dirname(fileURLToPath(import.meta.url));
const webDist = join(here, '..', 'web', 'dist');
const PORT = Number(process.env.PORT ?? 8088);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

async function readBody(req, max = 1_000_000) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > max) throw new Error('请求体过大');
    chunks.push(c);
  }
  return Buffer.concat(chunks).toString('utf8');
}

const json = (res, code, obj) => {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
};

/** 构造内置健康路径记录：root→sat→ops 三级委托，ops 解锁成功。 */
export async function buildHealthPathRecord() {
  const mk = async (name) => {
    const sk = ed.utils.randomPrivateKey();
    return [name, { sk, pk: bytesToBase64(await ed.getPublicKeyAsync(sk)) }];
  };
  const [root, sat, ops] = await Promise.all([mk('root'), mk('sat'), mk('ops')]);
  const subjects = { root: root[1].pk, sat: sat[1].pk, ops: ops[1].pk };
  const priv = { root: root[1].sk, sat: sat[1].sk, ops: ops[1].sk };
  const ALL = ['delegate', 'unlock', 'revoke'];

  const mkEv = async (author, seq, seen, fields) => {
    const unsigned = { ...fields, author, seq, seen };
    return { ...unsigned, signature: await signEvent(unsigned, priv[author]) };
  };

  const events = [
    await mkEv('root', 1, {}, {
      kind: 'delegation', edgeId: 'e-root-sat', from: 'root', to: 'sat', perms: ALL,
    }),
    await mkEv('sat', 1, { root: 1 }, {
      kind: 'delegation', edgeId: 'e-sat-ops', from: 'sat', to: 'ops', perms: ['unlock'],
    }),
    await mkEv('ops', 1, { root: 1, sat: 1 }, {
      kind: 'unlock', unlockId: 'u-health', requester: 'ops', target: 'PAYLOAD-BAY',
    }),
  ];
  return { subjects, root: 'root', events };
}

export const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    return json(res, 200, { ok: true, service: 'offline-delegation-verify' });
  }

  if (req.method === 'GET' && url.pathname === '/api/health-path') {
    const rec = await buildHealthPathRecord();
    const review = await reviewRecord(rec);
    return json(res, 200, { record: rec, review });
  }

  if (req.method === 'POST' && url.pathname === '/api/review') {
    let parsed;
    try {
      parsed = JSON.parse(await readBody(req));
    } catch (e) {
      return json(res, 400, { error: 'JSON 解析失败', detail: e.message });
    }
    const v = validateRecordFile(parsed);
    if (!v.ok) return json(res, 422, { error: '记录不满足文件约束', details: v.errors });
    const review = await reviewRecord(parsed);
    return json(res, 200, { review });
  }

  // 静态页面
  if (req.method === 'GET') {
    let rel = url.pathname === '/' ? '/index.html' : url.pathname;
    rel = normalize(rel).replace(/^(\.\.[/\\])+/, '');
    const file = join(webDist, rel);
    if (!file.startsWith(webDist) || !existsSync(file)) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('not found');
    }
    try {
      const data = await readFile(file);
      res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' });
      return res.end(data);
    } catch {
      res.writeHead(404);
      return res.end('not found');
    }
  }

  res.writeHead(405);
  res.end('method not allowed');
});

export function listen(port = PORT) {
  return new Promise((resolve) => {
    server.listen(port, '0.0.0.0', () => resolve(server.address().port));
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const p = await listen();
  console.log(`verify server listening on http://0.0.0.0:${p}`);
}
