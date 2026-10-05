// Static page + review API server. Used by the one-shot verify job and
// can also be run persistently with `npm run server`.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, normalize } from 'node:path';
import { buildScenario } from '../core/demo.js';
import { loadSubjects, evaluateLog } from '../core/model.js';

export function createApp(distDir) {
  const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8'
  };

  async function reviewScenario(name) {
    const doc = await buildScenario(name);
    const dir = loadSubjects(doc);
    if (dir.error) return { ok: false, stage: 'subjects', error: dir.error };
    const result = await evaluateLog(dir, doc.events);
    if (!result.ok) return { ok: false, stage: 'events', error: result.error };
    return { ok: true, scenario: name, document: doc, result };
  }

  function sendJson(res, status, payload) {
    const body = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': TYPES['.json'], 'content-length': Buffer.byteLength(body) });
    res.end(body);
  }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      const path = url.pathname;

      if (path === '/healthz') {
        sendJson(res, 200, { status: 'ok' });
        return;
      }

      const apiMatch = path.match(/^\/api\/review\/([a-z-]+)$/);
      if (apiMatch) {
        const name = apiMatch[1];
        try {
          const payload = await reviewScenario(name);
          sendJson(res, payload.ok ? 200 : 422, payload);
        } catch (e) {
          sendJson(res, 500, { ok: false, error: String(e && e.message ? e.message : e) });
        }
        return;
      }

      let rel = path === '/' ? '/index.html' : path;
      const file = normalize(join(distDir, rel));
      if (!file.startsWith(distDir)) {
        res.writeHead(403); res.end('forbidden'); return;
      }
      const data = await readFile(file);
      const ext = file.slice(file.lastIndexOf('.'));
      res.writeHead(200, { 'content-type': TYPES[ext] || 'application/octet-stream' });
      res.end(data);
    } catch (e) {
      if (e && e.code === 'ENOENT') {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('not found');
      } else {
        res.writeHead(500); res.end('server error');
      }
    }
  });
}

export async function startServer(distDir, port = 0, host = '127.0.0.1') {
  const app = createApp(distDir);
  await new Promise((resolve) => app.listen(port, host, resolve));
  const address = app.address();
  return { app, port: address.port, host };
}
