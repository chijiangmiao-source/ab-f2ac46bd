// Persistent entry point: build the page once, then serve it.
import { buildPage } from '../tools/build.mjs';
import { startServer } from './server.mjs';

const dist = await buildPage();
const port = Number(process.env.PORT) || 8080;
const host = process.env.HOST || '0.0.0.0';
const { actualPort } = await new Promise((resolve) => {
  startServer(dist, port, host).then((s) => resolve({ actualPort: s.port }));
});
console.log(`review page listening on http://${host}:${actualPort}`);
