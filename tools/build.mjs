// Bundle the browser page with esbuild and copy static assets into web-dist/.
import { build } from 'esbuild';
import { mkdir, rm, cp, readFile, writeFile, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'web-dist');

export async function buildPage({ log = true } = {}) {
  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });

  await build({
    entryPoints: [join(root, 'web', 'app.js')],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2020'],
    outfile: join(dist, 'app.js'),
    legalComments: 'none',
    logLevel: 'warning'
  });

  await cp(join(root, 'web', 'index.html'), join(dist, 'index.html'));
  await cp(join(root, 'web', 'styles.css'), join(dist, 'styles.css'));

  const bundleStat = await stat(join(dist, 'app.js'));
  if (log) console.log(`[build] web-dist ready (app.js ${bundleStat.size} bytes)`);
  return dist;
}

// Quick integrity self-check of the produced bundle: it must contain the
// bundled core modules and reference the served assets.
export async function checkBuildArtifacts(dist) {
  const js = await readFile(join(dist, 'app.js'), 'utf8');
  const html = await readFile(join(dist, 'index.html'), 'utf8');
  const problems = [];
  if (!js.includes('causal past')) problems.push('bundle is missing model module');
  if (!js.includes('Ed25519')) problems.push('bundle is missing ed25519 wrapper');
  if (!html.includes('/app.js')) problems.push('html does not reference /app.js');
  if (!html.includes('/styles.css')) problems.push('html does not reference /styles.css');
  return problems;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const d = await buildPage();
  const problems = await checkBuildArtifacts(d);
  if (problems.length) {
    console.error('[build] artifact check failed:\n - ' + problems.join('\n - '));
    process.exit(1);
  }
  console.log('[build] artifact check passed');
}
