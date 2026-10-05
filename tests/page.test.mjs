// Page smoke: load the built bundle into jsdom, let the auto-loaded
// healthy scenario render, then drive the UI (scenario switch, step
// back/review) and assert the DOM reflects the verdicts.
import { JSDOM } from 'jsdom';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'web-dist');

const html = await readFile(join(dist, 'index.html'), 'utf8');
const dom = new JSDOM(html, {
  url: 'http://review.local/',
  runScripts: 'dangerously',
  resources: 'usable',
  pretendToBeVisual: true
});
const { window } = dom;
// jsdom has no layout; silence not-implemented noise for range APIs.
window.HTMLInputElement.prototype.scrollIntoView = () => {};

// jsdom may lack crypto.subtle; wire Node's webcrypto onto the window
// before bundle evaluation, because core/crypto.js reads it at module load.
if (!window.crypto || !window.crypto.subtle) {
  Object.defineProperty(window, 'crypto', { value: globalThis.crypto, configurable: true });
}

const bundle = await readFile(join(dist, 'app.js'), 'utf8');
window.eval(bundle);

function fire(name) {
  window.document.querySelector(name).dispatchEvent(new window.Event('click', { bubbles: true }));
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

window.document.dispatchEvent(new window.Event('DOMContentLoaded'));

let failures = 0;
function check(cond, msg) {
  console.log(cond ? '  ✓ ' + msg : '  ✗ ' + msg);
  if (!cond) failures++;
}

// Wait for the auto-loaded healthy scenario (async Ed25519 signing).
for (let i = 0; i < 100; i++) {
  await sleep(50);
  if (window.document.querySelectorAll('.record').length > 0) break;
}
await sleep(100);

const cards = window.document.querySelectorAll('.record');
check(cards.length === 6, `健康场景渲染 6 张记录卡（实际 ${cards.length}）`);
const badges = [...window.document.querySelectorAll('.record .pill')].map((n) => n.textContent);
check(badges.some((t) => t.includes('解锁：授权')), '页面显示「解锁：授权」裁决');
check(window.document.body.textContent.includes('root#0'), '页面包含规范授权链边 id');

// Step back to a prefix, then review the whole log.
fire('#btnPrev'); fire('#btnPrev');
await sleep(50);
check(window.document.querySelectorAll('.record').length === 4, '单步回退到前 4 条记录前缀');
fire('#btnReview');
await sleep(50);
check(window.document.querySelectorAll('.record').length === 6, '直接复核整段恢复全部 6 条记录');

// Switch to the revocation scenario through the UI.
window.document.querySelector('#scenario').value = 'revoke';
fire('#btnSample');
for (let i = 0; i < 100; i++) {
  await sleep(50);
  const txt = window.document.body.textContent;
  if (txt.includes('解锁：拒绝')) break;
}
await sleep(100);
const text = window.document.body.textContent;
check(text.includes('后到的撤销不溯及既往') || text.includes('无可见撤销'), '页面标注撤销因果语义');
check(text.includes('解锁：拒绝') && text.includes('解锁：授权'), '撤销场景同时呈现拒绝与授权裁决');
check(text.includes('root#2'), '并列独立委托 root#2 出现在授权链中');

// Attack scenario: forged signature pinned to record 1.
window.document.querySelector('#scenario').value = 'forgery';
fire('#btnSample');
for (let i = 0; i < 100; i++) {
  await sleep(50);
  if (window.document.body.textContent.includes('首个无效记录')) break;
}
check(window.document.body.textContent.includes('首个无效记录'), '伪造签名场景页面标注首个无效记录');
check(window.document.querySelectorAll('.record.invalid').length >= 1, '无效记录卡片有错误样式');

window.close();
console.log(failures ? `\npage smoke: ${failures} failed` : '\npage smoke: all passed');
process.exit(failures ? 1 : 0);
