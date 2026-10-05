import { reviewRecord, validateRecordFile } from '@offline/core';
import type { RecordFile, ReviewResult, StepSnapshot, FailureEvidence } from '@offline/core';
import { buildDemoRecord } from './demo.js';
import './styles.css';

const app = document.querySelector<HTMLDivElement>('#app')!;

app.innerHTML = `
<header class="topbar">
  <div class="brand">🛰️ 卫星载荷 · 离线委托/撤销因果复核台</div>
  <div class="sub">每条解锁请求只依据其签名 <code>seen</code> 向量中的实际因果历史裁决；后抵达撤销不追溯，已见撤销不漏判。</div>
</header>
<main class="layout">
  <section class="panel import-panel">
    <h2>1 · 导入记录</h2>
    <div class="row">
      <button id="btn-demo" class="btn">载入内置示例</button>
      <button id="btn-parse" class="btn primary">复核整段记录</button>
      <button id="btn-template" class="btn ghost">下载模板</button>
      <label class="btn ghost file-btn">导入 JSON 文件
        <input id="file-import" type="file" accept="application/json,.json" hidden />
      </label>
    </div>
    <div id="file-errors" class="errors"></div>
    <textarea id="record-input" spellcheck="false" placeholder='{"subjects":{"root":"<Base64 Ed25519 公钥>"},"root":"root","events":[...]}'></textarea>
    <div class="limits">主体 ≤ 8 ｜ 根主体恰好 1 个 ｜ 事件 ≤ 24（delegation / revocation / unlock）</div>
  </section>

  <section class="panel review-panel" id="review-panel" hidden>
    <h2>2 · 回放与裁决</h2>
    <div class="controls">
      <button id="btn-first" class="btn">⏮</button>
      <button id="btn-prev" class="btn">◀ 上一步</button>
      <button id="btn-next" class="btn primary">下一步 ▶</button>
      <button id="btn-last" class="btn">复核整段 ⏭</button>
      <span class="step-label"><span id="step-pos">-</span></span>
    </div>

    <div id="first-failure" class="failure-banner" hidden></div>

    <div class="grid3">
      <div class="card">
        <h3>当前事件</h3>
        <pre id="cur-event" class="mono small"></pre>
      </div>
      <div class="card">
        <h3>本步可用授权边</h3>
        <div id="active-edges" class="edge-list"></div>
      </div>
      <div class="card">
        <h3>已见撤销</h3>
        <div id="visible-revs" class="rev-list"></div>
      </div>
    </div>

    <div class="card verdict-card">
      <h3>请求裁决</h3>
      <div id="verdict"></div>
    </div>

    <div class="card">
      <h3>事件序列（点击跳转）</h3>
      <ol id="timeline" class="timeline"></ol>
    </div>

    <div class="card">
      <h3>全部解锁裁决汇总</h3>
      <div id="all-verdicts"></div>
    </div>
  </section>
</main>
<footer class="foot">全部计算在浏览器本地完成 · Ed25519 验签 · 签名载荷为剔除 signature 后按键名排序的 UTF-8 JSON</footer>
`;

const $ = <T extends HTMLElement>(id: string) => document.querySelector<T>('#' + id)!;

let record: RecordFile | null = null;
let result: ReviewResult | null = null;
let cursor = -1;

const input = $('record-input') as HTMLTextAreaElement;

function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

function showErrors(errs: string[]): void {
  const box = $('file-errors');
  box.innerHTML = errs.length ? errs.map((e) => `<div class="err">⚠ ${esc(e)}</div>`).join('') : '';
}

$<HTMLButtonElement>('btn-demo').addEventListener('click', async () => {
  const { record: demo } = await buildDemoRecord();
  record = demo;
  input.value = JSON.stringify(demo, null, 2);
  showErrors([]);
  await runReview();
});

$<HTMLButtonElement>('btn-parse').addEventListener('click', async () => {
  await importAndReview();
});

$<HTMLInputElement>('file-import').addEventListener('change', async (e) => {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;
  input.value = await file.text();
  await importAndReview();
});

$<HTMLButtonElement>('btn-template').addEventListener('click', () => {
  const tpl = {
    subjects: { root: 'BASE64_ED25519_PUBKEY_32B', alice: '...' },
    root: 'root',
    events: [
      {
        kind: 'delegation', author: 'root', seq: 1, seen: {}, edgeId: 'e1', from: 'root', to: 'alice',
        perms: ['delegate', 'unlock', 'revoke'], signature: 'BASE64_ED25519_SIG_64B',
      },
      { kind: 'revocation', author: 'root', seq: 2, seen: { root: 1 }, edgeId: 'e1', signature: '...' },
      {
        kind: 'unlock', author: 'alice', seq: 1, seen: { root: 1, alice: 1 },
        unlockId: 'u1', requester: 'alice', target: 'PAYLOAD-BAY', signature: '...',
      },
    ],
  };
  const blob = new Blob([JSON.stringify(tpl, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'delegation-record-template.json';
  a.click();
});

async function importAndReview(): Promise<void> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input.value);
  } catch (e) {
    showErrors(['JSON 解析失败：' + (e as Error).message]);
    return;
  }
  const v = validateRecordFile(parsed);
  if (!v.ok) {
    showErrors(v.errors);
    return;
  }
  showErrors([]);
  record = parsed as RecordFile;
  await runReview();
}

async function runReview(): Promise<void> {
  if (!record) return;
  result = await reviewRecord(record);
  cursor = result.snapshots.length - 1;
  $('review-panel').hidden = false;
  render();
}

const KIND_LABEL: Record<string, string> = {
  delegation: '委托',
  revocation: '撤销',
  unlock: '解锁',
};

function renderFailureBanner(): void {
  const banner = $('first-failure');
  if (!result) return;
  const f = result.firstFailure;
  if (!f) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  banner.innerHTML = `🚫 <b>首个失效记录定位：#${f.recordIndex}</b> — ${esc(describeEvidence(f))}`;
}

function describeEvidence(f: FailureEvidence & { recordIndex?: number }): string {
  switch (f.kind) {
    case 'malformed-event': return `记录格式错误（${f.reason}）`;
    case 'unknown-key': return `未知主体公钥：${f.subject}`;
    case 'bad-signature': return `伪造/无效的 Ed25519 签名`;
    case 'seq-jump': return `计数跳跃：${f.subject} 期望 seq=${f.expected}，实际 ${f.actual}`;
    case 'unknown-predecessor':
      return `未知前驱：向量引用 ${f.subject}=${f.referenced}，已接收仅到 ${f.known}`;
    case 'cycle': return `委托成环：${f.cycle.join(' → ')}`;
    case 'privilege-escalation':
      return `权限集合放大：授予 [${f.granted.join(',')}]，持有 [${f.held.join(',')}]，边 ${f.edgeId}`;
    case 'not-delegator': return `${f.from} 当时无再委托权限，边 ${f.edgeId}`;
    case 'revoke-unknown': return `撤销目标边不存在：${f.edgeId}`;
    case 'revoke-not-reachable': return `${f.author} 无权撤销（无 revoke 权限或非其下游）：${f.edgeId}`;
    case 'duplicate-edge': return `边编号重复：${f.edgeId}`;
    case 'unlock-bad-author': return `解锁作者 ${f.author} 与请求者 ${f.requester} 不一致`;
    case 'unlock-no-chain': return `无有效授权链：${f.detail}`;
    default: return JSON.stringify(f);
  }
}

function render(): void {
  if (!result) return;
  const n = result.snapshots.length;
  if (cursor < 0) cursor = 0;
  if (cursor > n - 1) cursor = n - 1;
  $('step-pos').textContent = n === 0 ? '无事件' : `第 ${cursor + 1} / ${n} 步`;

  const snap: StepSnapshot | undefined = result.snapshots[cursor];
  const ev = record?.events[cursor];

  $('cur-event').textContent = ev ? JSON.stringify(redact(ev), null, 2) : '（无事件）';
  const curEl = $('cur-event').parentElement!;
  curEl.classList.toggle('invalid', snap ? !snap.eventValid : false);

  $('active-edges').innerHTML = (snap?.activeEdges ?? []).length
    ? snap!.activeEdges
      .map((e) => `<div class="edge"><span class="tag">${esc(e.edgeId)}</span>
        <b>${esc(e.from)}</b> → <b>${esc(e.to)}</b>
        <span class="perms">${e.perms.map(esc).join(' ∩ ')}</span>
        <span class="born">@#${e.bornAt}</span></div>`).join('')
    : '<div class="empty">（无）</div>';

  $('visible-revs').innerHTML = (snap?.visibleRevocations ?? []).length
    ? snap!.visibleRevocations
      .map((r) => `<div class="rev">🗑 边 <span class="tag">${esc(r.edgeId)}</span> 由 ${esc(r.author)} 于 #${r.revokedAt} 撤销</div>`)
      .join('')
    : '<div class="empty">（无）</div>';

  renderVerdict(snap);
  renderTimeline();
  renderAllVerdicts();
  renderFailureBanner();
}

function redact(ev: unknown): unknown {
  const e = { ...(ev as Record<string, unknown>) };
  if (typeof e.signature === 'string') {
    e.signature = e.signature.slice(0, 16) + (e.signature.length > 16 ? '…' : '');
  }
  return e;
}

function renderVerdict(snap?: StepSnapshot): void {
  const box = $('verdict');
  if (!snap || !snap.verdict) {
    box.innerHTML = '<div class="empty">本步不是解锁请求。</div>';
    return;
  }
  const v = snap.verdict;
  if (v.authorized && v.chain) {
    box.innerHTML = `
      <div class="verdict ok">✅ 解锁 <code>${esc(v.unlockId)}</code> 授权成立（目标 ${esc(v.target)}）</div>
      <div class="chain">规范授权链：
        ${v.chain.path.map((p, i) =>
    i === 0
      ? `<b>${esc(p)}</b>`
      : `<span class="hop">—<span class="tag">${esc(v.chain!.edges[i - 1])}</span>→<b>${esc(p)}</b></span>`).join(' ')}
      </div>
      <div class="perms-line">链上权限交集：${v.chain.perms.map(esc).join('、')}</div>`;
  } else {
    box.innerHTML = `
      <div class="verdict no">⛔ 解锁 <code>${esc(v.unlockId)}</code> 被拒绝（目标 ${esc(v.target)}）</div>
      <div class="evidence"><b>最短失效证据：</b>${esc(v.evidence ? describeEvidence(v.evidence) : '')}</div>
      <ul class="witness">${(v.evidence && 'witness' in v.evidence
        ? (v.evidence as { witness: string[] }).witness.map((w) => `<li>${esc(w)}</li>`).join('')
        : '')}</ul>`;
  }
}

function renderTimeline(): void {
  if (!result || !record) return;
  $('timeline').innerHTML = record.events.map((ev, i) => {
    const snap = result!.snapshots[i];
    const isCursor = i === cursor;
    const cls = [!snap.eventValid && 'bad', isCursor && 'current', ev.kind === 'unlock' &&
      (snap.verdict?.authorized ? 'ok' : 'deny')].filter(Boolean).join(' ');
    const verdictMark = ev.kind === 'unlock'
      ? (snap.verdict?.authorized ? ' ✅' : ' ⛔')
      : '';
    const invalidMark = !snap.eventValid ? ' 🚫' : '';
    const title = ev.kind === 'delegation'
      ? `${(ev as { from: string }).from} → ${(ev as { to: string }).to} [${(ev as { perms: string[] }).perms.join(',')}]`
      : ev.kind === 'revocation'
        ? `撤销 ${(ev as { edgeId: string }).edgeId}`
        : `${(ev as { requester: string }).requester} → ${(ev as { target: string }).target}`;
    return `<li class="tl ${cls}" data-i="${i}">#${i} ${KIND_LABEL[ev.kind]} <code>${esc((ev as { author: string }).author)}</code>
      <span class="tl-title">${esc(title)}</span>${verdictMark}${invalidMark}</li>`;
  }).join('');
  document.querySelectorAll<HTMLElement>('#timeline .tl').forEach((li) => {
    li.addEventListener('click', () => {
      cursor = Number(li.dataset.i);
      render();
    });
  });
}

function renderAllVerdicts(): void {
  if (!result) return;
  const box = $('all-verdicts');
  if (result.verdicts.length === 0) {
    box.innerHTML = '<div class="empty">记录中无解锁请求。</div>';
    return;
  }
  box.innerHTML = '<table class="vtable"><thead><tr><th>#</th><th>解锁</th><th>请求者</th><th>目标</th><th>裁决</th><th>规范链 / 失效证据</th></tr></thead><tbody>' +
    result.verdicts.map((v) => {
      const detail = v.authorized && v.chain
        ? v.chain.path.join(' → ') + `（${v.chain.edges.join(', ')}；交集 ${v.chain.perms.join('∩')}）`
        : `<span class="ev-text">${esc(describeEvidence(v.evidence!))}</span>` +
        (v.evidence && 'witness' in v.evidence
          ? `<ul class="witness">${(v.evidence as { witness: string[] }).witness.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>`
          : '');
      return `<tr class="${v.authorized ? 'ok-row' : 'no-row'}">
        <td>${v.eventIndex}</td><td><code>${esc(v.unlockId)}</code></td>
        <td>${esc(v.requester)}</td><td>${esc(v.target)}</td>
        <td>${v.authorized ? '✅ 授权' : '⛔ 拒绝'}</td><td>${detail}</td></tr>`;
    }).join('') + '</tbody></table>';
}

$<HTMLButtonElement>('btn-first').addEventListener('click', () => { cursor = 0; render(); });
$<HTMLButtonElement>('btn-prev').addEventListener('click', () => { cursor = Math.max(0, cursor - 1); render(); });
$<HTMLButtonElement>('btn-next').addEventListener('click', () => {
  if (result) cursor = Math.min(result.snapshots.length - 1, cursor + 1);
  render();
});
$<HTMLButtonElement>('btn-last').addEventListener('click', () => {
  if (result) cursor = result.snapshots.length - 1;
  render();
});
