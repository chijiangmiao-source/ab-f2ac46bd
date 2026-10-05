// Browser UI: import a signed log, single-step replay or review the whole
// record, with per-step live authorization edges, visible revocations and
// unlock verdicts.
import { loadSubjects, evaluateLog, ERROR } from '../core/model.js';
import { buildScenario } from '../core/demo.js';

const $ = (sel) => document.querySelector(sel);
const state = { result: null, doc: null, shown: 0, timer: null };

const ERROR_LABEL = {
  [ERROR.SCHEMA]: '结构错误',
  [ERROR.LIMIT]: '超出导入上限（≤8 主体 / ≤24 事件）',
  [ERROR.UNKNOWN_SUBJECT]: '未知主体',
  [ERROR.UNKNOWN_KEY]: '公钥不是 32 字节 Ed25519 密钥',
  [ERROR.FORGED_SIGNATURE]: '伪造签名',
  [ERROR.SEQ_SKIP]: '作者计数跳跃',
  [ERROR.UNKNOWN_PREDECESSOR]: '未知/无效前驱',
  [ERROR.BAD_DELEGATION]: '委托格式错误',
  [ERROR.CYCLE]: '委托成环',
  [ERROR.NO_DELEGATE_AUTHORITY]: '签发时无再委托权限',
  [ERROR.RIGHTS_AMPLIFICATION]: '权限集合放大（只能缩小）',
  [ERROR.BAD_REVOCATION]: '撤销格式错误',
  [ERROR.REVOKE_UNKNOWN_TARGET]: '撤销目标不存在',
  [ERROR.REVOKE_NOT_OWNER]: '非委托所有者撤销',
  [ERROR.BAD_UNLOCK]: '解锁请求格式错误',
  [ERROR.VECTOR_REGRESSION]: '已见向量回退（遗忘已可见历史）'
};

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function pill(text, cls) { return el('span', 'pill ' + (cls || 'muted'), text); }

async function loadDocument(doc) {
  stopPlay();
  state.doc = doc;
  const dir = loadSubjects(doc);
  const banner = $('#importMsg');
  banner.className = 'msg';
  banner.textContent = '';
  if (dir.error) {
    state.result = null;
    banner.className = 'msg err';
    banner.textContent = `导入被拒绝（${ERROR_LABEL[dir.error.code] || dir.error.code}）：${dir.error.message}`;
    render();
    return;
  }
  const result = await evaluateLog(dir, doc.events || []);
  if (!result.ok) {
    state.result = null;
    banner.className = 'msg err';
    banner.textContent = `导入被拒绝（${ERROR_LABEL[result.error.code] || result.error.code}）：${result.error.message}`;
    render();
    return;
  }
  state.result = result;
  state.shown = result.records.length;
  if (result.firstInvalidRecord !== null) {
    const r = result.records[result.firstInvalidRecord];
    banner.className = 'msg err';
    banner.textContent = `首个无效记录为第 ${result.firstInvalidRecord + 1} 条 ${r.ref}：${ERROR_LABEL[r.error.code] || r.error.code} —— ${r.error.message}`;
  } else {
    banner.className = 'msg ok';
    banner.textContent = `全部 ${result.records.length} 条记录格式与签名有效；解锁裁决见各记录卡片。`;
  }
  $('#slider').max = String(Math.max(1, result.records.length));
  $('#importJson').value = JSON.stringify(doc, null, 2);
  render();
}

function render() {
  const root = $('#timeline');
  root.innerHTML = '';
  if (!state.result) {
    $('#summary').innerHTML = '';
    $('#stepMeta').textContent = '未加载记录';
    $('#slider').value = '0';
    setButtons();
    return;
  }
  const { records, summary, firstInvalidRecord } = state.result;
  state.shown = Math.min(state.shown, records.length);

  // Summary counts
  const sum = $('#summary');
  sum.className = 'counts';
  sum.innerHTML = '';
  const chips = [
    ['记录总数', summary.total],
    ['委托', summary.delegates],
    ['撤销', summary.revokes],
    ['解锁', summary.unlocks],
    ['裁决：授权', summary.authorized, 'ok'],
    ['裁决：拒绝', summary.denied, 'bad'],
    ['无效记录', summary.invalid, summary.invalid ? 'bad' : 'ok']
  ];
  for (const [label, value, cls] of chips) {
    const c = el('div', 'c');
    const b = el('b', cls === 'bad' ? 'bad' : cls === 'ok' ? 'ok' : '', String(value));
    c.append(b, document.createTextNode(label));
    sum.append(c);
  }

  // Cards up to shown prefix
  records.forEach((r, i) => {
    if (i >= state.shown) return;
    root.appendChild(renderRecord(r, i, i === firstInvalidRecord, i === state.shown - 1));
  });

  $('#stepMeta').textContent = `回放位置：${state.shown} / ${records.length}`;
  $('#slider').max = String(records.length);
  $('#slider').value = String(state.shown);
  setButtons();
}

function renderRecord(r, i, isFirstInvalid, isCurrent) {
  const card = el('div', 'record' + (r.error ? ' invalid' : '') + (isCurrent ? ' current' : ''));
  const head = el('div', 'head');
  head.append(el('span', 'ref', `#${i + 1} ${r.ref}`));
  const kindMap = { delegate: ['委托', 'ok'], revoke: ['撤销', 'revoke'], unlock: ['解锁', 'warn'] };
  const [kText, kCls] = kindMap[r.kind] || [r.kind || '?', 'muted'];
  head.append(pill(kText, kCls));
  if (r.error) {
    head.append(pill('✗ ' + (ERROR_LABEL[r.error.code] || r.error.code), 'bad'));
    if (isFirstInvalid) head.append(pill('首个无效记录', 'warn'));
  } else {
    head.append(pill('✓ 签名与结构有效', 'ok'));
  }
  if (r.verdict) {
    head.append(pill(r.verdict.decision === 'AUTHORIZED' ? '解锁：授权' : '解锁：拒绝', r.verdict.decision === 'AUTHORIZED' ? 'ok' : 'bad'));
  }
  if (r.delegation) head.append(el('span', 'mono', `${r.delegation.from} → ${r.delegation.to}  [${r.delegation.rights.join(',')}]`));
  if (r.revocation) head.append(el('span', 'mono', `撤销 ${r.revocation.target}（→ ${r.revocation.to}）`));

  const body = el('div', 'body');
  if (r.error) {
    body.append(el('div', 'evidence', `定位：第 ${i + 1} 条记录 ${r.ref}\n${r.error.code}：${r.error.message}`));
    if (r.error.evidence) body.append(evidenceView(r.error.evidence));
  }

  if (r.authorityChain) {
    const block = el('div', 'block');
    block.append(el('h3', null, '签发时的再委托授权链（规范最短）'));
    block.append(chainView(r.authorityChain));
    body.append(block);
  }

  if (r.verdict) {
    const block = el('div', 'block');
    block.append(el('h3', null, `解锁请求裁决（请求者 ${r.verdict.target}，仅依据该记录的因果所见）`));
    if (r.verdict.decision === 'AUTHORIZED') {
      if (r.verdict.chain.length === 0) {
        block.append(el('div', 'msg ok', '根主体自身请求，天然授权（无需委托边）。'));
      } else {
        block.append(el('div', 'msg ok', '授权成立，规范授权链如下：'));
        block.append(chainView(r.verdict.chain));
      }
    } else {
      block.append(el('div', 'msg err', '请求被拒绝，最短失效证据：'));
      block.append(evidenceView(r.verdict.evidence));
    }
    body.append(block);
  }

  // Per-step retained views
  const g = el('div', 'grid2');
  g.append(edgesBlock(r));
  g.append(revocationsBlock(r));
  body.append(g);
  card.append(head, body);
  return card;
}

function chainView(chain) {
  const wrap = el('div', 'chain');
  wrap.append(el('span', 'edge', 'root'));
  for (const e of chain) {
    wrap.append(el('span', 'arrow', '→'));
    const edge = el('span', 'edge', `${e.to} （${e.id}，[${e.rights.join(',')}]）`);
    edge.title = `记录 #${e.record + 1}，${e.from}→${e.to}`;
    wrap.append(edge);
  }
  return wrap;
}

function evidenceView(ev) {
  const wrap = el('div', 'evidence');
  const lines = [ev.message];
  if (ev.edge) lines.push(`阻断边：${ev.edge.id}（${ev.edge.from}→${ev.edge.to}，权利 [${ev.edge.rights.join(',')}]）`);
  if (ev.missing) lines.push(`缺失权利：${ev.missing}`);
  if (Array.isArray(ev.revokedBy)) lines.push(`撤销记录：${ev.revokedBy.length ? ev.revokedBy.map((x) => '#' + (x + 1)).join('、') : '（记录序号）'}`);
  if (ev.type === 'NO_CHAIN' && ev.reachable) lines.push(`根可达但无法到达目标的主体：${ev.reachable.join('、') || '（仅根）'}`);
  if (ev.nominalChain) {
    const cw = el('div', 'chain');
    cw.style.marginTop = '8px';
    cw.append(el('span', 'mono', '名义最短链：'));
    cw.append(el('span', 'edge', 'root'));
    for (const e of ev.nominalChain) {
      cw.append(el('span', 'arrow', '→'));
      cw.append(el('span', 'edge', `${e.to}（${e.id}）`));
    }
    wrap.append(el('div', null, lines.join('\n')));
    wrap.append(cw);
    return wrap;
  }
  wrap.textContent = lines.join('\n');
  return wrap;
}

function edgesBlock(r) {
  const block = el('div', 'block');
  block.append(el('h3', null, `本步之后可用的授权边（${r.visibleEdges.length}；裁决本身仅依据过去所见）`));
  if (!r.visibleEdges.length) {
    block.append(el('div', 'sig', '（无可见委托边）'));
    return block;
  }
  const table = document.createElement('table');
  table.innerHTML = '<tr><th>边</th><th>权利</th><th>状态</th></tr>';
  for (const e of r.visibleEdges) {
    const tr = document.createElement('tr');
    const td1 = el('td', 'mono', `${e.id} ${e.from}→${e.to}`);
    const td2 = el('td', null, '[' + e.rights.join(',') + ']');
    const td3 = document.createElement('td');
    if (e.active) td3.append(pill('有效', 'ok'));
    else td3.append(pill('已撤销', 'revoke'), document.createTextNode(' 由 ' + (e.revokedBy.join('、') || '?')));
    tr.append(td1, td2, td3);
    table.append(tr);
  }
  block.append(table);
  return block;
}

function revocationsBlock(r) {
  const block = el('div', 'block');
  block.append(el('h3', null, `本步可见的撤销（${r.visibleRevocations.length}）`));
  if (!r.visibleRevocations.length) {
    block.append(el('div', 'sig', '（无可见撤销——晚到的撤销不会回溯否决本步）'));
    return block;
  }
  const table = document.createElement('table');
  table.innerHTML = '<tr><th>撤销记录</th><th>切断的边</th><th>语义</th></tr>';
  for (const v of r.visibleRevocations) {
    const tr = document.createElement('tr');
    tr.append(
      el('td', 'mono', v.record),
      el('td', 'mono', v.edgeId),
      el('td', null, '仅切断该边及必须经过它的后代链；并列独立委托不受影响')
    );
    table.append(tr);
  }
  block.append(table);
  return block;
}

// --- transport controls -----------------------------------------------------

function setButtons() {
  const n = state.result ? state.result.records.length : 0;
  $('#btnPrev').disabled = state.shown <= 0;
  $('#btnNext').disabled = state.shown >= n;
  $('#btnReview').disabled = n === 0;
  $('#btnPlay').disabled = n === 0;
}
function gotoStep(n) {
  if (!state.result) return;
  state.shown = Math.max(0, Math.min(state.result.records.length, n));
  render();
}
function stopPlay() {
  if (state.timer) { clearInterval(state.timer); state.timer = null; $('#btnPlay').textContent = '▶ 连续播放'; }
}

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
  $('#btnLoad').addEventListener('click', () => readJsonFrom($('#importJson').value));
  $('#btnExport').addEventListener('click', () => {
    const blob = new Blob([$('#importJson').value], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'causal-review.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $('#fileImport').addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    $('#importJson').value = await file.text();
    readJsonFrom($('#importJson').value);
    e.target.value = '';
  });
  $('#btnSample').addEventListener('click', async () => {
    const name = $('#scenario').value;
    const doc = await buildScenario(name);
    loadDocument(doc);
  });
  $('#btnPrev').addEventListener('click', () => { stopPlay(); gotoStep(state.shown - 1); });
  $('#btnNext').addEventListener('click', () => { stopPlay(); gotoStep(state.shown + 1); });
  $('#btnReview').addEventListener('click', () => { stopPlay(); gotoStep(state.result.records.length); });
  $('#btnReset').addEventListener('click', () => { stopPlay(); gotoStep(0); });
  $('#btnPlay').addEventListener('click', () => {
    if (state.timer) { stopPlay(); return; }
    if (state.shown >= state.result.records.length) gotoStep(0);
    $('#btnPlay').textContent = '⏸ 暂停';
    state.timer = setInterval(() => {
      if (state.shown >= state.result.records.length) { stopPlay(); return; }
      gotoStep(state.shown + 1);
    }, 900);
  });
  $('#slider').addEventListener('input', (e) => { stopPlay(); gotoStep(Number(e.target.value)); });

  buildScenario('healthy').then((doc) => {
    $('#importJson').value = JSON.stringify(doc, null, 2);
    loadDocument(doc);
  });
  });
}

function readJsonFrom(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    const banner = $('#importMsg');
    banner.className = 'msg err';
    banner.textContent = 'JSON 解析失败：' + e.message;
    return;
  }
  loadDocument(doc);
}
