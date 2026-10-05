# 卫星载荷离线维护密钥 —— 委托/撤销/解锁因果复核台

浏览器内复核一段**离线接收**的维护密钥授权记录。每条解锁请求只在它**实际可见的因果历史**中裁决：后来才到达的撤销不会回溯否决它；而一旦撤销已在它的“已见（seen）”向量闭包中，就绝不能被遗漏。

## 它做什么

1. 在网页导入至多 **8 个主体公钥**、**1 个根主体**、至多 **24 条事件**（委托 / 撤销 / 解锁）。
2. 可**单步回放**（步进滑块 / 连续播放）或**直接复核整段**记录。
3. 校验每条记录：
   - Ed25519 签名（Base64），覆盖**除 `signature` 字段外、字段名按字典序排序的紧凑 UTF-8 JSON**；
   - 作者递增计数（跳跃定位到第一条坏记录）；
   - “已见”计数向量的前驱必须存在、有效且在过去，同一作者的向量不得回退（**不得遗忘已可见的撤销**）；
   - 委托只能由**签发当时**具有再委托权限的主体作出，权限集合**只能缩小**；
   - 委托图无环。
4. 解锁只可沿“该记录向量所见、且未撤销”的有效链通过：中间边必须带 `DELEGATE`，到达请求者的末边必须带 `UNLOCK`。
5. 撤销只切断被撤销的那条委托边以及**必须经过它的后代链**；并列的独立委托仍然可用。
6. 结果给出**规范（最短、字典序并列优先）授权链**，或**最短失效证据**（被切断的边 / 缺失权利 / 结构不可达前沿）。
7. 页面在每一步保留并展示：**可用授权边、可见撤销、请求裁决**。

## 记录格式

```json
{
  "rootSubject": "root",
  "subjects": [
    { "id": "root", "publicKey": "<Base64 Ed25519 公钥, 32 字节>" }
  ],
  "events": [
    { "kind": "delegate", "author": "root", "seq": 0, "seen": {},
      "from": "root", "to": "A", "rights": ["DELEGATE", "UNLOCK"],
      "signature": "<Base64 Ed25519 签名, 64 字节>" },
    { "kind": "revoke", "author": "root", "seq": 1, "seen": {"root": 0},
      "target": {"from": "root", "to": "A", "seq": 0},
      "signature": "..." },
    { "kind": "unlock", "author": "A", "seq": 0, "seen": {"root": 1} }
  ]
}
```

签名内容 = `canonical_json(event − signature)` 的 UTF-8 字节，即对象字段名升序、无空白；嵌套对象与数组递归处理。

## 因果语义（审查要点）

- **可见历史**：记录的 `seen` 向量指向它直接见过的 `{主体: 计数}`；判定时取传递闭包。闭包之外的撤销对它不存在，哪怕撤销在到达顺序上更早（离线乱序到达）。
- **后到撤销不溯及既往**：在撤销可见之前裁决为 AUTHORIZED 的解锁保持原裁决；同一请求者之后发出的、见到了撤销的新记录会被 DENIED。
- **不得遗漏已见撤销**：某主体后续记录的向量对任一主体不得小于其既往已知的最大值；回退即 `SEEN_VECTOR_REGRESSION`，定位到第一条回退记录。
- **撤销作用域**：按边 id（`<委托者>#<委托者计数>`）切断。根→A、根→B 两条并列边中撤销 root→A，不影响经 root→B 的链。
- **权限只缩不放**：每条链上边的权利集合必须覆盖被授出的权利，且再委托要求该边带 `DELEGATE`。

## 本地运行（Node ≥ 18）

```bash
npm install
npm run verify     # 一次性：规则测试 → 构建页面 → jsdom 渲染冒烟 → HTTP 冒烟，然后以退出码结束
npm run serve      # 可选：常驻 http://localhost:8080 提供复核页与 /api/review/*
```

## Docker Compose（一次性 verify 服务）

```bash
docker compose up          # 只运行 verify：执行一次，按结果以 0/1 退出（只读文件系统）
docker compose run verify  # CI 中同理
docker compose --profile serve up app   # 常驻页面 :8080
```

`verify/verify.mjs` 严格执行一次：① `tests/model.test.mjs` 核对规则；② esbuild 构建页面并用 jsdom 核对渲染与交互；③ 对 `/healthz`、静态资源、`/api/review/revoke`（撤销复核结果）与 `/api/review/healthy`（健康路径）及两个攻击样本做 HTTP 冒烟；随后进程以退出码 0 或 1 结束。

## 目录

| 路径 | 说明 |
| --- | --- |
| `core/codec.js` | 浏览器/Node 通用标准 Base64 |
| `core/canonical.js` | 字段名排序的规范 JSON 与签名载荷 |
| `core/crypto.js` | Ed25519（@noble）+ WebCrypto SHA-512/随机数适配 |
| `core/model.js` | 校验、因果闭包、委托图、撤销切断、解锁裁决与最短证据 |
| `core/fixture.js` / `core/demo.js` | 签名夹具与预置场景 |
| `web/` | 复核页面（原生 ES module，打包为 `web-dist/`） |
| `tests/model.test.mjs` | 22 条规则测试 |
| `tests/page.test.mjs` | jsdom 页面渲染与交互冒烟 |
| `verify/` | HTTP 服务与一次性 verify 编排 |
