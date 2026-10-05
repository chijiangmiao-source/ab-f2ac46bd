# 卫星载荷离线委托/撤销因果复核台

安全审查员面对的是**离线接收、乱序抵达**的委托与撤销记录。本系统对每一条解锁
请求回答一个问题：**在请求者签发时实际可见的因果历史中，它是否仍然获授权？**

两条核心因果原则：

1. **后抵达的撤销不追溯** —— 记录位置更靠后的撤销绝不能否决它到达之前已裁决的
   解锁请求（回放时每步的裁决被固定保留）。
2. **已见撤销不漏判** —— 只要撤销位于解锁请求签名的 `seen` 向量内，就必须生效；
   反过来，物理已抵达但不在向量中的撤销对该请求不可见。请求也不能通过省略向量
   条目来“装没看见”自己已引用范围内的边——链只能沿向量中**已见**的委托边通过。

## 记录格式

```jsonc
{
  "subjects": { "root": "<Base64 Ed25519 公钥, 32B>", "alice": "..." }, // ≤ 8 个主体
  "root": "root",                                                        // 恰好 1 个已知根
  "events": [ /* ≤ 24 条，按接收顺序排列 */ ]
}
```

每个事件含：

| 字段 | 含义 |
| --- | --- |
| `author` | 签发主体（必须在 `subjects` 中） |
| `seq` | 该主体的严格递增计数（从 1 开始，跳跃即非法） |
| `seen` | 签发时已见的各主体最大计数向量；引用未接收计数/未知主体即“未知前驱” |
| `signature` | Base64 Ed25519 签名，覆盖剔除 `signature`（及接收方元数据 `recordIndex`）后、**按字段名排序**的 UTF-8 JSON |

事件三类：

- `delegation`：`from → to` 授予 `perms`（`delegate` / `unlock` / `revoke`）。
  作者必须即 `from`；`from` 当时必须沿未撤销链持有 `delegate`；授予的权限集合
  只能是其持有集合的子集；不得成环（含自环）。
- `revocation`：撤销指定 `edgeId`。撤销者须沿存活链持有 `revoke` 且目标边在其
  下游；只移除该边——依赖它的唯一上游后代自然失效，**并列独立委托不受影响**；
  后代若另有独立路径则仍然存活。
- `unlock`：`requester`（必须即作者）请求解锁 `target`。在其 `seen` 视图内移除
  已撤销边后，搜索根 → 请求者的最短**权限交集**链；链上每跳权限取交集，末跳仍
  含 `unlock` 才授权。命中给出**规范授权链**，未命中给出**最短失效证据**
  （根可达前沿 + 被撤销切断的边）。

非法事件（未知主体、伪造签名、计数跳跃、未知前驱、越权、成环、非法撤销……）不
改变状态，回放继续；系统定位**首个**非法记录。

## 仓库结构

```
packages/core      纯 TS 规则内核（Ed25519 验签、因果引擎、规范序列化）
  src/engine.ts    回放/裁决引擎，逐步产出快照（可用授权边/已见撤销/裁决）
  src/signing.ts   稳定序列化与验签
  test/            26 项 node:test 规则测试
packages/web       Vite 页面：导入 JSON、单步回放、整段复核、逐步状态与汇总表
packages/verify    一次性 verify：规则测试 → 页面构建 → HTTP 冒烟 → 退出码
```

## 本地运行

```bash
npm ci
npm test          # 内核规则测试
npm run build     # 构建内核与页面
npm run verify    # 一次性：测试 + 构建 + HTTP 冒烟，退出码 0/1
npm run serve     # 常驻服务：http://localhost:8088/ （页面 + /api/review）
```

打开页面后点“载入内置示例”即可看到：撤销前解锁维持授权、已见撤销后的解锁被
拒绝并给出最短失效证据、并列主体的独立委托不受误伤。

## Compose

```bash
docker compose build verify
docker compose up verify      # 执行一次：测试/构建/冒烟，容器以退出码结束
docker compose up app         # 常驻复核台 → http://localhost:8088/
```

verify 容器冒烟端点：`GET /health`、`GET /api/health-path`（三级健康链必须授权）、
`POST /api/review`（撤销不追溯/不漏判/不误伤并列的样本必须全部符合预期）。

## 裁决端点

`POST /api/review` 提交记录 JSON，返回：

```jsonc
{
  "review": {
    "snapshots": [ { "index": 0, "activeEdges": [...], "visibleRevocations": [...],
                     "verdict": { "authorized": true, "chain": { "edges": [...], "path": [...] } } } ],
    "verdicts": [ /* 全部解锁裁决 */ ],
    "firstFailure": null
  }
}
```
