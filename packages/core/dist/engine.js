/**
 * 因果复核引擎。
 *
 * 两类时间必须区分：
 *  1. 记录时间（recordIndex）：离线接收顺序，单步回放沿此推进；后来抵达的
 *     撤销（记录下标更靠后）绝不能追溯否决先前的解锁裁决。
 *  2. 因果时间（seen 向量）：事件作者签发时实际已见的各主体计数。解锁只能
 *     沿其向量中已见的边通过，且其已见的撤销必须生效——不能通过省略向量
 *     条目来“遗漏”撤销。
 *
 * 撤销语义：被撤销的委托边直接从授权图移除。依赖该边的“后代”在其唯一上游
 * 被切断时自然失效；若后代另有独立（并列）委托路径，则仍然存活——撤销绝不
 * 误伤并列独立委托。
 *
 * 记录级非法事件（未知作者/伪造签名/计数跳跃/未知前驱/越权/成环等）不改变
 * 状态，回放继续；引擎记录首个非法记录（最短失效证据）。
 */
import { ALL_PERMISSIONS, } from './types.js';
import { verifySignature } from './signing.js';
const PERM_SET = new Set(ALL_PERMISSIONS);
/** 记录文件级约束：至多 8 个主体、恰好 1 个已知根、至多 24 条事件。 */
export function validateRecordFile(file) {
    const errors = [];
    if (!file || typeof file !== 'object')
        return { ok: false, errors: ['记录不是 JSON 对象'] };
    const f = file;
    const subjects = f.subjects;
    if (!subjects || typeof subjects !== 'object' || Array.isArray(subjects)) {
        errors.push('subjects 必须是主体标识 → Base64 公钥的映射');
    }
    else {
        const keys = Object.keys(subjects);
        if (keys.length === 0)
            errors.push('至少需要 1 个主体');
        if (keys.length > 8)
            errors.push(`主体数量 ${keys.length} 超过上限 8`);
        for (const k of keys) {
            const v = subjects[k];
            if (typeof v !== 'string' || v.length === 0)
                errors.push(`主体 ${k} 的公钥缺失或非字符串`);
        }
        if (typeof f.root !== 'string' || !(f.root in subjects)) {
            errors.push('root 必须是 subjects 中已声明的主体标识');
        }
    }
    if (!Array.isArray(f.events)) {
        errors.push('events 必须是数组');
    }
    else if (f.events.length > 24) {
        errors.push(`事件数量 ${f.events.length} 超过上限 24`);
    }
    return { ok: errors.length === 0, errors };
}
function isNonNegInt(v) {
    return typeof v === 'number' && Number.isInteger(v) && v >= 0;
}
function adjacency(edges, removed) {
    const outgoing = new Map();
    for (const e of edges) {
        if (removed.has(e.edgeId))
            continue;
        if (!outgoing.has(e.from))
            outgoing.set(e.from, []);
        outgoing.get(e.from).push(e);
    }
    for (const list of outgoing.values()) {
        list.sort((a, b) => a.bornAt - b.bornAt || (a.edgeId < b.edgeId ? -1 : a.edgeId > b.edgeId ? 1 : 0));
    }
    return outgoing;
}
/**
 * 在去掉 removed 边的图上枚举根 → goal 的简单路径。始终返回诊断结构
 * （根可达集合、被移除边前沿）；找到携带所需权限的最短规范链时
 * （并列按出生下标、边编号字典序）edges 非空。
 */
function searchChain(edges, root, goal, need, removed) {
    const outgoingLive = adjacency(edges, removed);
    const outgoingAll = adjacency(edges, new Set());
    const reachable = new Set([root]);
    const removedFrontier = [];
    let best = null;
    const keyOf = (es) => es.map((e) => String(e.bornAt).padStart(3, '0') + ':' + e.edgeId).join('|');
    const dfs = (path, chainEdges, perms, visited) => {
        const cur = path[path.length - 1];
        if (cur === goal) {
            if (perms.has(need)) {
                const b = best;
                if (b === null || chainEdges.length < b.edges.length ||
                    (chainEdges.length === b.edges.length && keyOf(chainEdges) < keyOf(b.edges))) {
                    best = { edges: [...chainEdges], perms: new Set(perms) };
                }
            }
            return;
        }
        for (const e of outgoingLive.get(cur) ?? []) {
            if (visited.has(e.to))
                continue;
            const nextPerms = new Set([...perms].filter((p) => e.perms.includes(p)));
            visited.add(e.to);
            chainEdges.push(e);
            path.push(e.to);
            dfs(path, chainEdges, nextPerms, visited);
            path.pop();
            chainEdges.pop();
            visited.delete(e.to);
        }
    };
    // BFS 求根可达集合与移除边前沿（见证），DFS 求规范链。
    {
        const stack = [root];
        const seen = new Set([root]);
        while (stack.length) {
            const cur = stack.pop();
            reachable.add(cur);
            for (const e of outgoingAll.get(cur) ?? []) {
                if (removed.has(e.edgeId)) {
                    removedFrontier.push(e);
                }
                else if (!seen.has(e.to)) {
                    seen.add(e.to);
                    stack.push(e.to);
                }
            }
        }
    }
    dfs([root], [], new Set(ALL_PERMISSIONS), new Set([root]));
    const winner = best;
    return {
        edges: winner ? winner.edges : [],
        perms: winner ? winner.perms : new Set(),
        reachable,
        removedFrontier,
    };
}
function chainOf(hit, root) {
    if (hit.edges.length === 0)
        return null;
    return {
        status: 'authorized',
        edges: hit.edges.map((e) => e.edgeId),
        path: [root, ...hit.edges.map((e) => e.to)],
        perms: [...ALL_PERMISSIONS].filter((p) => hit.perms.has(p)),
    };
}
function validateShape(ev) {
    if (!ev || typeof ev !== 'object')
        return false;
    const e = ev;
    if (typeof e.author !== 'string' || !isNonNegInt(e.seq) || typeof e.signature !== 'string')
        return false;
    if (!e.seen || typeof e.seen !== 'object' || Array.isArray(e.seen))
        return false;
    if (e.kind === 'delegation') {
        return (typeof e.edgeId === 'string' &&
            typeof e.from === 'string' &&
            typeof e.to === 'string' &&
            Array.isArray(e.perms) &&
            e.perms.length > 0 &&
            e.perms.every((p) => typeof p === 'string' && PERM_SET.has(p)));
    }
    if (e.kind === 'revocation')
        return typeof e.edgeId === 'string';
    if (e.kind === 'unlock') {
        return typeof e.unlockId === 'string' && typeof e.requester === 'string' && typeof e.target === 'string';
    }
    return false;
}
function hasSeen(seen, author, authorSeq) {
    const v = seen[author];
    return typeof v === 'number' && v >= authorSeq;
}
export async function reviewRecord(file) {
    const snapshots = [];
    const verdicts = [];
    let firstFailure = null;
    const fail = (i, evidence) => {
        if (firstFailure === null)
            firstFailure = { ...evidence, recordIndex: i };
    };
    const edges = [];
    const revocations = [];
    const maxSeq = new Map();
    const edgeById = new Map();
    const removed = () => new Set(revocations.map((r) => r.edgeId));
    for (let i = 0; i < file.events.length; i++) {
        const raw = file.events[i];
        raw.recordIndex = i;
        let eventValid = true;
        let verdict = null;
        const invalidate = (evidence) => {
            eventValid = false;
            fail(i, evidence);
            return false;
        };
        if (!validateShape(raw)) {
            invalidate({ kind: 'malformed-event', eventIndex: i, reason: '事件字段缺失或类型错误' });
        }
        else {
            const ev = raw;
            // 1) 未知作者
            if (!(ev.author in file.subjects)) {
                invalidate({ kind: 'unknown-key', subject: ev.author });
            }
            // 2) 伪造签名
            if (eventValid) {
                const sig = await verifySignature(raw, file.subjects);
                if (!sig.ok)
                    invalidate({ kind: 'bad-signature', eventIndex: i });
            }
            // 3) seen 向量：非负整数、主体已知、引用计数不超过已接收计数
            if (eventValid) {
                for (const [s, n] of Object.entries(ev.seen)) {
                    if (!isNonNegInt(n)) {
                        invalidate({ kind: 'unknown-predecessor', eventIndex: i, subject: s, referenced: Number(n), known: 0 });
                        break;
                    }
                    if (!(s in file.subjects)) {
                        invalidate({ kind: 'unknown-predecessor', eventIndex: i, subject: s, referenced: n, known: 0 });
                        break;
                    }
                    // 向量可包含作者自身当前事件计数（v[author]=seq 的向量时钟约定）
                    const known = s === ev.author ? (maxSeq.get(s) ?? 0) + 1 : (maxSeq.get(s) ?? 0);
                    if (n > known) {
                        invalidate({ kind: 'unknown-predecessor', eventIndex: i, subject: s, referenced: n, known });
                        break;
                    }
                }
            }
            // 4) 计数跳跃（同一作者必须严格 +1，从 1 起）
            if (eventValid) {
                const expected = (maxSeq.get(ev.author) ?? 0) + 1;
                if (ev.seq !== expected) {
                    invalidate({ kind: 'seq-jump', eventIndex: i, subject: ev.author, expected, actual: ev.seq });
                }
            }
            if (eventValid && ev.kind === 'delegation') {
                // 重复边编号
                if (edgeById.has(ev.edgeId)) {
                    invalidate({ kind: 'duplicate-edge', eventIndex: i, edgeId: ev.edgeId });
                }
                // 签发者必须即委托方
                if (eventValid && ev.author !== ev.from) {
                    invalidate({ kind: 'not-delegator', eventIndex: i, edgeId: ev.edgeId, from: ev.from });
                }
                // 委托方当时必须经未撤销链持有 delegate
                let held;
                if (eventValid) {
                    held = ev.from === file.root
                        ? [...ALL_PERMISSIONS]
                        : chainOf(searchChain(edges, file.root, ev.from, 'delegate', removed()), file.root)?.perms ?? [];
                    if (!held.includes('delegate')) {
                        invalidate({ kind: 'not-delegator', eventIndex: i, edgeId: ev.edgeId, from: ev.from });
                    }
                }
                // 权限集合只能缩小
                if (eventValid) {
                    const granted = [...new Set(ev.perms)];
                    if (!granted.every((p) => held.includes(p))) {
                        invalidate({
                            kind: 'privilege-escalation',
                            eventIndex: i,
                            edgeId: ev.edgeId,
                            granted,
                            held: held,
                        });
                    }
                }
                // 成环：在当前存活图上加入该边后，to 可回到 from（含自环）
                if (eventValid) {
                    const candidate = {
                        edgeId: ev.edgeId,
                        from: ev.from,
                        to: ev.to,
                        perms: [...new Set(ev.perms)],
                        bornAt: i,
                        author: ev.author,
                        authorSeq: ev.seq,
                    };
                    const back = searchChain([...edges, candidate], ev.to, ev.from, 'delegate', removed());
                    if (ev.to === ev.from || back.edges.length > 0) {
                        invalidate({
                            kind: 'cycle',
                            eventIndex: i,
                            edges: [...edges, candidate].map((e) => e.edgeId),
                            cycle: ev.to === ev.from ? [ev.edgeId] : [...back.edges.map((e) => e.edgeId), ev.edgeId],
                        });
                    }
                }
                if (eventValid) {
                    const edge = {
                        edgeId: ev.edgeId,
                        from: ev.from,
                        to: ev.to,
                        perms: [...new Set(ev.perms)],
                        bornAt: i,
                        author: ev.author,
                        authorSeq: ev.seq,
                    };
                    edges.push(edge);
                    edgeById.set(edge.edgeId, edge);
                }
            }
            if (eventValid && ev.kind === 'revocation') {
                const target = edgeById.get(ev.edgeId);
                const rem = removed();
                if (!target) {
                    invalidate({ kind: 'revoke-unknown', eventIndex: i, edgeId: ev.edgeId });
                }
                else if (rem.has(target.edgeId)) {
                    invalidate({ kind: 'revoke-not-reachable', eventIndex: i, edgeId: ev.edgeId, author: ev.author });
                }
                else if (eventValid) {
                    // 撤销者须经未撤销链持有 revoke，且目标边位于其下游（撤销者能到达
                    // 目标边的起点）。根可撤销任何边。
                    const power = ev.author === file.root
                        ? true
                        : searchChain(edges, file.root, ev.author, 'revoke', rem).edges.length > 0;
                    let downstream = ev.author === file.root;
                    if (!downstream) {
                        const outgoing = adjacency(edges, rem);
                        const stack = [ev.author];
                        const seenNodes = new Set(stack);
                        while (stack.length) {
                            const cur = stack.pop();
                            if (cur === target.from) {
                                downstream = true;
                                break;
                            }
                            for (const e of outgoing.get(cur) ?? []) {
                                if (!seenNodes.has(e.to)) {
                                    seenNodes.add(e.to);
                                    stack.push(e.to);
                                }
                            }
                        }
                    }
                    if (!power || !downstream) {
                        invalidate({ kind: 'revoke-not-reachable', eventIndex: i, edgeId: ev.edgeId, author: ev.author });
                    }
                }
                if (eventValid) {
                    revocations.push({ edgeId: ev.edgeId, revokedAt: i, author: ev.author, authorSeq: ev.seq });
                }
            }
            if (eventValid && ev.kind === 'unlock') {
                const uev = ev;
                if (uev.author !== uev.requester) {
                    invalidate({ kind: 'unlock-bad-author', eventIndex: i, author: uev.author, requester: uev.requester });
                }
                else if (!(uev.requester in file.subjects)) {
                    invalidate({ kind: 'unknown-key', subject: uev.requester });
                }
                else {
                    verdict = judgeUnlock(uev, i, file.root, edges, revocations);
                    verdicts.push(verdict);
                }
            }
            if (eventValid)
                maxSeq.set(ev.author, ev.seq);
        }
        const rem = removed();
        // 快照中只保留“可用授权边”：未撤销且当前仍可从根沿未撤销边到达。
        const live = edges.filter((e) => !rem.has(e.edgeId));
        const outgoingSnap = adjacency(live, new Set());
        const reach = new Set([file.root]);
        const stk = [file.root];
        while (stk.length) {
            const cur = stk.pop();
            for (const e of outgoingSnap.get(cur) ?? []) {
                if (!reach.has(e.to)) {
                    reach.add(e.to);
                    stk.push(e.to);
                }
            }
        }
        snapshots.push({
            index: i,
            activeEdges: live
                .filter((e) => reach.has(e.from))
                .map(({ edgeId, from, to, perms, bornAt }) => ({ edgeId, from, to, perms, bornAt })),
            visibleRevocations: revocations.map(({ edgeId, revokedAt, author }) => ({ edgeId, revokedAt, author })),
            verdict,
            eventValid,
        });
    }
    return {
        subjectCount: Object.keys(file.subjects).length,
        eventCount: file.events.length,
        snapshots,
        verdicts,
        firstFailure,
    };
}
/**
 * 依据解锁请求自身的因果视图裁决：
 *  - 边：记录中先于本请求抵达，且 (边作者, 边作者计数) 已被请求向量所见；
 *  - 撤销：同样要求先抵达且已见——已见撤销不得遗漏；
 *  - 后抵达的撤销尚不在记录前缀内，天然不能追溯否决。
 */
function judgeUnlock(ev, recordIndex, root, allEdges, allRevs) {
    const visibleEdges = allEdges.filter((e) => e.bornAt < recordIndex && hasSeen(ev.seen, e.author, e.authorSeq));
    const visibleRevs = allRevs.filter((r) => r.revokedAt < recordIndex && hasSeen(ev.seen, r.author, r.authorSeq));
    const rem = new Set(visibleRevs.map((r) => r.edgeId));
    if (ev.requester === root) {
        return {
            unlockId: ev.unlockId,
            eventIndex: recordIndex,
            requester: ev.requester,
            target: ev.target,
            authorized: true,
            chain: { status: 'authorized', edges: [], path: [root], perms: [...ALL_PERMISSIONS] },
        };
    }
    const hit = searchChain(visibleEdges, root, ev.requester, 'unlock', rem);
    const chain = chainOf(hit, root);
    if (chain) {
        return {
            unlockId: ev.unlockId,
            eventIndex: recordIndex,
            requester: ev.requester,
            target: ev.target,
            authorized: true,
            chain,
        };
    }
    // 最短失效证据：根可达前沿 + 被撤销切断的边
    const witness = [];
    if (visibleEdges.length === 0) {
        witness.push('向量中未见任何委托边');
    }
    else {
        witness.push('根可达: ' + (hit ? [...hit.reachable].sort().join('、') : root));
        const cut = (hit ? hit.removedFrontier : []).map((e) => `${e.edgeId}(${e.from}→${e.to})`);
        if (cut.length)
            witness.push('被已见撤销切断: ' + cut.join('；'));
    }
    return {
        unlockId: ev.unlockId,
        eventIndex: recordIndex,
        requester: ev.requester,
        target: ev.target,
        authorized: false,
        evidence: {
            kind: 'unlock-no-chain',
            eventIndex: recordIndex,
            detail: `在 ${ev.requester} 的因果视图中不存在根 → ${ev.requester} 的未撤销 unlock 链`,
            witness,
        },
    };
}
