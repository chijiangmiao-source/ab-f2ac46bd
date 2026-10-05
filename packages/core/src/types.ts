/**
 * 离线委托/解锁记录的核心数据模型。
 *
 * 记录是“离线接收”的：每条事件自带作者递增计数（seq）以及作者在签发时
 * 已经观察到的所有主体计数向量（seen）。该向量构成因果历史，解锁请求只能
 * 沿其向量中“已见且未撤销”的有效委托链获得授权。
 */

/** 权限位。权限集合只能随委托缩小（子集关系）。 */
export type Permission = 'delegate' | 'unlock' | 'revoke';

export const ALL_PERMISSIONS: readonly Permission[] = ['delegate', 'unlock', 'revoke'];

/** 委托事件：from 把 perms 委托给 to，委托边编号为 edgeId（记录内全局唯一）。 */
export interface DelegationEvent {
  kind: 'delegation';
  recordIndex: number;
  author: string;
  seq: number;
  /** 签发时已见的各主体最大计数（因果向量）。 */
  seen: Record<string, number>;
  edgeId: string;
  from: string;
  to: string;
  perms: Permission[];
  signature: string;
}

/** 撤销事件：撤销指定的委托边（只切断该边及其后代）。 */
export interface RevocationEvent {
  kind: 'revocation';
  recordIndex: number;
  author: string;
  seq: number;
  seen: Record<string, number>;
  edgeId: string;
  signature: string;
}

/** 解锁请求事件：requester 请求解锁 target。 */
export interface UnlockEvent {
  kind: 'unlock';
  recordIndex: number;
  author: string;
  seq: number;
  seen: Record<string, number>;
  unlockId: string;
  requester: string;
  target: string;
  signature: string;
}

export type AuthEvent = DelegationEvent | RevocationEvent | UnlockEvent;

export interface RecordFile {
  /** 至多 8 个主体；键为主体标识（公钥的短标签或完整 Base64 公钥）。 */
  subjects: Record<string, string>;
  /** 根主体：拥有全部权限的初始权威。 */
  root: string;
  /** 至多 24 条事件，按记录顺序排列。 */
  events: AuthEvent[];
}

/** 一条存活的授权边。 */
export interface AuthEdge {
  edgeId: string;
  from: string;
  to: string;
  perms: Permission[];
  /** 建立该边的记录下标。 */
  bornAt: number;
  /** 截至某一步，沿边向下游继承的“撤销标记”是否已到达该边本身。 */
}

/** 某次复核中一条撤销的可见信息。 */
export interface VisibleRevocation {
  edgeId: string;
  revokedAt: number;
  author: string;
}

/** 规范授权链：根 → ... → 请求者。 */
export interface AuthChain {
  status: 'authorized';
  /** 从根到请求者的边编号序列。 */
  edges: string[];
  /** 链上主体序列，含根与请求者。 */
  path: string[];
  /** 链上每一跳的权限交集（末跳仍含 unlock）。 */
  perms: Permission[];
}

/** 最短失效证据。 */
export type FailureEvidence =
  | { kind: 'malformed-event'; eventIndex: number; reason: string }
  | { kind: 'unknown-key'; subject: string }
  | { kind: 'bad-signature'; eventIndex: number }
  | { kind: 'seq-jump'; eventIndex: number; subject: string; expected: number; actual: number }
  | { kind: 'unknown-predecessor'; eventIndex: number; subject: string; referenced: number; known: number }
  | { kind: 'cycle'; eventIndex: number; edges: string[]; cycle: string[] }
  | { kind: 'privilege-escalation'; eventIndex: number; edgeId: string; granted: Permission[]; held: Permission[] }
  | { kind: 'not-delegator'; eventIndex: number; edgeId: string; from: string }
  | { kind: 'revoke-unknown'; eventIndex: number; edgeId: string }
  | { kind: 'revoke-not-reachable'; eventIndex: number; edgeId: string; author: string }
  | { kind: 'duplicate-edge'; eventIndex: number; edgeId: string }
  | { kind: 'unlock-bad-author'; eventIndex: number; author: string; requester: string }
  | { kind: 'unlock-no-chain'; eventIndex: number; detail: string; witness: string[] };

export interface UnlockVerdict {
  unlockId: string;
  eventIndex: number;
  requester: string;
  target: string;
  authorized: boolean;
  chain?: AuthChain;
  evidence?: FailureEvidence;
}

/** 单步快照：页面回放时保留的全部可见状态。 */
export interface StepSnapshot {
  index: number;
  /** 截至该步（含）仍然存活的授权边。 */
  activeEdges: AuthEdge[];
  /** 截至该步作者可见的撤销（边编号 → 撤销所在记录下标）。 */
  visibleRevocations: VisibleRevocation[];
  /** 若该步是解锁事件，其裁决；否则为 null。 */
  verdict: UnlockVerdict | null;
  /** 该步事件本身是否通过记录级校验（签名/计数/前驱）。 */
  eventValid: boolean;
}
