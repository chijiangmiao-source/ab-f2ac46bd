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
import { FailureEvidence, RecordFile, StepSnapshot, UnlockVerdict } from './types.js';
export interface FileValidation {
    ok: boolean;
    errors: string[];
}
/** 记录文件级约束：至多 8 个主体、恰好 1 个已知根、至多 24 条事件。 */
export declare function validateRecordFile(file: unknown): FileValidation;
export interface ReviewResult {
    subjectCount: number;
    eventCount: number;
    snapshots: StepSnapshot[];
    verdicts: UnlockVerdict[];
    /** 首个记录级失效证据；全部合法时为 null。 */
    firstFailure: (FailureEvidence & {
        recordIndex: number;
    }) | null;
}
export declare function reviewRecord(file: RecordFile): Promise<ReviewResult>;
