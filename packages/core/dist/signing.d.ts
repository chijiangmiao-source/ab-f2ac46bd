export declare function base64ToBytes(b64: string): Uint8Array;
export declare function bytesToBase64(bytes: Uint8Array): string;
/** 返回用于签名/验签的规范字节（去掉 signature 字段，键名排序）。 */
export declare function signingPayload(event: Record<string, unknown>): Uint8Array;
export interface SignatureCheck {
    ok: boolean;
    reason?: 'unknown-key' | 'bad-key-encoding' | 'bad-signature-encoding' | 'bad-signature';
}
export declare function verifySignature(event: Record<string, unknown>, subjects: Record<string, string>): Promise<SignatureCheck>;
/** 供测试/示例生成签名：私钥为 32 字节。 */
export declare function signEvent(event: Record<string, unknown>, privateKey: Uint8Array): Promise<string>;
