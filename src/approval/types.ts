import * as crypto from 'crypto';

export interface ApprovalRequest {
    id: string;
    tool: string;
    summary: string;
    operationHash: string;
    createdAt: number;
    expiresAt: number;
}

export interface ApprovalResult {
    approved: boolean;
    reason: string;
    requestId: string;
    duration: number;
}

export interface AuditEntry {
    timestamp: string;
    requestId: string;
    tool: string;
    operationHash: string;
    approved: boolean;
    reason: string;
    durationMs: number;
}

export function hashOperation(tool: string, ...parts: unknown[]): string {
    const data = JSON.stringify({ tool, parts });
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

export function createApprovalRequest(
    tool: string,
    summary: string,
    operationParts: unknown[],
    timeoutMs: number = 60_000,
): ApprovalRequest {
    const now = Date.now();
    return {
        id: crypto.randomUUID(),
        tool,
        summary,
        operationHash: hashOperation(tool, ...operationParts),
        createdAt: now,
        expiresAt: now + timeoutMs,
    };
}

export function isExpired(req: ApprovalRequest, now: number = Date.now()): boolean {
    return now > req.expiresAt;
}
