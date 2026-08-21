import * as crypto from 'crypto';

export type OperationCategory =
    | 'read-only'
    | 'sandboxed-verification'
    | 'paid-generation'
    | 'workspace-mutation';

export interface ApprovalRequest {
    id: string;
    tool: string;
    summary: string;
    operationHash: string;
    createdAt: number;
    expiresAt: number;
    decisionToken: string;
    category: OperationCategory;
    workspaceId: string | null;
}

export interface ApprovalResult {
    approved: boolean;
    reason: string;
    requestId: string;
    duration: number;
    category?: OperationCategory;
}

export type AuditReason =
    | 'approved'
    | 'denied'
    | 'timeout'
    | 'cancelled'
    | 'expired'
    | 'invalid-token'
    | 'replayed'
    | 'shutdown';

export interface AuditEntry {
    timestamp: string;
    requestId: string;
    tool: string;
    operationHash: string;
    category: OperationCategory | 'unknown';
    workspaceId: string | null;
    approved: boolean;
    reason: AuditReason;
    durationMs: number;
}

export function hashOperation(tool: string, ...parts: unknown[]): string {
    const data = JSON.stringify({ tool, parts });
    return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

export function workspaceIdFromRoot(workspaceRoot: string | null): string | null {
    if (!workspaceRoot) return null;
    return crypto.createHash('sha256').update(workspaceRoot).digest('hex').substring(0, 16);
}

export function createApprovalRequest(
    tool: string,
    summary: string,
    operationParts: unknown[],
    timeoutMs: number = 60_000,
    category: OperationCategory = 'paid-generation',
    workspaceRoot: string | null = null,
): ApprovalRequest {
    const now = Date.now();
    return {
        id: crypto.randomUUID(),
        tool,
        summary,
        operationHash: hashOperation(tool, ...operationParts),
        createdAt: now,
        expiresAt: now + timeoutMs,
        decisionToken: crypto.randomBytes(16).toString('hex'),
        category,
        workspaceId: workspaceIdFromRoot(workspaceRoot),
    };
}

export function isExpired(req: ApprovalRequest, now: number = Date.now()): boolean {
    return now > req.expiresAt;
}
