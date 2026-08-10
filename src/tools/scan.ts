import * as fs from 'fs';
import * as path from 'path';
import { ApiClient } from '../api/client';
import type { ScanResponse, FinalFinding, ScanFinding } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace, inferLanguage } from '../utils/files';

export async function toolScan(ctx: ServerContext, args: any): Promise<unknown> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });

    let code: string | undefined = args.code;
    let language: string | undefined = args.language;
    const filePath = args.filePath as string | undefined;

    if (!code && filePath) {
        const file = readFileFromWorkspace(ctx.workspaceRoot, filePath);
        code = file.code;
        language = language || file.language;
    }

    if (!code) {
        throw Object.assign(new Error('Provide code or filePath.'), { code: -32602 });
    }
    if (!language) {
        throw Object.assign(new Error('Provide language or filePath with a known extension.'), { code: -32602 });
    }

    const data = await client.postJson<ScanResponse>('/scan', {
        code,
        language,
        ...(filePath ? { filePath } : {}),
        scanDepth: 'auto',
    });

    const findings: (FinalFinding | ScanFinding)[] =
        data.scanType === 'advanced' && data.finalFindings
            ? data.finalFindings
            : data.findings || [];

    return {
        scanType: data.scanType,
        scanId: data.scanId,
        findings: findings.map((f: any) => ({
            type: f.type || f.check_id,
            severity: f.severity || f.extra?.severity,
            location: f.location || {
                line_start: f.start?.line,
                line_end: f.end?.line ?? f.start?.line,
            },
            message: f.message || f.extra?.message,
            evidence: f.evidence_snippet,
            confidence: f.confidence,
            why: f.why_real,
            fixStrategy: f.fix_strategy,
            fixSnippet: f.fix_snippet,
        })),
        scanSummary: data.scanSummary,
        degraded: data.degraded,
        remainingScans: data.remainingAIScans,
        plan: data.plan,
        scanCredits: data.scanCredits,
    };
}
