import { ApiClient } from '../api/client';
import type { FixResponse } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';
import { ApprovalBroker } from '../approval/broker';

export async function toolFix(ctx: ServerContext, args: any): Promise<unknown> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });

    let code: string = args.code;
    const language: string = args.language;

    if (!code && args.filePath) {
        const file = readFileFromWorkspace(ctx.workspaceRoot, args.filePath);
        code = file.code;
    }

    if (!code) {
        throw Object.assign(new Error('Provide code or filePath.'), { code: -32602 });
    }

    const summary = `Fix ${args.vulnerabilityType} at line ${args.lineStart}-${args.lineEnd}\n\nEvidence: ${args.evidenceSnippet?.substring(0, 200) || '(not provided)'}`;

    const broker = new ApprovalBroker();
    await broker.start();

    try {
        const result = await broker.requestApproval(
            'securecode.fix',
            summary,
            [code, language, args.vulnerabilityType, args.lineStart, args.lineEnd, args.evidenceSnippet],
            60_000,
        );

        if (!result.approved) {
            return {
                applied: false,
                reason: result.reason,
                requestId: result.requestId,
            };
        }

        const data = await client.postJson<FixResponse>('/fix', {
            code,
            language,
            vulnerability: {
                type: args.vulnerabilityType,
                line_start: args.lineStart,
                line_end: args.lineEnd,
                evidence_snippet: args.evidenceSnippet,
            },
            ...(args.framework ? { framework: args.framework } : {}),
        });

        return {
            applied: false,
            fix: {
                fixedCode: data.fixed_code,
                diff: data.diff,
                summary: data.fix_summary,
                securityNotes: data.security_notes,
                whySecure: data.why_secure,
                importsNeeded: data.imports_needed,
                confidence: data.confidence,
            },
            note: 'Patch returned for human review. Apply in your editor — do not auto-apply.',
            approvedBy: result.requestId,
        };
    } finally {
        await broker.stop();
    }
}
