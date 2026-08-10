import { ApiClient } from '../api/client';
import type { FixResponse } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';

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
    };
}
