import { ApiClient } from '../api/client';
import type { FixResponse } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';
import { ApprovalBroker } from '../approval/broker';
import { mergeFixedCode } from '../attack/fixCodeMerge';

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
    const progress = args._progress as ((c: number, t: number, m: string) => void) | undefined;

    try {
        const result = await broker.requestApproval(
            'securecode.fix',
            summary,
            [code, language, args.vulnerabilityType, args.lineStart, args.lineEnd, args.evidenceSnippet],
            120_000,
            'paid-generation',
            ctx.workspaceRoot,
            { onUrl: progress ? (url) => progress(0, 1, `⏸ Approval required — open ${url} (expires in 120s)`) : undefined },
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
                ...(args.why ? { why: String(args.why).slice(0, 2000) } : {}),
                ...(args.severity ? { severity: String(args.severity).slice(0, 50) } : {}),
                ...(args.verificationEvidence ? { verification_evidence: String(args.verificationEvidence).slice(0, 4000) } : {}),
            },
            ...(args.framework ? { framework: args.framework } : {}),
            ...(Array.isArray(args.relatedFiles) && args.relatedFiles.length > 0
                ? { relatedFiles: args.relatedFiles.slice(0, 5) }
                : {}),
        });

        // Patch-apply validation: the fixer returns a fragment meant to
        // replace [replace_range] lines. Verify the range actually fits the
        // file the user has (it may have changed since the scan) so a broken
        // patch is flagged instead of silently failing in the editor.
        let applyValidation: { valid: boolean; error?: string } | undefined;
        if (data.replace_range && data.fixed_code) {
            const merge = mergeFixedCode(code, data.fixed_code, data.replace_range);
            applyValidation = merge.ok
                ? { valid: true }
                : { valid: false, error: merge.error };
        } else if (data.fixed_code) {
            applyValidation = { valid: false, error: 'The fixer did not return a replace_range; apply manually by searching for the vulnerable snippet.' };
        }

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
                replaceRange: data.replace_range,
            },
            syntax: {
                valid: data.syntax_valid,
                checked: data.syntax_checked,
                retried: data.syntax_retried,
                error: data.syntax_error,
                unavailableReason: data.syntax_unavailable_reason,
            },
            applyValidation,
            note: 'Patch returned for human review. Apply in your editor — do not auto-apply.',
            approvedBy: result.requestId,
        };
    } finally {
        await broker.stop();
    }
}
