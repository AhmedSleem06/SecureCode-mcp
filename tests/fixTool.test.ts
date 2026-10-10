// Unit tests for the enriched fix tool — evidence passthrough, patch-apply
// validation, and syntax flag surfacing (previously dropped at the MCP
// boundary).

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
    ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
    };
});

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'fix-approval', duration: 0 }),
    })),
}));

import { toolFix } from '../src/tools/fix';
import { ApiClient } from '../src/api/client';
import { ApprovalBroker } from '../src/approval/broker';

const ctx: any = { workspaceRoot: 'C:\\ws', apiUrl: 'http://localhost', apiToken: 't' };

const CODE = [
    'function handler(req, res) {',
    '  const q = "SELECT * FROM t WHERE id=" + req.body.id;',
    '  db.query(q);',
    '}',
].join('\n');

function mockFixResponse(response: any) {
    const postJson = vi.fn().mockResolvedValue(response);
    (ApiClient as any).mockImplementation(() => ({ postJson }));
    return postJson;
}

const BASE_ARGS = {
    code: CODE,
    language: 'javascript',
    vulnerabilityType: 'sql_injection',
    lineStart: 2,
    lineEnd: 2,
    evidenceSnippet: 'const q = "SELECT * FROM t WHERE id=" + req.body.id;',
};

describe('toolFix — enriched generation', () => {
    beforeEach(() => vi.clearAllMocks());

    it('passes why, severity, verification evidence and related files to /fix', async () => {
        const postJson = mockFixResponse({
            fixed_code: '  db.query("SELECT * FROM t WHERE id=?", [req.body.id]);',
            replace_range: { start_line: 2, end_line: 2 },
            syntax_valid: true,
            syntax_checked: true,
        });

        await toolFix(ctx, {
            ...BASE_ARGS,
            why: 'user input concatenated into SQL',
            severity: 'high',
            verificationEvidence: 'exploit returned all rows',
            relatedFiles: [
                { filePath: 'src/db.ts', content: 'export const db = {...}', relationship: 'config' },
            ],
        });

        const body = postJson.mock.calls[0][1];
        expect(body.vulnerability.why).toBe('user input concatenated into SQL');
        expect(body.vulnerability.severity).toBe('high');
        expect(body.vulnerability.verification_evidence).toBe('exploit returned all rows');
        expect(body.relatedFiles).toHaveLength(1);
        expect(body.relatedFiles[0].filePath).toBe('src/db.ts');
    });

    it('validates the replace_range against the file (applyValidation)', async () => {
        mockFixResponse({
            fixed_code: '  db.query("SELECT * FROM t WHERE id=?", [req.body.id]);',
            replace_range: { start_line: 2, end_line: 2 },
            syntax_valid: true,
            syntax_checked: true,
        });

        const result: any = await toolFix(ctx, BASE_ARGS);

        expect(result.applyValidation).toEqual({ valid: true });
        expect(result.syntax).toMatchObject({ valid: true, checked: true });
        expect(result.fix.replaceRange).toEqual({ start_line: 2, end_line: 2 });
        expect(result.applied).toBe(false);
    });

    it('flags an out-of-range replace_range as invalid', async () => {
        mockFixResponse({
            fixed_code: 'fixed',
            replace_range: { start_line: 2, end_line: 9999 },
        });

        const result: any = await toolFix(ctx, BASE_ARGS);

        expect(result.applyValidation.valid).toBe(false);
        expect(result.applyValidation.error).toMatch(/exceeds file length/);
    });

    it('flags a missing replace_range with a manual-apply hint', async () => {
        mockFixResponse({ fixed_code: 'fixed fragment' });

        const result: any = await toolFix(ctx, BASE_ARGS);

        expect(result.applyValidation.valid).toBe(false);
        expect(result.applyValidation.error).toMatch(/did not return a replace_range/);
    });

    it('surfaces syntax flags even when the fixer retried', async () => {
        mockFixResponse({
            fixed_code: 'fixed',
            replace_range: { start_line: 2, end_line: 2 },
            syntax_valid: true,
            syntax_checked: true,
            syntax_retried: true,
        });

        const result: any = await toolFix(ctx, BASE_ARGS);

        expect(result.syntax.retried).toBe(true);
    });

    describe('line-range consistency guard', () => {
        it('returns an actionable result when the finding line exceeds the provided code — no approval, no API call', async () => {
            // Production case 2026-10-10: a 43-line inline excerpt with a
            // finding from line 121 of the full file. The tool must fail fast
            // with a reason the calling agent can act on (retry with filePath)
            // instead of generating a patch that can never apply.
            const postJson = vi.fn().mockRejectedValue(new Error('API must not be called'));
            (ApiClient as any).mockImplementation(() => ({ postJson }));

            const result: any = await toolFix(ctx, {
                ...BASE_ARGS,
                lineStart: 121,
                lineEnd: 121,
            });

            expect(result.applied).toBe(false);
            expect(result.reason).toContain('line 121 is outside the provided code (4 lines)');
            expect(result.reason).toContain('filePath');
            expect(postJson).not.toHaveBeenCalled();
            // The guard fires before the approval broker is ever constructed.
            expect((ApprovalBroker as any).mock.results.length).toBe(0);
        });

        it('still passes lineStart=0 (no line info) straight through', async () => {
            const postJson = mockFixResponse({
                fixed_code: 'fixed',
                replace_range: { start_line: 2, end_line: 2 },
                syntax_valid: true,
                syntax_checked: true,
            });

            const result: any = await toolFix(ctx, { ...BASE_ARGS, lineStart: 0, lineEnd: 0 });

            expect(postJson).toHaveBeenCalledTimes(1);
            expect(result.applied).toBe(false);
            expect(result.fix).toBeDefined();
        });
    });

    describe('approval wiring', () => {
        function lastBrokerInstance(): any {
            const ctor = ApprovalBroker as any;
            expect(ctor.mock.results.length).toBeGreaterThan(0);
            return ctor.mock.results[ctor.mock.results.length - 1].value;
        }

        it('requests approval with a 120s timeout', async () => {
            mockFixResponse({ fixed_code: 'fixed', replace_range: { start_line: 2, end_line: 2 } });

            await toolFix(ctx, BASE_ARGS);

            const requestApproval = lastBrokerInstance().requestApproval;
            expect(requestApproval).toHaveBeenCalledTimes(1);
            const call = requestApproval.mock.calls[0];
            expect(call[0]).toBe('securecode.fix');
            expect(call[3]).toBe(120_000);
            expect(call[4]).toBe('paid-generation');
            expect(call[5]).toBe(ctx.workspaceRoot);
        });

        it('wires opts.onUrl to args._progress so clients surface the approval URL live', async () => {
            mockFixResponse({ fixed_code: 'fixed', replace_range: { start_line: 2, end_line: 2 } });
            const progress = vi.fn();

            await toolFix(ctx, { ...BASE_ARGS, _progress: progress });

            const requestApproval = lastBrokerInstance().requestApproval;
            const opts = requestApproval.mock.calls[0][6];
            expect(typeof opts.onUrl).toBe('function');

            const url = 'http://127.0.0.1:45678/?id=abc-123';
            opts.onUrl(url);
            expect(progress).toHaveBeenCalledTimes(1);
            expect(progress).toHaveBeenCalledWith(0, 1, `⏸ Approval required — open ${url} (expires in 120s)`);
        });

        it('passes onUrl: undefined when the client sent no progress callback', async () => {
            mockFixResponse({ fixed_code: 'fixed', replace_range: { start_line: 2, end_line: 2 } });

            await toolFix(ctx, BASE_ARGS);

            const requestApproval = lastBrokerInstance().requestApproval;
            const opts = requestApproval.mock.calls[0][6];
            expect(opts).toBeDefined();
            expect(opts.onUrl).toBeUndefined();
        });
    });
});
