// Unit tests for the enriched fix tool — evidence passthrough, patch-apply
// validation, and syntax flag surfacing (previously dropped at the MCP
// boundary).

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
}));

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'fix-approval', duration: 0 }),
    })),
}));

import { toolFix } from '../src/tools/fix';
import { ApiClient } from '../src/api/client';

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
});
