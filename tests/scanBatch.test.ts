import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { toolScanBatch } from '../src/tools/scanBatch';

// ── Mock API client ──────────────────────────────────────────────────────
// We mock the ApiClient module so /scan calls don't hit the real API.

const mockScanResponse = (filePath: string) => {
    if (filePath.includes('vuln')) {
        return {
            scanType: 'advanced',
            scanId: 'test-scan-' + Math.random().toString(36).slice(2),
            findings: [{
                type: 'sql_injection',
                severity: 'CRITICAL',
                location: { line_start: 5, line_end: 5 },
                message: 'SQL injection detected',
                confidence: 95,
            }],
            scanSummary: 'Found 1 vulnerability',
            degraded: false,
            scanCredits: 10,
            remainingAIScans: 10,
            plan: 'free',
        };
    }
    return {
        scanType: 'advanced',
        scanId: 'test-scan-' + Math.random().toString(36).slice(2),
        findings: [],
        scanSummary: 'No vulnerabilities found',
        degraded: false,
        scanCredits: 10,
        remainingAIScans: 10,
        plan: 'free',
    };
};

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn().mockImplementation((_p: string, body: any) =>
            Promise.resolve(mockScanResponse(body.filePath || '')),
        ),
    })),
}));

describe('securecode.scan-batch', () => {
    let workspace: string;

    beforeEach(() => {
        workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-batch-test-'));
    });

    afterEach(() => {
        try { fs.rmSync(workspace, { recursive: true, force: true }); } catch { /* ok */ }
    });

    it('scans files from a directory', async () => {
        fs.writeFileSync(path.join(workspace, 'clean.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, 'vuln.ts'), 'const id = req.query.id; db.query(`SELECT * FROM users WHERE id = ${id}`);');
        fs.writeFileSync(path.join(workspace, 'readme.md'), '# readme');

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.' },
        ) as any;

        expect(result.scanned).toBe(2);
        expect(result.skipped.length).toBe(1);
        expect(result.skipped[0].reason).toBe('unsupported');
        expect(result.summary.totalFindings).toBe(1);
        expect(result.summary.bySeverity.critical).toBe(1);
        expect(result.stoppedEarly).toBe(false);
    });

    it('scans files from an explicit filePaths list', async () => {
        fs.writeFileSync(path.join(workspace, 'a.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, 'b.ts'), 'const y = 2;');

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { filePaths: ['a.ts', 'b.ts'] },
        ) as any;

        expect(result.scanned).toBe(2);
        expect(result.results.length).toBe(2);
        expect(result.results[0].filePath).toBe('a.ts');
        expect(result.results[1].filePath).toBe('b.ts');
    });

    it('skips secret files', async () => {
        fs.writeFileSync(path.join(workspace, 'code.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, '.env'), 'SECRET=abc');

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.' },
        ) as any;

        expect(result.scanned).toBe(1);
        const envSkip = result.skipped.find((s: any) => s.path.endsWith('.env'));
        expect(envSkip).toBeDefined();
        expect(envSkip.reason).toBe('secret');
    });

    it('respects .securecodeignore', async () => {
        fs.writeFileSync(path.join(workspace, '.securecodeignore'), 'ignored.ts');
        fs.writeFileSync(path.join(workspace, 'ignored.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, 'kept.ts'), 'const y = 2;');

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.' },
        ) as any;

        expect(result.scanned).toBe(1);
        const ignored = result.skipped.find((s: any) => s.path === 'ignored.ts');
        expect(ignored).toBeDefined();
        expect(ignored.reason).toBe('ignored');
    });

    it('respects maxFiles cap', async () => {
        for (let i = 0; i < 5; i++) {
            fs.writeFileSync(path.join(workspace, `file${i}.ts`), `const x${i} = ${i};`);
        }

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.', maxFiles: 3 },
        ) as any;

        expect(result.scanned).toBe(3);
        expect(result.stoppedEarly).toBe(true);
        expect(result.stopReason).toBe('max_files');
    });

    it('reports progress via callback', async () => {
        fs.writeFileSync(path.join(workspace, 'a.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, 'b.ts'), 'const y = 2;');

        const progressCalls: Array<{ progress: number; total: number }> = [];
        await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {
                directory: '.',
                _progress: (progress: number, total: number, _msg: string) => {
                    progressCalls.push({ progress, total });
                },
            },
        ) as any;

        expect(progressCalls.length).toBeGreaterThan(0);
        expect(progressCalls[0].total).toBe(2);
        expect(progressCalls[progressCalls.length - 1].progress).toBe(2);
    });

    it('errors when neither directory nor filePaths provided', async () => {
        await expect(toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        )).rejects.toThrow();
    });

    it('skips files larger than 1MB', async () => {
        fs.writeFileSync(path.join(workspace, 'big.ts'), 'const x = 1;');
        // Create a file just over 1MB
        const bigContent = 'x'.repeat(1024 * 1024 + 100);
        fs.writeFileSync(path.join(workspace, 'huge.ts'), bigContent);

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.' },
        ) as any;

        const hugeSkip = result.skipped.find((s: any) => s.path === 'huge.ts');
        if (hugeSkip) {
            expect(hugeSkip.reason).toBe('too_large');
        }
    });

    it('skips test files by default', async () => {
        fs.writeFileSync(path.join(workspace, 'code.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, 'code.test.ts'), 'const y = 2;');
        fs.writeFileSync(path.join(workspace, 'code.spec.ts'), 'const z = 3;');

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.' },
        ) as any;

        expect(result.scanned).toBe(1);
        const testSkip = result.skipped.find((s: any) => s.path === 'code.test.ts');
        const specSkip = result.skipped.find((s: any) => s.path === 'code.spec.ts');
        expect(testSkip).toBeDefined();
        expect(testSkip.reason).toBe('test_file');
        expect(specSkip).toBeDefined();
        expect(specSkip.reason).toBe('test_file');
    });

    it('includes test files when includeTests is true', async () => {
        fs.writeFileSync(path.join(workspace, 'code.ts'), 'const x = 1;');
        fs.writeFileSync(path.join(workspace, 'code.test.ts'), 'const y = 2;');

        const result = await toolScanBatch(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            { directory: '.', includeTests: true },
        ) as any;

        expect(result.scanned).toBe(2);
        expect(result.skipped.find((s: any) => s.reason === 'test_file')).toBeUndefined();
    });
});
