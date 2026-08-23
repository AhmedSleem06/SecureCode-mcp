// Vitest suite for the scan agent executor — tool dispatch.
//
// Covers:
//   - read_file: reads file, returns numbered content
//   - search_code: calls searchCode, returns formatted results
//   - trace_flow: calls trackTaint, returns formatted results
//   - check_guard: calls evaluateGuard, returns formatted result
//   - check_policy: calls API client POST /agent/scan/tool
//   - error handling: returns error string on failure
//   - truncation: long observations are truncated

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// Mock the underlying tools
vi.mock('../src/project-map/taintTracker', () => ({
    trackTaint: vi.fn(),
}));

vi.mock('../src/project-map/guardEvaluator', () => ({
    evaluateGuard: vi.fn(),
}));

vi.mock('../src/utils/searchCode', () => ({
    searchCode: vi.fn(),
    formatSearchResult: vi.fn(),
}));

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

import { executeAction, executeReadFileAction } from '../src/attack/agentScanExecutor';
import { trackTaint } from '../src/project-map/taintTracker';
import { evaluateGuard } from '../src/project-map/guardEvaluator';
import { searchCode, formatSearchResult } from '../src/utils/searchCode';
import { ApiClient } from '../src/api/client';

const ctx = { workspaceRoot: os.tmpdir(), apiUrl: 'http://localhost:3000', apiToken: 'test-token' };
const target = {
    filePath: 'test.ts',
    language: 'typescript',
    fileContent: 'export function handler() {}',
};
const client = new ApiClient({ baseUrl: 'http://localhost:3000', token: 'test-token' });

describe('executeAction — read_file', () => {
    beforeEach(() => vi.clearAllMocks());

    it('reads a file and returns numbered content', async () => {
        const tmpFile = path.join(os.tmpdir(), 'test-read.ts');
        fs.writeFileSync(tmpFile, 'line one\nline two\n');

        const result = await executeAction(
            { type: 'read_file', path: 'test-read.ts', rationale: 'read' },
            ctx, 'run-1', client, target,
        );

        expect(result).toContain('1: line one');
        expect(result).toContain('2: line two');
        expect(result).toContain('test-read.ts');

        fs.unlinkSync(tmpFile);
    });

    it('returns error string on missing file', async () => {
        const result = await executeAction(
            { type: 'read_file', path: 'nonexistent.ts', rationale: 'read' },
            ctx, 'run-1', client, target,
        );

        expect(result).toContain('Error reading file');
        expect(result).toContain('nonexistent.ts');
    });
});

describe('executeAction — search_code', () => {
    beforeEach(() => vi.clearAllMocks());

    it('calls searchCode and returns formatted results', async () => {
        (searchCode as any).mockResolvedValue({ hits: [{ path: 'a.ts', line: 5, text: 'isProjectOwner' }], total: 1, truncated: false });
        (formatSearchResult as any).mockReturnValue('a.ts:5: isProjectOwner');

        const result = await executeAction(
            { type: 'search_code', pattern: 'isProjectOwner', rationale: 'find guard' },
            ctx, 'run-1', client, target,
        );

        expect(searchCode).toHaveBeenCalledWith(os.tmpdir(), 'isProjectOwner', undefined);
        expect(result).toContain('isProjectOwner');
    });

    it('returns error string on search failure', async () => {
        (searchCode as any).mockRejectedValue(new Error('grep not found'));

        const result = await executeAction(
            { type: 'search_code', pattern: 'test', rationale: 'search' },
            ctx, 'run-1', client, target,
        );

        expect(result).toContain('Error searching');
    });
});

describe('executeAction — trace_flow', () => {
    beforeEach(() => vi.clearAllMocks());

    it('calls trackTaint and returns formatted results', async () => {
        (trackTaint as any).mockResolvedValue([{
            source: 'req.body', sourceLine: 5,
            sink: 'db.query', sinkLine: 10,
            canonicalType: 'sql_injection',
            propagationPath: [
                { line: 5, variable: 'q', operation: 'source', description: 'req.body.q' },
                { line: 10, variable: 'q', operation: 'sink-arg', description: 'db.query(q)' },
            ],
            isTainted: true,
        }]);

        // Need to write a file for the executor to read
        const tmpFile = path.join(os.tmpdir(), 'test-trace.ts');
        fs.writeFileSync(tmpFile, 'export function handler() {}');

        const result = await executeAction(
            { type: 'trace_flow', filePath: 'test-trace.ts', rationale: 'trace' },
            ctx, 'run-1', client, target,
        );

        expect(trackTaint).toHaveBeenCalled();
        expect(result).toContain('req.body');
        expect(result).toContain('db.query');
        expect(result).toContain('TAINTED');

        fs.unlinkSync(tmpFile);
    });

    it('returns "No taint flows found" when trackTaint returns empty', async () => {
        (trackTaint as any).mockResolvedValue([]);

        const tmpFile = path.join(os.tmpdir(), 'test-trace-empty.ts');
        fs.writeFileSync(tmpFile, 'export function handler() {}');

        const result = await executeAction(
            { type: 'trace_flow', filePath: 'test-trace-empty.ts', rationale: 'trace' },
            ctx, 'run-1', client, target,
        );

        expect(result).toContain('No taint flows found');

        fs.unlinkSync(tmpFile);
    });
});

describe('executeAction — check_guard', () => {
    beforeEach(() => vi.clearAllMocks());

    it('calls evaluateGuard and returns formatted result', async () => {
        (evaluateGuard as any).mockResolvedValue({
            guardName: 'requireAuth',
            guardType: 'auth-jwt-verify',
            attackType: 'broken_access_control',
            effective: true,
            reason: 'JWT verification prevents unauthenticated access',
        });

        const guardCode = 'export async function requireAuth(req, res, next) { /* jwt verify */ next(); }';
        const tmpFile = path.join(os.tmpdir(), 'test-guard.ts');
        fs.writeFileSync(tmpFile, guardCode);

        const result = await executeAction(
            { type: 'check_guard', filePath: 'test-guard.ts', guardName: 'requireAuth', attackType: 'broken_access_control', rationale: 'check' },
            ctx, 'run-1', client, target,
        );

        expect(evaluateGuard).toHaveBeenCalled();
        expect(result).toContain('EFFECTIVE');
        expect(result).toContain('requireAuth');
        expect(result).toContain('broken_access_control');

        fs.unlinkSync(tmpFile);
    });

    it('returns "not found" when guard function is missing', async () => {
        const tmpFile = path.join(os.tmpdir(), 'test-no-guard.ts');
        fs.writeFileSync(tmpFile, 'export function otherFunc() {}');

        const result = await executeAction(
            { type: 'check_guard', filePath: 'test-no-guard.ts', guardName: 'missingGuard', attackType: 'sql_injection', rationale: 'check' },
            ctx, 'run-1', client, target,
        );

        expect(result).toContain('not found');
        expect(result).toContain('missingGuard');

        fs.unlinkSync(tmpFile);
    });
});

describe('executeAction — check_policy', () => {
    beforeEach(() => vi.clearAllMocks());

    it('calls the API client POST /agent/scan/tool', async () => {
        const mockPostJson = vi.fn().mockResolvedValue({ observation: 'Found missing-ownership-update' });
        (ApiClient as any).mockImplementation(() => ({ postJson: mockPostJson }));

        const apiClient = new ApiClient({ baseUrl: 'http://localhost:3000', token: 'test' });

        const result = await executeAction(
            { type: 'check_policy', filePath: 'test.ts', rationale: 'check' },
            ctx, 'run-1', apiClient, target,
        );

        expect(mockPostJson).toHaveBeenCalledWith('/agent/scan/tool', expect.objectContaining({
            runId: 'run-1',
            action: expect.objectContaining({ type: 'check_policy' }),
        }));
        expect(result).toContain('missing-ownership-update');
    });

    it('returns error string on API failure', async () => {
        const mockPostJson = vi.fn().mockRejectedValue(new Error('API down'));
        (ApiClient as any).mockImplementation(() => ({ postJson: mockPostJson }));

        const apiClient = new ApiClient({ baseUrl: 'http://localhost:3000', token: 'test' });

        const result = await executeAction(
            { type: 'check_policy', filePath: 'test.ts', rationale: 'check' },
            ctx, 'run-1', apiClient, target,
        );

        expect(result).toContain('Error running check_policy');
    });
});

describe('executeAction — truncation', () => {
    it('truncates very long observations', async () => {
        const longContent = 'x'.repeat(20000);
        const tmpFile = path.join(os.tmpdir(), 'test-long.ts');
        fs.writeFileSync(tmpFile, longContent);

        const result = await executeAction(
            { type: 'read_file', path: 'test-long.ts', rationale: 'read' },
            ctx, 'run-1', client, target,
        );

        expect(result.length).toBeLessThan(17000);
        expect(result).toContain('truncated');

        fs.unlinkSync(tmpFile);
    });
});

describe('executeReadFileAction — structured metadata', () => {
    beforeEach(() => vi.clearAllMocks());

    it('returns actualStart/actualEnd for a ranged read', async () => {
        const content = Array.from({ length: 500 }, (_, i) => `line ${i + 1}`).join('\n');
        const tmpFile = path.join(os.tmpdir(), 'test-range.ts');
        fs.writeFileSync(tmpFile, content);

        const result = await executeReadFileAction(
            { type: 'read_file', path: 'test-range.ts', startLine: 10, endLine: 20, rationale: 'read' },
            ctx,
        );

        expect(result.actualStart).toBe(10);
        expect(result.actualEnd).toBe(20);
        expect(result.totalLines).toBe(500);
        expect(result.truncated).toBe(false);
        expect(result.observation).toContain('lines 10-20 of 500');

        fs.unlinkSync(tmpFile);
    });

    it('clamps endLine to totalLines', async () => {
        const content = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`).join('\n');
        const tmpFile = path.join(os.tmpdir(), 'test-clamp.ts');
        fs.writeFileSync(tmpFile, content);

        const result = await executeReadFileAction(
            { type: 'read_file', path: 'test-clamp.ts', startLine: 50, endLine: 2000, rationale: 'read' },
            ctx,
        );

        expect(result.actualStart).toBe(50);
        expect(result.actualEnd).toBe(100);
        expect(result.totalLines).toBe(100);
        expect(result.truncated).toBe(false);

        fs.unlinkSync(tmpFile);
    });

    it('returns truncated=true for a large file with no range', async () => {
        const content = Array.from({ length: 500 }, (_, i) => `function func${i}() { return ${i}; }`).join('\n');
        const tmpFile = path.join(os.tmpdir(), 'test-large.ts');
        fs.writeFileSync(tmpFile, content);

        const result = await executeReadFileAction(
            { type: 'read_file', path: 'test-large.ts', rationale: 'read' },
            ctx,
        );

        expect(result.totalLines).toBe(500);
        expect(result.truncated).toBe(true);
        expect(result.actualStart).toBe(0);
        expect(result.actualEnd).toBe(0);
        expect(result.observation).toContain('LARGE FILE');
        expect(result.observation).toContain('function map');

        fs.unlinkSync(tmpFile);
    });

    it('returns full coverage for a small file with no range', async () => {
        const content = 'line one\nline two\nline three';
        const tmpFile = path.join(os.tmpdir(), 'test-small.ts');
        fs.writeFileSync(tmpFile, content);

        const result = await executeReadFileAction(
            { type: 'read_file', path: 'test-small.ts', rationale: 'read' },
            ctx,
        );

        expect(result.actualStart).toBe(1);
        expect(result.actualEnd).toBe(3);
        expect(result.totalLines).toBe(3);
        expect(result.truncated).toBe(false);
        expect(result.observation).toContain('1: line one');

        fs.unlinkSync(tmpFile);
    });

    it('returns totalLines=0 on error', async () => {
        const result = await executeReadFileAction(
            { type: 'read_file', path: 'nonexistent.ts', rationale: 'read' },
            ctx,
        );

        expect(result.totalLines).toBe(0);
        expect(result.actualStart).toBe(0);
        expect(result.actualEnd).toBe(0);
        expect(result.observation).toContain('Error reading file');
    });
});
