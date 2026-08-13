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

import { executeAction } from '../src/attack/agentScanExecutor';
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

        expect(result.length).toBeLessThan(10000);
        expect(result).toContain('truncated');

        fs.unlinkSync(tmpFile);
    });
});
