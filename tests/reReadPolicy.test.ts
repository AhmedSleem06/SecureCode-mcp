import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({
            postJson: vi.fn(),
        })),
    };
});

vi.mock('../src/attack/agentScanExecutor', () => ({
    executeAction: vi.fn(),
    executeReadFileAction: vi.fn(),
    executeFlowAction: vi.fn(),
    extractFunctionBoundaries: vi.fn(),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';
import {
    coverageReReadCheck,
    formatCoverageReReadObservation,
    keyLineDigest,
    COVERAGE_REREAD_MAX_EXACT_LINES,
} from '../src/attack/investigationState';

const ctx = { workspaceRoot: '/tmp/securecode-reread-test-missing', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
const startResp = (harness?: unknown) => ({ runId: 'run-1', budget, scanCredits: 95, refundId: 'r1', ...(harness ? { harness } : {}) });
const coverageHarness = { gateMode: 'evidence', fullReadWindow: 3, reReadPolicy: 'coverage' };

function step(next: any, remaining: number, extra: Record<string, unknown> = {}) {
    return { next, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: remaining, ...extra };
}

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) mockFn.mockResolvedValueOnce(resp);
    mockFn.mockResolvedValue({ settlement: { creditsRefunded: 0, creditsUsed: 5 } });
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

function linesContent(total: number, special: Record<number, string> = {}): string {
    return Array.from({ length: total }, (_, i) => special[i + 1] ?? `const v${i + 1} = ${i + 1};`).join('\n');
}

function setupExecutors(totalLines: number) {
    (executeReadFileAction as any).mockImplementation(async (action: any) => ({
        observation: `lines ${action.startLine}-${action.endLine}`,
        actualStart: action.startLine ?? 1,
        actualEnd: action.endLine ?? totalLines,
        totalLines,
        truncated: false,
    }));
    (executeAction as any).mockResolvedValue('ok');
    (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [], truncated: false } });
    (extractFunctionBoundaries as any).mockResolvedValue(null);
}

const read = (path: string, start?: number, end?: number) => ({ type: 'read_file', path, startLine: start, endLine: end, rationale: 'read' });
const readSteps = (result: any) => result.transcript.filter((t: any) => t.action.type === 'read_file');

describe('coverageReReadCheck', () => {
    it('skips a long read that is at least 80% delivered', () => {
        const delivered = [{ range: { start: 1, end: 90 }, step: 2 }];
        const check = coverageReReadCheck({ start: 1, end: 100 }, delivered);
        expect(check.skip).toBe(true);
        expect(check.fraction).toBeCloseTo(0.9);
        expect(check.sources).toEqual(delivered);
    });

    it('executes reads of 80 lines or fewer, and long reads with mostly new lines', () => {
        expect(coverageReReadCheck({ start: 1, end: COVERAGE_REREAD_MAX_EXACT_LINES }, [{ range: { start: 1, end: 500 }, step: 1 }]).skip).toBe(false);
        expect(coverageReReadCheck({ start: 1, end: 100 }, [{ range: { start: 1, end: 70 }, step: 1 }]).skip).toBe(false);
        expect(coverageReReadCheck({ start: 1, end: 100 }, []).skip).toBe(false);
    });

    it('combines several earlier reads and the prompt-shown source', () => {
        const check = coverageReReadCheck({ start: 1, end: 200 }, [
            { range: { start: 1, end: 100 }, step: null },
            { range: { start: 101, end: 170 }, step: 4 },
            { range: { start: 400, end: 500 }, step: 5 },
        ]);
        expect(check.skip).toBe(true);
        expect(check.sources.map(s => s.step)).toEqual([null, 4]);
    });
});

describe('formatCoverageReReadObservation', () => {
    it('names the earlier reads and digests the key lines', () => {
        const content = linesContent(200, { 12: 'if (!session.isOwner) throw new Error("forbidden");', 40: 'export function handle(req) {' });
        const text = formatCoverageReReadObservation({ start: 1, end: 150 }, [{ range: { start: 1, end: 200 }, step: 2 }], content);
        expect(text.startsWith('Already read lines 1–150 at step 2.')).toBe(true);
        expect(text).toContain('12| if (!session.isOwner) throw new Error("forbidden");');
        expect(text).toContain('40| export function handle(req) {');
        expect(text).toContain('For exact code, re-read ≤ 80 lines around the line you need.');
    });

    it('describes prompt-shown source and handles missing content', () => {
        const text = formatCoverageReReadObservation({ start: 1, end: 100 }, [{ range: { start: 1, end: 100 }, step: null }], undefined);
        expect(text).toContain('Already read lines 1–100 in the target source shown in the prompt.');
        expect(text).toContain('Key lines: none matched');
    });

    it('keyLineDigest caps the number of lines', () => {
        const special: Record<number, string> = {};
        for (let i = 1; i <= 50; i++) special[i] = `const token${i} = sign(user);`;
        expect(keyLineDigest(linesContent(50, special), { start: 1, end: 50 })).toHaveLength(15);
    });
});

describe('runAgentScan — re-read policy', () => {
    beforeEach(() => vi.clearAllMocks());

    const target = { filePath: 'svc.ts', language: 'typescript', fileContent: linesContent(400) };

    it('coverage policy: a big repeat read gets a digest instead of executing, and is not a blocked strike', async () => {
        setupExecutors(600);
        mockPostJson([
            startResp(coverageHarness),
            step(read('lib.ts', 1, 200), 39),
            step(read('lib.ts', 1, 200), 38),
            step(read('lib.ts', 1, 200), 37),
            step(read('lib.ts', 1, 200), 36),
            step(null, 35, { costCapped: true, capReason: 'max_credits' }),
            step(null, 34, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        const reads = readSteps(result);
        expect(executeReadFileAction).toHaveBeenCalledTimes(1);
        for (const r of reads.slice(1)) {
            expect(r.observation.startsWith('Already read lines 1–200 at step 1.')).toBe(true);
            expect(r.observation).not.toContain('BLOCKED');
            expect(r.observation).not.toContain('RECOVERY REQUIRED');
        }
        expect(result.transcript.some((t: any) => String(t.observation).startsWith('[DETERMINISTIC RECOVERY]'))).toBe(false);
    });

    it('coverage policy: a small re-read always executes', async () => {
        setupExecutors(600);
        mockPostJson([
            startResp(coverageHarness),
            step(read('lib.ts', 1, 200), 39),
            step(read('lib.ts', 10, 60), 38),
            step(read('lib.ts', 10, 60), 37),
            step(null, 36, { costCapped: true, capReason: 'max_credits' }),
            step(null, 35, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(executeReadFileAction).toHaveBeenCalledTimes(3);
        for (const r of readSteps(result)) expect(r.observation).not.toContain('BLOCKED');
    });

    it('coverage policy: the prompt-shown target counts as delivered', async () => {
        setupExecutors(400);
        const small = { filePath: 'small.ts', language: 'typescript', fileContent: linesContent(100, { 30: 'const token = issueToken(user);' }) };
        mockPostJson([
            startResp(coverageHarness),
            step(read('small.ts'), 39),
            step(null, 38, { costCapped: true, capReason: 'max_credits' }),
            step(null, 37, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, small, {});

        expect(executeReadFileAction).not.toHaveBeenCalled();
        const [r] = readSteps(result);
        expect(r.observation).toContain('Already read lines 1–100 in the target source shown in the prompt.');
        expect(r.observation).toContain('30| const token = issueToken(user);');
    });

    it('window policy is unchanged: an identical read inside the window is blocked', async () => {
        setupExecutors(600);
        mockPostJson([
            startResp(),
            step(read('lib.ts', 1, 200), 39),
            step(read('lib.ts', 1, 200), 38),
            step(null, 37, { costCapped: true, capReason: 'max_credits' }),
            step(null, 36, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        const reads = readSteps(result);
        expect(executeReadFileAction).toHaveBeenCalledTimes(1);
        expect(reads[1].observation).toContain('BLOCKED: Lines 1-200 of "lib.ts" are one of your last 2 reads');
        expect(reads[1].observation).toContain('[Investigation checklist');
    });
});
