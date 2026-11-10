// Vitest suite for agent-scan landing mode, no-finish salvage, and
// split-file (segment) scoping in the scan agent loop.

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

import { runAgentScan, partitionSegmentFindings, buildFunctionMap } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';

const ctx = { workspaceRoot: '/tmp/securecode-landing-test-missing', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const startResp = { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' };

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
    (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'big.ts', line: 1 }], truncated: false } });
    (extractFunctionBoundaries as any).mockResolvedValue(null);
}

describe('runAgentScan — landing mode', () => {
    beforeEach(() => vi.clearAllMocks());

    const target = { filePath: 'small.ts', language: 'typescript', fileContent: linesContent(100) };

    it('accepts an early finish as forced-incomplete when the step response says landing', async () => {
        setupExecutors(100);
        const mockFn = mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'small.ts', startLine: 1, endLine: 100, rationale: 'read it' }, 39),
            step({ type: 'finish', findings: [], summary: 'landing finish', selfCritique: 'done' }, 38, { landing: true }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('forced_incomplete');
        expect(result.summary).toBe('landing finish');
        expect(result.coverageGaps.some(g => g.title.includes('Investigation step not completed'))).toBe(true);
        const stepCalls = (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step');
        expect(stepCalls).toHaveLength(2);
    });

    it('derives landing from serverBudget when the response has no landing field', async () => {
        setupExecutors(100);
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'small.ts', startLine: 1, endLine: 100, rationale: 'read it' }, 39),
            step({ type: 'finish', findings: [], summary: 'out of budget', selfCritique: 'done' }, 38, {
                serverBudget: { costSpentUsd: 3.95, costCapUsd: 4.0, creditsUsed: 15, maxCredits: 15, extensionsGranted: 5 },
            }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('forced_incomplete');
    });

    it('rejects the same early finish when the server budget can still be extended', async () => {
        setupExecutors(100);
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'small.ts', startLine: 1, endLine: 100, rationale: 'read it' }, 39),
            step({ type: 'finish', findings: [], summary: 'premature', selfCritique: 'done' }, 38, {
                serverBudget: { costSpentUsd: 1.0, costCapUsd: 4.0, creditsUsed: 5, maxCredits: 15, extensionsGranted: 0 },
            }),
            step(null, 37, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.transcript.some(t => t.action.type === 'system_event' && (t.action as any).eventType === 'finish_rejected')).toBe(true);
    });
});

describe('runAgentScan — salvage without a finish', () => {
    beforeEach(() => vi.clearAllMocks());

    it('returns an incomplete result with recent reasoning, unread ranges and read ranges', async () => {
        setupExecutors(300);
        const target = { filePath: 'svc.ts', language: 'typescript', fileContent: linesContent(300, { 250: 'const token = session.issue(user);' }) };
        const mockFn = mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'svc.ts', startLine: 1, endLine: 100, rationale: 'first look' }, 39),
            step({ type: 'search_code', pattern: 'issueToken', rationale: 'find token issuance' }, 38),
            step({ type: 'read_file', path: 'svc.ts', startLine: 101, endLine: 150, rationale: 'follow the handler' }, 37),
            step({ type: 'trace_flow_cross_file', filePath: 'svc.ts', rationale: 'trace user input to the session store' }, 36),
            step(null, 35, { costCapped: true, capReason: 'max_credits' }),
            step(null, 34, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('incomplete');
        expect(result.terminationReason).toBe('cost_cap');
        expect(result.findings).toEqual([]);
        expect(result.investigationNotes.map(n => n.detail)).toEqual([
            'find token issuance',
            'follow the handler',
            'trace user input to the session store',
        ]);
        const unread = result.coverageGaps.filter(g => g.title.startsWith('Unread range'));
        expect(unread).toHaveLength(1);
        expect(unread[0].title).toContain('lines 151-300');
        expect(unread[0].priority).toBe('high');
        expect(result.summary).toContain('Lines read in svc.ts: 1–150');
        const closeCall = (mockFn.mock.calls as any[]).find(c => c[0] === '/agent/scan/close');
        expect(closeCall[1].status).toBe('incomplete');
    });

    it('marks unread ranges without security keywords as medium priority', async () => {
        setupExecutors(200);
        const target = { filePath: 'util.ts', language: 'typescript', fileContent: linesContent(200) };
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'util.ts', startLine: 1, endLine: 50, rationale: 'start' }, 39),
            step(null, 38),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('incomplete');
        expect(result.terminationReason).toBe('budget_exhausted');
        const unread = result.coverageGaps.filter(g => g.title.startsWith('Unread range'));
        expect(unread[0].priority).toBe('medium');
        expect(result.investigationNotes).toHaveLength(1);
    });

    it('still returns the plain result when no step was delivered', async () => {
        setupExecutors(100);
        mockPostJson([startResp, step(null, 39, { costCapped: true })]);
        const result = await runAgentScan(ctx, { filePath: 'x.ts', language: 'typescript', fileContent: 'x' }, {});
        expect(result.status).toBe('incomplete');
        expect(result.stepsUsed).toBe(0);
    });

    it('asks once for a final report after a capped step with no finish, and keeps that finish', async () => {
        setupExecutors(300);
        const target = { filePath: 'svc.ts', language: 'typescript', fileContent: linesContent(300) };
        const mockFn = mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'svc.ts', startLine: 1, endLine: 100, rationale: 'first look' }, 39),
            step(null, 38, { costCapped: true, capReason: 'max_credits' }),
            step({ type: 'finish', findings: [], summary: 'final report', selfCritique: 'budget reached' }, 37, { landing: true }),
        ]);

        const result = await runAgentScan(ctx, target, {});

        const stepCalls = mockFn.mock.calls.filter((c: any[]) => String(c[0]).includes('/agent/scan/step'));
        expect(stepCalls).toHaveLength(3);
        expect(result.transcript.some(t => t.action.type === 'system_event' && String((t.action as any).message).startsWith('BUDGET REACHED'))).toBe(true);
        expect(result.summary).toContain('final report');
    });
});

describe('runAgentScan — segment (part of a split file)', () => {
    beforeEach(() => vi.clearAllMocks());

    const segment = { groupId: 'grp-1', index: 2, total: 3, startLine: 1001, endLine: 2000 };
    const content = linesContent(3000, { 2500: 'const token = authenticate(req.headers.authorization);' });
    const target = { filePath: 'big.ts', language: 'typescript', fileContent: content };

    it('tags start/step requests, scopes the gate, and moves out-of-range findings to notes', async () => {
        setupExecutors(3000);
        (extractFunctionBoundaries as any).mockResolvedValue([
            { name: 'a', startLine: 1, endLine: 900 },
            { name: 'inner', startLine: 10, endLine: 20 },
            { name: 'b', startLine: 901, endLine: 2500 },
        ]);
        const findings = [
            { line: 1200, type: 'broken_access_control', severity: 'medium', confidence: 85, evidence: 'no check', why: 'missing ownership' },
            { line: 2003, type: 'xss', severity: 'medium', confidence: 80, evidence: 'raw html', why: 'unescaped output near the edge' },
            { line: 2700, type: 'sql_injection', severity: 'high', confidence: 80, evidence: 'concat', why: 'string-built query in another part' },
        ];
        const mockFn = mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'big.ts', startLine: 1001, endLine: 1500, rationale: 'r' }, 39),
            step({ type: 'read_file', path: 'big.ts', startLine: 1501, endLine: 2000, rationale: 'r' }, 38),
            step({ type: 'trace_flow_cross_file', filePath: 'big.ts', rationale: 'r' }, 37),
            step({ type: 'check_policy', filePath: 'big.ts', rationale: 'r' }, 36),
            step({ type: 'read_config', configKind: 'all', rationale: 'r' }, 35),
            step({ type: 'find_tests', filePath: 'big.ts', rationale: 'r' }, 34),
            step({ type: 'finish', findings, summary: 'part done', selfCritique: 'done' }, 33),
        ]);

        const result = await runAgentScan(ctx, target, { segment });

        const startCall = (mockFn.mock.calls as any[]).find(c => c[0] === '/agent/scan/start');
        expect(startCall[1]).toEqual({ segment: { groupId: 'grp-1', index: 2, total: 3 } });
        const stepCalls = (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step');
        for (const call of stepCalls) {
            expect(call[1].target.segment).toEqual(segment);
            expect(call[1].target.functionMap).toEqual([
                { name: 'a', startLine: 1, endLine: 900 },
                { name: 'b', startLine: 901, endLine: 2500 },
            ]);
        }

        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.segment).toEqual(segment);
        expect(result.findings.map(f => f.line).sort()).toEqual([1200, 2003]);
        const outside = result.investigationNotes.filter(n => n.title.startsWith('Outside this part (lines 1001–2000)'));
        expect(outside).toHaveLength(1);
        expect(outside[0].line).toBe(2700);
        expect(outside[0].detail).toContain('string-built query');
    });

    it('applies the read cap of the part, not the whole file', async () => {
        const small = { groupId: 'grp-2', index: 1, total: 2, startLine: 1, endLine: 150 };
        const reads = (count: number) => Array.from({ length: count }, (_, i) =>
            step({ type: 'read_file', path: 'big.ts', startLine: 1 + i * 10, endLine: 10 + i * 10, rationale: 'r' }, 39 - i));

        setupExecutors(3000);
        mockPostJson([startResp, ...reads(6), step(null, 30)]);
        const scoped = await runAgentScan(ctx, target, { segment: small });
        const scopedReads = scoped.transcript.filter(t => t.action.type === 'read_file');
        expect(scopedReads[5].observation).toContain('NOTE: You have read');
        expect(scopedReads[4].observation).not.toContain('NOTE: You have read');

        vi.clearAllMocks();
        setupExecutors(3000);
        mockPostJson([startResp, ...reads(6), step(null, 30)]);
        const unscoped = await runAgentScan(ctx, target, {});
        const unscopedReads = unscoped.transcript.filter(t => t.action.type === 'read_file');
        expect(unscopedReads[5].observation).not.toContain('NOTE: You have read');
    });

    it('salvage gaps are limited to the part', async () => {
        setupExecutors(3000);
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: 'big.ts', startLine: 1001, endLine: 1400, rationale: 'r' }, 39),
            step(null, 38, { costCapped: true }),
            step(null, 37, { costCapped: true }),
        ]);
        const result = await runAgentScan(ctx, target, { segment });
        const unread = result.coverageGaps.filter(g => g.title.startsWith('Unread range'));
        expect(unread.map(g => g.title)).toEqual(['Unread range: lines 1401-2000 of big.ts']);
        expect(result.summary).toContain('part 2 of 3, lines 1001–2000');
        expect(result.segment).toEqual(segment);
    });
});

describe('segment helpers', () => {
    it('partitionSegmentFindings keeps findings within ±5 lines of the edges', () => {
        const seg = { groupId: 'g', index: 1, total: 2, startLine: 100, endLine: 200 };
        const mk = (line: number) => ({ line, type: 't', severity: 'low' as const, confidence: 50, evidence: 'e', why: 'w' });
        const { inRange, notes } = partitionSegmentFindings([mk(94), mk(95), mk(150), mk(205), mk(206)], seg, 'f.ts');
        expect(inRange.map(f => f.line)).toEqual([95, 150, 205]);
        expect(notes.map(n => n.line)).toEqual([94, 206]);
        expect(notes[0].title).toBe('Outside this part (lines 100–200): t at line 94');
        expect(partitionSegmentFindings([mk(1)], undefined, 'f.ts').inRange).toHaveLength(1);
    });

    it('buildFunctionMap keeps outermost entries and caps at 200', () => {
        const many = Array.from({ length: 250 }, (_, i) => ({ name: `f${i}`, startLine: i * 10 + 1, endLine: i * 10 + 9 }));
        expect(buildFunctionMap(many)).toHaveLength(200);
        expect(buildFunctionMap(undefined)).toEqual([]);
    });
});
