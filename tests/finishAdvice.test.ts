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
    createRunTestsRefusalTracker: () => ({ counts: new Map(), disabled: false }),
}));

import { runAgentScan, candidateIsReported, withOpenQuestions } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';

const ctx = { workspaceRoot: '/tmp/securecode-advice-test-missing', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const startResp = {
    runId: 'run-1',
    budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 },
    scanCredits: 95,
    refundId: 'r1',
    harness: { gateMode: 'evidence', fullReadWindow: 3, reReadPolicy: 'coverage' },
};
const lines = Array.from({ length: 20 }, (_, i) => `const v${i + 1} = ${i + 1};`);
lines[2] = 'db.query("SELECT * FROM t WHERE id = " + req.query.id);';
const target = { filePath: 'small.ts', language: 'typescript', fileContent: lines.join('\n') };
const sqli = { line: 3, type: 'sql_injection', severity: 'high', confidence: 80, evidence: 'db.query("SELECT ... " + req.query.id)', why: 'an anonymous caller changes the query through ?id=' };

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

describe('finish checklist gives advice instead of rejecting', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        (executeReadFileAction as any).mockImplementation(async (action: any) => ({
            observation: 'lines', actualStart: action.startLine ?? 1, actualEnd: action.endLine ?? 20, totalLines: 20, truncated: false,
        }));
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'no flow', flowResult: { status: 'none', hops: [], truncated: false } });
        (extractFunctionBoundaries as any).mockResolvedValue(null);
    });

    it('accepts a finish with an open evidence question at once, as a normal finish, with the question on the finding', async () => {
        const mockFn = mockPostJson([
            startResp,
            step({ type: 'finish', findings: [sqli], summary: 'one finding', selfCritique: 'checked the query' }, 39, { review: { ran: true, verdict: 'accept' } }),
        ]);
        const result = await runAgentScan(ctx, target, {});

        const stepCalls = (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step');
        expect(stepCalls).toHaveLength(1);
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.transcript.some(t => /FINISH REJECTED/.test(String(t.observation)))).toBe(false);
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].openQuestions).toContain('No traced flow or runtime test showed attacker input reaching this line.');
        expect(result.findings[0].aiReview).toEqual({ status: 'reviewed' });
        expect(result.investigationNotes.filter(n => n.line === 3)).toEqual([]);
    });
});

describe('candidateIsReported / withOpenQuestions', () => {
    const candidate = { rootCauseId: 'sql_injection:3', type: 'sql_injection', locations: [{ line: 3 }] };

    it('treats a candidate as reported when the final report has its root cause or the same type within 2 lines', () => {
        expect(candidateIsReported(candidate, [{ type: 'sql_injection', line: 3 }])).toBe(true);
        expect(candidateIsReported(candidate, [{ type: 'sql_injection', line: 5 }])).toBe(true);
        expect(candidateIsReported(candidate, [{ type: 'xss', line: 9, rootCause: { rootCauseId: 'sql_injection:3' } }])).toBe(true);
    });

    it('treats a candidate the agent withdrew as not reported', () => {
        expect(candidateIsReported(candidate, [])).toBe(false);
        expect(candidateIsReported(candidate, [{ type: 'xss', line: 3 }])).toBe(false);
        expect(candidateIsReported(candidate, [{ type: 'sql_injection', line: 9 }])).toBe(false);
    });

    it('attaches open questions only to the matching finding', () => {
        const out = withOpenQuestions(
            [{ type: 'sql_injection', line: 3 }, { type: 'xss', line: 9 }],
            [{ rootCauseId: 'sql_injection:3', line: 3, openQuestions: ['q1'] }],
        );
        expect(out[0].openQuestions).toEqual(['q1']);
        expect(out[1].openQuestions).toBeUndefined();
    });
});
