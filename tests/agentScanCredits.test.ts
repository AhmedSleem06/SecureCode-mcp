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
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction } from '../src/attack/agentScanExecutor';
import {
    AgentScanRunCloser,
    capReasonSummary,
    formatCreditUsage,
    isAgentScanBudgetExhausted,
} from '../src/attack/agentScanCredits';

const ctx = { workspaceRoot: '/tmp', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const target = {
    filePath: 'test.ts',
    language: 'typescript',
    fileContent: 'export function handler() {}',
};

const START = { runId: 'run-c', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' };

function serverBudget(costSpentUsd: number, overrides: Record<string, unknown> = {}) {
    return { costSpentUsd, costCapUsd: 0.57, creditsUsed: 5, baseCredits: 5, maxCredits: 15, extensionsGranted: 0, extensionCreditsDrawn: 0, ...overrides };
}

function step(next: any, remaining: number, extra: Record<string, unknown> = {}) {
    return { next, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: remaining, ...extra };
}

function checklist(extraPerStep: (i: number) => Record<string, unknown> = () => ({}), findings: any[] = [], summary = 'done') {
    return [
        step({ type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, 39, extraPerStep(0)),
        step({ type: 'trace_flow_cross_file', filePath: 'test.ts', rationale: 'r' }, 38, extraPerStep(1)),
        step({ type: 'check_policy', filePath: 'test.ts', rationale: 'r' }, 37, extraPerStep(2)),
        step({ type: 'read_config', configKind: 'all', rationale: 'r' }, 36, extraPerStep(3)),
        step({ type: 'find_tests', filePath: 'test.ts', rationale: 'r' }, 35, extraPerStep(4)),
        step({ type: 'finish', findings, summary, selfCritique: 'done' }, 34, extraPerStep(5)),
    ];
}

function mockPostJson(responses: any[], closeResponse: any = {}) {
    const queue = [...responses];
    const mockFn = vi.fn(async (path: string) => {
        if (path === '/agent/scan/close') return closeResponse;
        return queue.shift();
    });
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

function stubExecutors() {
    (executeReadFileAction as any).mockResolvedValue({
        observation: 'file content here', actualStart: 1, actualEnd: 100, totalLines: 100, truncated: false,
    });
    (executeAction as any).mockResolvedValue('ok');
    (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });
}

describe('runAgentScan — server budget', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        stubExecutors();
    });

    it('uses serverBudget as the source of truth for cost and cap (server cap lower than the client cap)', async () => {
        const mockFn = mockPostJson([
            START,
            ...checklist(i => ({ costUsd: 0.5, serverBudget: serverBudget(0.05 * (i + 1)) })),
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.costSpentUsd).toBeCloseTo(0.30, 5);
        expect(result.creditsUsed).toBe(5);
        expect(result.maxCredits).toBe(15);
        const stepCalls = (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step');
        expect(stepCalls[0][1].budget.costCapUsd).toBe(4.0);
        expect(stepCalls[1][1].budget.costCapUsd).toBe(0.57);
        expect(stepCalls[1][1].budget.costSpentUsd).toBeCloseTo(0.05, 5);
    });

    it('logs a progress message on paid extensions and reports the extension count', async () => {
        mockPostJson([
            START,
            ...checklist(i => i === 2
                ? { serverBudget: serverBudget(0.5, { costCapUsd: 0.798, creditsUsed: 7, extensionsGranted: 1 }), paidExtension: { creditsDrawn: 2, creditsUsed: 7, maxCredits: 15, newCostCapUsd: 0.798 } }
                : { serverBudget: serverBudget(0.1 * (i + 1), i > 2 ? { costCapUsd: 0.798, creditsUsed: 7, extensionsGranted: 1 } : {}) }),
        ]);
        const messages: string[] = [];

        const result = await runAgentScan(ctx, target, { onProgress: (_s, _m, msg) => messages.push(msg) });

        expect(messages).toContain('Extended scan budget: +2 credits (7/15 used)');
        expect(result.creditsUsed).toBe(7);
        expect(result.creditExtensionsGranted).toBe(1);
    });

    it('salvages findings with a top-up message when the server stops for insufficient credits', async () => {
        const finding = { line: 10, type: 'broken_access_control', severity: 'high', confidence: 85, evidence: 'no check', why: 'missing ownership' };
        const mockFn = mockPostJson([
            START,
            step({ type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, 39, { serverBudget: serverBudget(0.4) }),
            step({ type: 'finish', findings: [finding], summary: 'premature', selfCritique: 'done' }, 38, { serverBudget: serverBudget(0.5) }),
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, capReason: 'insufficient_credits', stepsRemaining: 37, serverBudget: serverBudget(0.55) },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.terminationReason).toBe('forced_incomplete');
        expect(result.summary).toContain('This file needs more budget. Top up credits to scan deeper.');
        expect(result.findings.some(f => f.type === 'broken_access_control')).toBe(true);
        expect(result.capReason).toBe('insufficient_credits');
        const closeCalls = (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/close');
        expect(closeCalls).toHaveLength(1);
    });

    it('returns incomplete with the top-up message when there is nothing to salvage', async () => {
        mockPostJson([
            START,
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, capReason: 'insufficient_credits', stepsRemaining: 39, serverBudget: serverBudget(0.56) },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('incomplete');
        expect(result.summary).toBe('This file needs more budget. Top up credits to scan deeper.');
        expect(result.capReason).toBe('insufficient_credits');
    });

    it('reports the 15-credit maximum when the server stops for max_credits', async () => {
        mockPostJson([
            START,
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, capReason: 'max_credits', stepsRemaining: 39, serverBudget: serverBudget(1.7, { creditsUsed: 15, extensionsGranted: 5, costCapUsd: 1.71 }) },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.summary).toBe('Reached the 15-credit maximum for one scan.');
        expect(result.creditsUsed).toBe(15);
    });

    it('applies the /close settlement when the loop owns the close', async () => {
        mockPostJson([START, ...checklist(() => ({ serverBudget: serverBudget(0.1, { creditsUsed: 7, extensionsGranted: 1 }) }))],
            { settlement: { creditsRefunded: 2, creditsUsed: 5, costSpentUsd: 0.1 } });

        const result = await runAgentScan(ctx, target, {});

        expect(result.creditsUsed).toBe(5);
        expect(result.creditsRefunded).toBe(2);
        expect(result.runId).toBeUndefined();
    });

    it('with deferClose leaves the run open and returns its runId', async () => {
        const mockFn = mockPostJson([START, ...checklist()]);

        const result = await runAgentScan(ctx, target, { deferClose: true });

        expect(result.runId).toBe('run-c');
        expect((mockFn.mock.calls as any[]).some(c => c[0] === '/agent/scan/close')).toBe(false);
    });

    it('old API without serverBudget still sums cost locally and reports no credits', async () => {
        mockPostJson([START, ...checklist()]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.costSpentUsd).toBeCloseTo(0.06, 5);
        expect(result.creditsUsed).toBeUndefined();
        expect(result.capReason).toBeUndefined();
    });

    it('old API cost cap keeps the dollar summary', async () => {
        mockPostJson([
            START,
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, stepsRemaining: 39 },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.summary).toBe('Cost cap ($4.00) reached.');
    });
});

describe('agentScanCredits helpers', () => {
    it('formats credit usage with extensions and refunds', () => {
        expect(formatCreditUsage({ creditsUsed: 9, baseCredits: 5, creditExtensionsGranted: 2 })).toBe('This scan used 9 credits (5 + 2 extensions).');
        expect(formatCreditUsage({ creditsUsed: 5, baseCredits: 5, creditExtensionsGranted: 0 })).toBe('This scan used 5 credits.');
        expect(formatCreditUsage({ creditsUsed: 7, baseCredits: 5, creditExtensionsGranted: 2, creditsRefunded: 2 }))
            .toBe('This scan used 7 credits (5 + 2 extensions). 2 credits were refunded.');
        expect(formatCreditUsage({})).toBeUndefined();
    });

    it('maps cap reasons to user-facing summaries', () => {
        expect(capReasonSummary('insufficient_credits')).toBe('This file needs more budget. Top up credits to scan deeper.');
        expect(capReasonSummary('max_credits', 15)).toBe('Reached the 15-credit maximum for one scan.');
        expect(capReasonSummary('cost_cap')).toBeUndefined();
        expect(capReasonSummary(undefined)).toBeUndefined();
    });

    it('detects the budget-exhausted API error', () => {
        expect(isAgentScanBudgetExhausted({ status: 402, apiCode: 'AGENT_SCAN_BUDGET_EXHAUSTED' })).toBe(true);
        expect(isAgentScanBudgetExhausted({ status: 402, apiCode: 'INSUFFICIENT_CREDITS' })).toBe(false);
        expect(isAgentScanBudgetExhausted(new Error('x'))).toBe(false);
    });

    it('run closer posts /close exactly once and swallows failures', async () => {
        const postJson = vi.fn().mockResolvedValue({ settlement: { creditsRefunded: 0, creditsUsed: 5 } });
        const closer = new AgentScanRunCloser();
        closer.attach({ postJson } as any, 'run-z', 'completed', 'agent_finish');

        const [a, b] = await Promise.all([closer.close(), closer.close()]);
        await closer.close();

        expect(postJson).toHaveBeenCalledTimes(1);
        expect(postJson.mock.calls[0][1]).toEqual({ runId: 'run-z', status: 'completed', terminationReason: 'agent_finish' });
        expect(a).toEqual({ creditsRefunded: 0, creditsUsed: 5 });
        expect(b).toBe(a);

        const failing = new AgentScanRunCloser();
        failing.attach({ postJson: vi.fn().mockRejectedValue(new Error('down')) } as any, 'run-y', 'failed', 'api_error');
        await expect(failing.close()).resolves.toBeUndefined();
    });

    it('run closer without a run id never posts', async () => {
        const postJson = vi.fn();
        const closer = new AgentScanRunCloser();
        closer.attach({ postJson } as any, undefined, 'completed', 'agent_finish');
        await closer.close();
        expect(postJson).not.toHaveBeenCalled();
    });
});
