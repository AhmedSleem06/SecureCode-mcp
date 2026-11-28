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

import { runAgentScan } from '../src/attack/agentScanLoop';
import { findingReviewFromStep } from '../src/attack/agentScanProtocol';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';

const ctx = { workspaceRoot: '/tmp/securecode-review-test-missing', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const startResp = { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' };
const target = { filePath: 'small.ts', language: 'typescript', fileContent: Array.from({ length: 20 }, (_, i) => `const v${i + 1} = ${i + 1};`).join('\n') };
const finding = { line: 3, type: 'hardcoded_secret', severity: 'high', confidence: 80, evidence: 'const v3 = 3;', why: 'anyone who reads the source can sign tokens' };

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

function setupExecutors() {
    (executeReadFileAction as any).mockImplementation(async (action: any) => ({
        observation: `lines ${action.startLine}-${action.endLine}`,
        actualStart: action.startLine ?? 1,
        actualEnd: action.endLine ?? 20,
        totalLines: 20,
        truncated: false,
    }));
    (executeAction as any).mockResolvedValue('ok');
    (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'none', hops: [], truncated: false } });
    (extractFunctionBoundaries as any).mockResolvedValue(null);
}

const finishAction = { type: 'finish', findings: [finding], summary: 'done', selfCritique: 'checked' };

async function runWithReview(review: unknown) {
    setupExecutors();
    const mockFn = mockPostJson([
        startResp,
        step({ type: 'read_file', path: 'small.ts', startLine: 1, endLine: 20, rationale: 'read it' }, 39),
        step(finishAction, 38, { landing: true, ...(review === undefined ? {} : { review }) }),
    ]);
    const result = await runAgentScan(ctx, target, {});
    return { result, mockFn };
}

describe('findingReviewFromStep', () => {
    it('maps the server answer to a per-finding status', () => {
        expect(findingReviewFromStep({ ran: true, verdict: 'accept' })).toEqual({ status: 'reviewed' });
        expect(findingReviewFromStep({ ran: false, skippedReason: 'final-step' }).status).toBe('not-reviewed');
        expect(findingReviewFromStep({ ran: false, skippedReason: 'critique-error' }).reason).toContain('reviewer failed');
        expect(findingReviewFromStep(undefined).status).toBe('unknown');
        expect(findingReviewFromStep({ ran: 'yes' } as any).status).toBe('unknown');
    });
});

describe('runAgentScan — per-finding review status', () => {
    beforeEach(() => vi.clearAllMocks());

    it('asks the server for the review status', async () => {
        const { mockFn } = await runWithReview({ ran: true, verdict: 'accept' });
        const stepCalls = (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step');
        expect(stepCalls.length).toBeGreaterThan(0);
        for (const c of stepCalls) expect(c[1].clientCapabilities.reviewStatus).toBe(true);
    });

    it('marks findings reviewed when the reviewer ran on that finish', async () => {
        const { result } = await runWithReview({ ran: true, verdict: 'accept' });
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].aiReview).toEqual({ status: 'reviewed' });
    });

    it('marks findings not reviewed, with the reason, when the reviewer was skipped', async () => {
        const { result } = await runWithReview({ ran: false, skippedReason: 'final-step' });
        expect(result.findings[0].aiReview?.status).toBe('not-reviewed');
        expect(result.findings[0].aiReview?.reason).toContain('last step');
    });

    it('marks findings unknown when an older server sends no review status', async () => {
        const { result } = await runWithReview(undefined);
        expect(result.findings[0].aiReview?.status).toBe('unknown');
    });

    it('keeps the stop reason and the review status as separate facts', async () => {
        const { result } = await runWithReview({ ran: false, skippedReason: 'over-cap' });
        expect(result.terminationReason).toBe('forced_incomplete');
        expect(result.findings[0].aiReview?.status).toBe('not-reviewed');
        expect(result.findings[0].type).toBe('hardcoded_secret');
        expect(result.findings[0].severity).toBe('high');
    });
});
