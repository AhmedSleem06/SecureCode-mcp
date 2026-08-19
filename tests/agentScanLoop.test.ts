// Vitest suite for the scan agent loop — termination conditions + transcript.
//
// Covers:
//   - Loop terminates on finish action
//   - Loop terminates on null next (capped)
//   - Loop terminates on null next (completed)
//   - Loop terminates on wall clock exceeded
//   - Loop terminates on abort signal
//   - Transcript accumulates action+observation pairs
//   - Cost tracking accumulates from step responses
//   - spawn_failed on API error

import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

vi.mock('../src/attack/agentScanExecutor', () => ({
    executeAction: vi.fn(),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction } from '../src/attack/agentScanExecutor';

const ctx = { workspaceRoot: '/tmp', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const target = {
    filePath: 'test.ts',
    language: 'typescript',
    fileContent: 'export function handler() {}',
};

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    let callIdx = 0;
    for (const resp of responses) {
        mockFn.mockResolvedValueOnce(resp);
    }
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

describe('runAgentScan — termination', () => {
    beforeEach(() => vi.clearAllMocks());

    it('terminates on finish action', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            {
                next: { type: 'read_file', path: 'test.ts', rationale: 'read' },
                costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 19,
            },
            {
                next: { type: 'finish', findings: [{ line: 10, type: 'broken_access_control', severity: 'high', confidence: 85, evidence: 'no check', why: 'missing ownership' }], summary: 'Found issue' },
                costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18,
            },
        ]);
        (executeAction as any).mockResolvedValue('file content here');

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].type).toBe('broken_access_control');
        expect(result.summary).toBe('Found issue');
        expect(result.stepsUsed).toBe(2);
        expect(result.transcript).toHaveLength(1); // the read_file step
    });

    it('terminates on null next with capped status', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, stepsRemaining: 19 },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('capped');
        expect(result.findings).toHaveLength(0);
        expect(result.stepsUsed).toBe(0);
    });

    it('terminates on null next with completed status (no costCapped)', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: false, stepsRemaining: 19 },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.findings).toHaveLength(0);
    });

    it('terminates on null next with degraded status', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            { next: null, costUsd: 0, tokens: 0, degraded: true, costCapped: false, stepsRemaining: 19 },
        ]);

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('degraded');
    });

    it('terminates on abort signal', async () => {
        const controller = new AbortController();
        controller.abort();

        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
        ]);

        const result = await runAgentScan(ctx, target, { signal: controller.signal });

        expect(result.status).toBe('cancelled');
    });

    it('returns spawn_failed on API error', async () => {
        const mockFn = vi.fn().mockRejectedValue(new Error('Connection refused'));
        (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('spawn_failed');
        expect(result.error).toContain('Connection refused');
    });

    it('accumulates cost from step responses', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            { next: { type: 'read_file', path: 'a.ts', rationale: 'r' }, costUsd: 0.05, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 19 },
            { next: { type: 'finish', findings: [], summary: 'done' }, costUsd: 0.03, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18 },
        ]);
        (executeAction as any).mockResolvedValue('content');

        const result = await runAgentScan(ctx, target, {});

        expect(result.costSpentUsd).toBeCloseTo(0.08, 4);
    });

    it('calls onProgress with step info', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            { next: { type: 'read_file', path: 'a.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 19 },
            { next: { type: 'finish', findings: [], summary: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18 },
        ]);
        (executeAction as any).mockResolvedValue('content');

        const progressCalls: any[] = [];
        const result = await runAgentScan(ctx, target, {
            onProgress: (steps, max, msg) => progressCalls.push({ steps, max, msg }),
        });

        expect(progressCalls).toHaveLength(2);
        expect(progressCalls[0].steps).toBe(1);
        expect(progressCalls[1].steps).toBe(2);
        expect(progressCalls[0].msg).toContain('read_file');
    });

    it('transcript accumulates action+observation pairs', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            { next: { type: 'read_file', path: 'a.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 19 },
            { next: { type: 'search_code', pattern: 'test', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18 },
            { next: { type: 'finish', findings: [], summary: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 17 },
        ]);
        (executeAction as any)
            .mockResolvedValueOnce('file content')
            .mockResolvedValueOnce('search results');

        const result = await runAgentScan(ctx, target, {});

        expect(result.transcript).toHaveLength(2);
        expect(result.transcript[0].action.type).toBe('read_file');
        expect(result.transcript[0].observation).toBe('file content');
        expect(result.transcript[1].action.type).toBe('search_code');
        expect(result.transcript[1].observation).toBe('search results');
    });

    it('appends systemEvent to transcript without executing it (critique delivery fix)', async () => {
        // The API rejected the agent's finish with a critique. The API runs
        // the critique INSIDE the step that sees the finish action — so the
        // systemEvent comes back in the SAME response (with next: null). The
        // MCP loop must append the critique as a system_event (NOT try to
        // execute a fake read_file('__CRITIQUE__')), then continue the loop.
        // The next step's prompt will see the critique in the transcript.
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: API saw the agent's finish, ran the critique LLM, and
            // rejected it. Returns next: null + systemEvent (the MCP must
            // append the critique and re-loop, not treat null as "done").
            {
                next: null,
                costUsd: 0.02, tokens: 200, degraded: false, costCapped: false, stepsRemaining: 19,
                systemEvent: {
                    type: 'system_event',
                    eventType: 'critique',
                    message: 'CRITIQUE: finding 0 is a false positive — remove it.',
                    issues: [{ findingIndex: 0, reason: 'not vulnerable', severity: 'high' }],
                },
            },
            // Step 2: agent re-plans (sees the critique in the transcript)
            // and calls finish with no findings.
            {
                next: { type: 'finish', findings: [], summary: 'no findings after critique' },
                costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18,
            },
        ]);
        (executeAction as any).mockResolvedValue('');

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.summary).toBe('no findings after critique');
        // The transcript contains the critique system_event (the finish
        // actions are not pushed — they return immediately).
        expect(result.transcript.some(t => t.action.type === 'system_event' && (t.action as any).eventType === 'critique')).toBe(true);
        // The critique message must be preserved verbatim in the observation.
        const critiqueStep = result.transcript.find(t => t.action.type === 'system_event');
        expect(critiqueStep?.observation).toContain('CRITIQUE: finding 0 is a false positive');
        // The agent must NOT have called executeAction on the system_event.
        // (executeAction is only called for read_file/search_code/etc.)
        expect(executeAction).not.toHaveBeenCalled();
    });

    it('emits a system_event on API rejection instead of read_file(__ERROR__)', async () => {
        const mockFn = vi.fn();
        // First call: start succeeds.
        mockFn.mockResolvedValueOnce({ runId: 'run-1', budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 }, scanCredits: 95, refundId: 'r1' });
        // Second call: /step throws (API rejected).
        mockFn.mockRejectedValueOnce(new Error('actionType is required'));
        // Third call: agent retries successfully with finish.
        mockFn.mockResolvedValueOnce({
            next: { type: 'finish', findings: [], summary: 'done' },
            costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18,
        });
        (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        // The error must appear as a system_event, NOT as read_file('__ERROR__').
        const errorStep = result.transcript.find(t => t.action.type === 'system_event' && (t.action as any).eventType === 'error');
        expect(errorStep).toBeDefined();
        expect(errorStep!.observation).toContain('actionType is required');
        expect(result.transcript.some(t => t.action.type === 'read_file' && (t.action as any).path === '__ERROR__')).toBe(false);
    });
});
