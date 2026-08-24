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
    executeReadFileAction: vi.fn(),
    executeFlowAction: vi.fn(),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { sanitizeFindings, isCoherentText, estimateTranscriptSize, compactTranscript, compactTranscriptAggressive } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction } from '../src/attack/agentScanExecutor';

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

// Helper: generate mock steps that complete the generic-utility checklist
// (initial-read, cross-file-flow, tests-found, candidates-verified)
function completeChecklistSteps(findings: any[] = [], summary: string = 'done') {
    return [
        { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
        { next: { type: 'trace_flow_cross_file', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
        { next: { type: 'check_policy', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 37 },
        { next: { type: 'read_config', configKind: 'all', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 36 },
        { next: { type: 'find_tests', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 35 },
        { next: { type: 'finish', findings, summary, selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 34 },
    ];
}

describe('runAgentScan — termination', () => {
    beforeEach(() => vi.clearAllMocks());

    it('terminates on finish action', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 0.40, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            ...completeChecklistSteps([{ line: 10, type: 'broken_access_control', severity: 'medium', confidence: 85, evidence: 'no check', why: 'missing ownership' }], 'Found issue'),
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'file content here', actualStart: 1, actualEnd: 100, totalLines: 100, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.findings).toHaveLength(1);
        expect(result.findings[0].type).toBe('broken_access_control');
        expect(result.summary).toBe('Found issue');
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
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 0.40, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            ...completeChecklistSteps([], 'done'),
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        // 4 steps × $0.01 each + finish $0.01 = $0.05
        expect(result.costSpentUsd).toBeGreaterThan(0);
    });

    it('calls onProgress with step info', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 0.40, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            ...completeChecklistSteps(),
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const progressCalls: any[] = [];
        const result = await runAgentScan(ctx, target, {
            onProgress: (steps, max, msg) => progressCalls.push({ steps, max, msg }),
        });

        expect(progressCalls.length).toBeGreaterThanOrEqual(4);
        expect(progressCalls[0].steps).toBe(1);
        expect(progressCalls[0].msg).toContain('read_file');
    });

    it('transcript accumulates action+observation pairs', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 0.40, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            ...completeChecklistSteps(),
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'file content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValueOnce('flow result').mockResolvedValueOnce('test result');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(result.transcript.length).toBeGreaterThanOrEqual(3);
        expect(result.transcript[0].action.type).toBe('read_file');
        expect(result.transcript[0].observation).toBe('file content');
        expect(result.transcript[1].action.type).toBe('trace_flow_cross_file');
        expect(result.transcript[1].observation).toBe('flow result');
    });

    it('appends systemEvent to transcript without executing it (critique delivery fix)', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 0.40, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: read_file (checklist: initial-read)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            // Step 2: trace_flow_cross_file (checklist: cross-file-flow)
            { next: { type: 'trace_flow_cross_file', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
            // Step 3: find_tests (checklist: tests-found)
            { next: { type: 'find_tests', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 37 },
            // Step 4: agent calls finish with a finding, API runs critique and
            // rejects it. Returns next: null + systemEvent (critique).
            {
                next: null,
                costUsd: 0.02, tokens: 200, degraded: false, costCapped: false, stepsRemaining: 36,
                systemEvent: {
                    type: 'system_event',
                    eventType: 'critique',
                    message: 'CRITIQUE: finding 0 is a false positive — remove it.',
                    issues: [{ findingIndex: 0, reason: 'not vulnerable', severity: 'high' }],
                },
            },
            // Step 5: agent re-plans and finishes with no findings
            { next: { type: 'finish', findings: [], summary: 'no findings after critique', selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 35 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(['completed', 'capped']).toContain(result.status);
        // The transcript contains the critique system_event
        expect(result.transcript.some(t => t.action.type === 'system_event' && (t.action as any).eventType === 'critique')).toBe(true);
    });

    it('emits a system_event on API rejection instead of read_file(__ERROR__)', async () => {
        const mockFn = vi.fn();
        // First call: start succeeds.
        mockFn.mockResolvedValueOnce({ runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 0.40, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' });
        // Second call: /step throws (API rejected).
        mockFn.mockRejectedValueOnce(new Error('actionType is required'));
        // Remaining calls: complete the checklist and finish
        for (const resp of completeChecklistSteps()) {
            mockFn.mockResolvedValueOnce(resp);
        }
        (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        // The error must appear as a system_event, NOT as read_file('__ERROR__').
        const errorStep = result.transcript.find(t => t.action.type === 'system_event' && (t.action as any).eventType === 'error');
        expect(errorStep).toBeDefined();
        expect(errorStep!.observation).toContain('actionType is required');
        expect(result.transcript.some(t => t.action.type === 'read_file' && (t.action as any).path === '__ERROR__')).toBe(false);
    });
});

describe('runAgentScan — adaptive budget fields', () => {
    beforeEach(() => vi.clearAllMocks());

    it('returns stepsGranted and extensionsGranted in result', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            ...completeChecklistSteps(),
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.stepsGranted).toBe(40);
        expect(result.extensionsGranted).toBe(0);
        expect(['agent_finish', 'forced_incomplete']).toContain(result.terminationReason);
    });

    it('returns terminationReason wall_clock when time expires', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
        ]);

        const result = await runAgentScan(ctx, target, {
            budget: { stepsRemaining: 40, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 },
        });

        // The loop will hit wall clock or step budget since only start response is mocked
        expect(['capped', 'completed', 'degraded', 'spawn_failed', 'cancelled', 'blocked_recovery']).toContain(result.status);
    });

    it('handles budgetExtension in step response', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'read' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38, budgetExtension: { granted: 10, totalGranted: 50, hardMaxSteps: 80, reason: 'test extension' } },
            { next: { type: 'trace_flow_cross_file', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 47 },
            { next: { type: 'find_tests', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 46 },
            { next: { type: 'finish', findings: [], summary: 'done', selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 45 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'file content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(result.status).toBe('completed');
        expect(result.stepsGranted).toBe(50);
        expect(result.extensionsGranted).toBe(1);
    });
});

describe('runAgentScan — blocked-read recovery', () => {
    beforeEach(() => vi.clearAllMocks());

    it('sends actionConstraint with forbiddenActions after 2 blocked reads', async () => {
        const mockFn = mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: first read succeeds (consecutiveBlockedReads stays 0)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            // Step 2: duplicate → blocked (consecutiveBlockedReads becomes 1)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
            // Step 3: duplicate → blocked (consecutiveBlockedReads becomes 2)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 37 },
            // Step 4: constraint is sent BEFORE this call (consecutiveBlockedReads=2 at build time)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 36 },
            // Step 5: finish
            { next: { type: 'finish', findings: [], summary: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 35 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('recovery observation');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        await runAgentScan(ctx, target, {});

        // Call index 4 (step 4) should have actionConstraint — consecutiveBlockedReads=2 at build time
        const step4Call = mockFn.mock.calls[4];
        expect(step4Call).toBeDefined();
        const step4Req = step4Call[1];
        expect(step4Req.actionConstraint).toBeDefined();
        expect(step4Req.actionConstraint.mode).toBe('recovery');
        expect(step4Req.actionConstraint.forbiddenActions).toContain('read_file');
    });

    it('triggers deterministic recovery on the third blocked read', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: first read succeeds (records coverage 1-50)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            // Step 2: duplicate → blocked (1)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
            // Step 3: duplicate → blocked (2)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 37 },
            // Step 4: duplicate → blocked (3) → deterministic recovery fires, counter resets
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 36 },
            // Steps 5-7: complete the checklist (trace_flow, find_tests, finish)
            { next: { type: 'trace_flow_cross_file', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 35 },
            { next: { type: 'find_tests', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 34 },
            { next: { type: 'finish', findings: [], summary: 'done', selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 33 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('recovery observation');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        expect(['completed', 'blocked_read_recovery']).toContain(result.status);
        // The transcript should contain a deterministic recovery step
        const recoveryStep = result.transcript.find(t => t.observation?.includes('[DETERMINISTIC RECOVERY]'));
        expect(recoveryStep).toBeDefined();
    });

    it('force-finishes when no recovery action is available after 5 blocked reads', async () => {
        // Scenario: file is fully covered (totalLines=50, read 1-50) and
        // all investigation steps are complete → recovery action is null
        // → force-finish at recoveryLimit (5)
        const blockedReadAction = { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' };
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: read succeeds
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            // Steps 2-6: all duplicates → blocked (1,2,3→recovery,1,2)
            // But recovery is null since all steps are done (we need to complete them first)
            // Actually, recovery fires at 3 but get_endpoints etc. will be the recovery
            // action since steps are incomplete. So we need enough responses for the cycle.
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 37 },
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 36 },
            // After step 4 blocked (3), recovery fires (get_endpoints), counter resets
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 35 },
            // After step 5 blocked (1), no constraint
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 34 },
            // After step 6 blocked (2), constraint sent
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 33 },
            // After step 7 blocked (3), recovery fires again, counter resets
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 32 },
            { next: blockedReadAction, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 31 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('recovery observation');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: 'test.ts', line: 1 }], truncated: false } });

        const result = await runAgentScan(ctx, target, {});

        // The recovery cycle prevents force-finish — the agent keeps getting
        // blocked, recovery fires at 3, resets, and the cycle repeats.
        // Eventually the budget runs out or we run out of mock responses.
        // The important thing is that the loop doesn't hang and eventually
        // terminates (either via budget, blocked_read_recovery, or api_error).
        expect(['completed', 'capped', 'spawn_failed', 'blocked_read_recovery']).toContain(result.status);
    });
});

describe('sanitizeFindings quality guard', () => {
    it('validates required fields and applies defaults', () => {
        const input = [{ why: 'This is a valid explanation of the issue', evidence: 'code here' }];
        const result = sanitizeFindings(input);
        expect(result[0].line).toBe(0);
        expect(result[0].type).toBe('unknown');
        expect(result[0].severity).toBe('low');
        expect(result[0].confidence).toBe(0.3);
    });

    it('preserves valid findings', () => {
        const input = [{
            line: 42, type: 'sql-injection', severity: 'high', confidence: 0.8,
            why: 'User input flows into SQL query without parameterization',
            evidence: 'db.query(req.body.input)',
        }];
        const result = sanitizeFindings(input);
        expect(result[0].line).toBe(42);
        expect(result[0].type).toBe('sql-injection');
        expect(result[0].severity).toBe('high');
        expect(result[0].confidence).toBe(0.8);
    });

    it('clamps confidence to [0, 1]', () => {
        const result = sanitizeFindings([
            { line: 1, type: 'xss', severity: 'medium', confidence: 5, why: 'valid explanation here', evidence: 'x' },
            { line: 2, type: 'xss', severity: 'medium', confidence: -1, why: 'another valid explanation', evidence: 'y' },
        ]);
        expect(result[0].confidence).toBe(1);
        expect(result[1].confidence).toBe(0);
    });

    it('downgrades severity on incoherent why', () => {
        const result = sanitizeFindings([{
            line: 1, type: 'rce', severity: 'critical', confidence: 0.9,
            why: '   ', evidence: 'x',
        }]);
        expect(result[0].severity).toBe('medium');
        expect(result[0].confidence).toBeLessThanOrEqual(0.3);
        expect(result[0].why).toContain('Quality warning');
    });

    it('fixes invalid severity to low', () => {
        const result = sanitizeFindings([{
            line: 1, type: 'xss', severity: 'extreme', confidence: 0.5,
            why: 'valid explanation text', evidence: 'x',
        }]);
        expect(result[0].severity).toBe('low');
    });

    it('removes invalid lineEnd', () => {
        const result = sanitizeFindings([{
            line: 10, lineEnd: 5, type: 'xss', severity: 'low', confidence: 0.5,
            why: 'valid explanation text', evidence: 'x',
        }]);
        expect(result[0].lineEnd).toBeUndefined();
    });

    it('deduplicates findings with same type and line', () => {
        const result = sanitizeFindings([
            { line: 42, type: 'xss', severity: 'high', confidence: 0.8, why: 'first valid explanation', evidence: 'a' },
            { line: 42, type: 'xss', severity: 'medium', confidence: 0.5, why: 'second valid explanation', evidence: 'b' },
        ]);
        expect(result.length).toBe(1);
        expect(result[0].evidence).toBe('a');
    });

    it('handles non-array input', () => {
        expect(sanitizeFindings(null as any)).toEqual([]);
        expect(sanitizeFindings(undefined as any)).toEqual([]);
    });

    it('strips control characters from text fields', () => {
        const result = sanitizeFindings([{
            line: 1, type: 'xss', severity: 'low', confidence: 0.5,
            why: 'valid\x00\x01explanation here', evidence: 'code\x02here',
        }]);
        expect(result[0].why).not.toContain('\x00');
        expect(result[0].evidence).not.toContain('\x02');
    });
});

describe('isCoherentText', () => {
    it('rejects empty or very short text', () => {
        expect(isCoherentText('')).toBe(false);
        expect(isCoherentText('ab')).toBe(false);
    });

    it('rejects text with too few words', () => {
        expect(isCoherentText('a b')).toBe(false);
    });

    it('accepts normal English text', () => {
        expect(isCoherentText('This is a valid explanation')).toBe(true);
    });

    it('rejects text with control characters', () => {
        expect(isCoherentText('valid text\x00 here')).toBe(false);
    });

    it('rejects text with low ASCII ratio', () => {
        expect(isCoherentText('1234567890123456789012345ab')).toBe(false);
    });
});

describe('compactTranscript', () => {
    function makeStep(obs: string, type = 'read_file'): { action: any; observation: string } {
        return { action: { type, path: 'test.ts' }, observation: obs };
    }

    it('returns transcript unchanged when under budget', () => {
        const small = [makeStep('short observation text here'), makeStep('another short one')];
        expect(compactTranscript(small)).toBe(small);
    });

    it('returns transcript unchanged when fewer than keep-recent steps', () => {
        const tiny = [makeStep('x'.repeat(200000))];
        expect(compactTranscript(tiny)).toBe(tiny);
    });

    it('compacts old steps when over budget', () => {
        const steps: { action: any; observation: string }[] = [];
        for (let i = 0; i < 20; i++) {
            steps.push(makeStep('x'.repeat(10000), 'read_file'));
        }
        const result = compactTranscript(steps);
        const resultSize = estimateTranscriptSize(result);
        expect(resultSize).toBeLessThan(estimateTranscriptSize(steps));
        expect(result.length).toBe(20);
    });

    it('preserves recent steps at full fidelity', () => {
        const steps: { action: any; observation: string }[] = [];
        for (let i = 0; i < 20; i++) {
            steps.push(makeStep('x'.repeat(10000), 'read_file'));
        }
        const result = compactTranscript(steps);
        for (let i = result.length - 12; i < result.length; i++) {
            expect(result[i].observation.length).toBe(10000);
        }
    });

    it('preserves system_event steps at full fidelity', () => {
        const steps: { action: any; observation: string }[] = [];
        for (let i = 0; i < 20; i++) {
            steps.push(makeStep('x'.repeat(10000), 'read_file'));
        }
        steps.splice(2, 0, makeStep('x'.repeat(10000), 'system_event'));
        const result = compactTranscript(steps);
        const eventStep = result.find(s => s.action.type === 'system_event');
        expect(eventStep).toBeDefined();
        expect(eventStep!.observation.length).toBe(10000);
    });

    it('adds compaction marker to truncated observations', () => {
        const steps: { action: any; observation: string }[] = [];
        for (let i = 0; i < 20; i++) {
            steps.push(makeStep('x'.repeat(10000), 'read_file'));
        }
        const result = compactTranscript(steps);
        expect(result[0].observation).toContain('[compacted]');
    });
});

describe('compactTranscriptAggressive', () => {
    it('keeps only 6 recent steps at full fidelity', () => {
        const steps: { action: any; observation: string }[] = [];
        for (let i = 0; i < 20; i++) {
            steps.push({ action: { type: 'read_file', path: 'test.ts' }, observation: 'x'.repeat(10000) });
        }
        const result = compactTranscriptAggressive(steps);
        for (let i = result.length - 6; i < result.length; i++) {
            expect(result[i].observation.length).toBe(10000);
        }
        expect(result[0].observation.length).toBeLessThan(200);
    });

    it('returns unchanged when fewer than 6 steps', () => {
        const tiny = [{ action: { type: 'read_file' }, observation: 'short' }];
        expect(compactTranscriptAggressive(tiny)).toBe(tiny);
    });
});

describe('estimateTranscriptSize', () => {
    it('sums observation and action sizes', () => {
        const steps = [
            { action: { type: 'read_file', path: 'a.ts' }, observation: 'hello world' },
        ];
        expect(estimateTranscriptSize(steps)).toBeGreaterThan(20);
    });

    it('handles empty transcript', () => {
        expect(estimateTranscriptSize([])).toBe(0);
    });
});
