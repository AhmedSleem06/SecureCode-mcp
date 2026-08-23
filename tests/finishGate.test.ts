/**
 * Regression tests for the agent scan finish gate.
 *
 * These tests document the DESIRED behavior:
 * - Finish with incomplete checklist and available budget is REJECTED
 * - Finish with findings and incomplete checklist is also REJECTED
 * - Finish with unresolved architecture tasks is REJECTED
 * - Finish with unverified candidates is REJECTED
 * - Finish is accepted when all tasks and candidates are terminal
 * - Finish is allowed as incomplete when no executable work remains
 *
 * Phase 1: These tests FAIL because the finish gate does not exist yet.
 * Phase 9: These tests PASS after the finish gate is implemented.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

vi.mock('../src/attack/agentScanExecutor', () => ({
    executeAction: vi.fn(),
    executeReadFileAction: vi.fn(),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction } from '../src/attack/agentScanExecutor';

const ctx = { workspaceRoot: '/tmp', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const target = {
    filePath: 'test.ts',
    language: 'typescript',
    fileContent: 'export function handler() {}',
};

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) {
        mockFn.mockResolvedValueOnce(resp);
    }
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

describe('Finish Gate — regression tests for premature finish rejection', () => {
    beforeEach(() => vi.clearAllMocks());

    it('rejects finish with incomplete checklist when budget remains', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: read the target file (completes initial-read only)
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            // Step 2: model calls finish with 0 findings — checklist is incomplete
            { next: { type: 'finish', findings: [], summary: 'no issues', selfCritique: 'checked everything' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });

        const result = await runAgentScan(ctx, target, {});

        // DESIRED: finish should be rejected and the scan should continue
        // CURRENT: finish is accepted immediately
        expect(result.terminationReason).not.toBe('agent_finish');
        expect(result.stepsUsed).toBeGreaterThan(2);
    });

    it('rejects finish with findings when checklist is incomplete', async () => {
        const finding = {
            line: 10, type: 'broken_access_control', severity: 'high',
            confidence: 85, evidence: 'no auth check', why: 'missing ownership',
        };
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: read
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            // Step 2: finish with a finding — checklist still incomplete
            { next: { type: 'finish', findings: [finding], summary: 'found issue', selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });

        const result = await runAgentScan(ctx, target, {});

        // DESIRED: finish should be rejected because checklist is incomplete
        // CURRENT: finish is accepted with findings (bypasses gap reporting)
        expect(result.terminationReason).not.toBe('agent_finish');
    });

    it('accepts finish when all required tasks are complete', async () => {
        // This test should PASS now — when the model completes all steps, finish works
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Complete all investigation steps by using the right tools
            { next: { type: 'read_file', path: 'test.ts', startLine: 1, endLine: 50, rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
            { next: { type: 'get_endpoints', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 38 },
            { next: { type: 'check_policy', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 37 },
            { next: { type: 'search_code', pattern: 'auth', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 36 },
            { next: { type: 'trace_flow_cross_file', filePath: 'test.ts', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 35 },
            { next: { type: 'read_config', configKind: 'all', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 34 },
            { next: { type: 'finish', findings: [], summary: 'done', selfCritique: 'all checked' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 33 },
        ]);
        (executeReadFileAction as any).mockResolvedValue({
            observation: 'content', actualStart: 1, actualEnd: 50, totalLines: 50, truncated: false,
        });
        (executeAction as any).mockResolvedValue('ok');

        const result = await runAgentScan(ctx, target, {});

        // When all steps are done, finish should be accepted
        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');
    });

    it('allows forced-incomplete finish when budget is exhausted', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 1, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 1, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Only one step left — model calls finish with incomplete checklist
            { next: { type: 'finish', findings: [], summary: 'budget gone', selfCritique: 'no budget' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 0 },
        ]);

        const result = await runAgentScan(ctx, target, {});

        // When budget is exhausted, finish must be accepted (forced-incomplete)
        expect(result.status).toBe('completed');
        // Coverage gaps should be reported
        expect(result.coverageGaps.length).toBeGreaterThan(0);
    });

    it('reports unresolved tasks for finding-bearing finishes', async () => {
        const finding = {
            line: 10, type: 'broken_access_control', severity: 'high',
            confidence: 85, evidence: 'no auth check', why: 'missing ownership',
        };
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' },
            // Step 1: finish immediately with a finding and no investigation
            { next: { type: 'finish', findings: [finding], summary: 'found it', selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 39 },
        ]);

        const result = await runAgentScan(ctx, target, {});

        // DESIRED: even with findings, unresolved tasks should be reported as gaps
        // CURRENT: findings-bearing finishes bypass gap reporting
        const hasStepGap = result.coverageGaps.some(g => g.title?.includes('Investigation step'));
        expect(hasStepGap).toBe(true);
    });
});
