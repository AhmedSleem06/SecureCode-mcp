import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runVerifyLoop } from '../src/attack/verifyLoop';
import type { ApiClient } from '../api/client';
import {
    VerifyBudgetTracker,
    defaultVerifyBudget,
} from '../src/attack/agentScanProtocol';

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

import { runLocalTest } from '../src/utils/localTestRunner';

const FINDING = {
    type: 'command_injection',
    line: 10,
    evidence: 'exec(input)',
    why: 'user input reaches exec',
    severity: 'high' as const,
};

const BASE_OPTS = {
    filePath: 'src/foo.ts',
    code: 'const x = 1;',
    relatedFiles: [],
    workspaceRoot: '/tmp/workspace',
    language: 'javascript',
};

function queueResponses(client: ApiClient, ...responses: any[]): void {
    vi.mocked(client.postJson).mockReset();
    for (const r of responses) {
        vi.mocked(client.postJson).mockResolvedValueOnce(r);
    }
}

function makeClient(): ApiClient {
    return { postJson: vi.fn() } as unknown as ApiClient;
}

describe('runVerifyLoop — orchestration (Suite 2)', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    // ── Malformed generate response ──────────────────────────────────────

    it('returns INCONCLUSIVE when generate response is malformed (missing canTest)', async () => {
        const client = makeClient();
        queueResponses(client, { testScript: 'x', runner: 'node' }); // no canTest

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('malformed');
        expect(result.reason).toContain('canTest');
        expect(result.subVerdict).toBe('analyzed');
    });

    it('returns INCONCLUSIVE when generate response has unsupported runner', async () => {
        const client = makeClient();
        queueResponses(client, { canTest: true, testScript: 'x', runner: 'ruby' });

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('malformed');
        expect(result.reason).toContain('runner');
    });

    it('returns INCONCLUSIVE when canTest=true but testScript is empty', async () => {
        const client = makeClient();
        queueResponses(client, { canTest: true, testScript: '', runner: 'node' });

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('malformed');
        expect(result.reason).toContain('testScript');
    });

    // ── Malformed analyze response ───────────────────────────────────────

    it('returns INCONCLUSIVE when analyze response has invalid verdict', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("PASS: x")', runner: 'node', description: 't' },
            { verdict: 'MAYBE', reason: 'unsure', shouldRetry: false },
        );

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('malformed');
        expect(result.reason).toContain('verdict');
    });

    it('returns INCONCLUSIVE when analyze response has PROVEN+shouldRetry=true', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("PASS: x")', runner: 'node', description: 't' },
            { verdict: 'PROVEN', reason: 'worked', shouldRetry: true },
        );

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('malformed');
        expect(result.reason).toContain('PROVEN');
    });

    it('returns INCONCLUSIVE when analyze response has empty reason', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("PASS: x")', runner: 'node', description: 't' },
            { verdict: 'PROVEN', reason: '', shouldRetry: false },
        );

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('malformed');
        expect(result.reason).toContain('reason');
    });

    // ── Cancellation (Fix 4) ──────────────────────────────────────────────

    it('returns subVerdict=cancelled when test runner reports cancellation', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'cancelled' as any,
            output: 'Test cancelled by user',
            exitCode: -1,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("x")', runner: 'node', description: 't' },
        );

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('cancelled');
        expect(result.reason).toContain('cancelled');
    });

    it('does NOT retry after cancellation even if rounds remain', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'cancelled' as any,
            output: 'Test cancelled by user',
            exitCode: -1,
        });
        const client = makeClient();
        // Queue many responses — if cancellation is ignored, the loop would
        // keep calling generate. It should only be called once.
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("x")', runner: 'node', description: 't' },
            { verdict: 'PROVEN', reason: 'should not reach', shouldRetry: false },
        );

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        expect(result.subVerdict).toBe('cancelled');
        expect(result.roundsUsed).toBe(1);
        // Only one generate call should have happened.
        expect(vi.mocked(client.postJson)).toHaveBeenCalledTimes(1);
    });

    // ── Cost tracking (Fix 6) ──────────────────────────────────────────────

    it('records costUsd from generate + analyze responses into the budget tracker', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("PASS: x")', runner: 'node', description: 't', costUsd: 0.015 },
            { verdict: 'PROVEN', reason: 'exploit worked', shouldRetry: false, costUsd: 0.008 },
        );

        const tracker = new VerifyBudgetTracker(defaultVerifyBudget());
        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('PROVEN');
        expect(tracker.llmCallsUsed).toBe(2);
        // 0.015 + 0.008 = 0.023
        expect(tracker.costSpentUsd).toBeCloseTo(0.023, 5);
    });

    it('records $0 cost when costUsd is absent (backward compatible)', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("PASS: x")', runner: 'node', description: 't' },
            { verdict: 'PROVEN', reason: 'exploit worked', shouldRetry: false },
        );

        const tracker = new VerifyBudgetTracker(defaultVerifyBudget());
        await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
            budgetTracker: tracker,
        });

        expect(tracker.llmCallsUsed).toBe(2);
        expect(tracker.costSpentUsd).toBe(0);
    });

    it('records cost even when cannot-test (generate ran, no analyze)', async () => {
        const client = makeClient();
        queueResponses(
            client,
            { canTest: false, skipReason: 'needs server', costUsd: 0.003 },
        );

        const tracker = new VerifyBudgetTracker(defaultVerifyBudget());
        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
            budgetTracker: tracker,
        });

        expect(result.subVerdict).toBe('cannot-test');
        expect(tracker.llmCallsUsed).toBe(1);
        expect(tracker.costSpentUsd).toBeCloseTo(0.003, 5);
    });

    // ── Python runner end-to-end (Fix 5) ──────────────────────────────────

    it('passes python3 runner through to runLocalTest when API returns it', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'print("PASS: x")', runner: 'python3', description: 'py test' },
            { verdict: 'PROVEN', reason: 'exploit worked', shouldRetry: false },
        );

        await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            language: 'python',
            client,
        });

        const callArgs = vi.mocked(runLocalTest).mock.calls[0];
        expect(callArgs[1]).toBe('python3');
    });

    it('passes deno runner through to runLocalTest when API returns it', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass', output: 'PASS: ok', exitCode: 0,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("PASS: x")', runner: 'deno', description: 'deno test' },
            { verdict: 'PROVEN', reason: 'exploit worked', shouldRetry: false },
        );

        await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
        });

        const callArgs = vi.mocked(runLocalTest).mock.calls[0];
        expect(callArgs[1]).toBe('deno');
    });

    // ── Budget exhaustion mid-finding ─────────────────────────────────────

    it('stops mid-finding when budget runs out of LLM calls', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'timeout', output: 'timed out', exitCode: -1,
        });
        const client = makeClient();
        queueResponses(
            client,
            { canTest: true, testScript: 'console.log("x")', runner: 'node', description: 't' },
            // Re-queue generate for the retry attempt
            { canTest: true, testScript: 'console.log("x")', runner: 'node', description: 't' },
            { verdict: 'INCONCLUSIVE', reason: 'timeout', shouldRetry: true },
        );

        const budget = defaultVerifyBudget();
        budget.maxLlmCalls = 3; // 1 gen + 1 analyze = 2 per round; 3 allows ~1.5 rounds
        budget.maxRoundsPerFinding = 8;
        const tracker = new VerifyBudgetTracker(budget);

        const result = await runVerifyLoop({
            ...BASE_OPTS,
            finding: FINDING,
            client,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('budget-exhausted');
    });
});
