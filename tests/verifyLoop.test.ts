import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runVerifyLoop } from '../src/attack/verifyLoop';
import type { ApiClient } from '../api/client';

function makeMockClient(genResp: any, analyzeResp?: any): ApiClient {
    const postJson = vi.fn();
    if (analyzeResp) {
        postJson
            .mockResolvedValueOnce(genResp)
            .mockResolvedValueOnce(analyzeResp);
    } else {
        postJson.mockResolvedValue(genResp);
    }
    return { postJson } as unknown as ApiClient;
}

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

import { runLocalTest } from '../src/utils/localTestRunner';

const VALID_PROOF_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"real-import"}:SECURECODE_PROOF_END';

describe('runVerifyLoop', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    it('returns PROVEN when test passes on first round', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass',
            output: `PASS: exploit worked\n${VALID_PROOF_MARKER}`,
            exitCode: 0,
        });

        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS: test")', runner: 'node', description: 'test' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );

        const result = await runVerifyLoop({
            finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('PROVEN');
        expect(result.roundsUsed).toBe(1);
    });

    it('returns UNPROVEN when guard held', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: 'FAIL: guard blocked',
            exitCode: 0,
        });

        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("FAIL: blocked")', runner: 'node', description: 'test' },
            { verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false },
        );

        const result = await runVerifyLoop({
            finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('UNPROVEN');
    });

    it('returns INCONCLUSIVE when canTest is false', async () => {
        const client = makeMockClient({ canTest: false, skipReason: 'needs running server' });

        const result = await runVerifyLoop({
            finding: { type: 'missing_rate_limiting', line: 10, evidence: 'no rate limit', why: 'no middleware', severity: 'medium' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('needs running server');
    });

    it('retries on INCONCLUSIVE with shouldRetry=true', async () => {
        vi.mocked(runLocalTest)
            .mockResolvedValueOnce({ verdict: 'error', output: 'Cannot find module', exitCode: 1 })
            .mockResolvedValueOnce({ verdict: 'pass', output: `PASS: exploit worked\n${VALID_PROOF_MARKER}`, exitCode: 0 });

        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS: test")', runner: 'node', description: 'test' },
        );
        // First analyze: INCONCLUSIVE shouldRetry=true, second: PROVEN
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'import {foo} from "./nonexistent"', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'INCONCLUSIVE', reason: 'import error', shouldRetry: true })
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("PASS: test")', runner: 'node', description: 'fixed' })
            .mockResolvedValueOnce({ verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false });

        const result = await runVerifyLoop({
            finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('PROVEN');
        expect(result.roundsUsed).toBe(2);
    });

    it('stops retrying when shouldRetry=false', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'error',
            output: 'TypeError',
            exitCode: 1,
        });

        const client = makeMockClient({});
        // Call order matters: /verify/generate is called first, then
        // /verify/analyze. mockResolvedValueOnce queues in call order.
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("test")', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'INCONCLUSIVE', reason: 'type error', shouldRetry: false });

        const result = await runVerifyLoop({
            finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.roundsUsed).toBe(1);
        expect(result.subVerdict).toBe('analyzed');
    });

    it('returns subVerdict=sandbox-unavailable when no isolation backend exists', async () => {
        // The runner returns sandbox-unavailable — the loop must surface this
        // as a distinct subVerdict so toolAgentScan can count it and show
        // a single top-level install hint instead of N per-finding reasons.
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'sandbox-unavailable',
            output: 'No verification sandbox backend (Docker or Deno) was detected.',
            exitCode: -1,
        });

        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS: test")', runner: 'node', description: 'test' },
        );

        const result = await runVerifyLoop({
            finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('sandbox-unavailable');
        expect(result.reason).toContain('Docker or Deno');
    });

    it('returns subVerdict=cannot-test when /verify/generate says canTest:false', async () => {
        const client = makeMockClient({ canTest: false, skipReason: 'needs running server' });

        const result = await runVerifyLoop({
            finding: { type: 'missing_rate_limiting', line: 10, evidence: 'no rate limit', why: 'no middleware', severity: 'medium' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('cannot-test');
    });

    it('returns subVerdict=budget-exhausted when the aggregate budget is empty at entry', async () => {
        const client = makeMockClient({});
        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const tracker = new VerifyBudgetTracker(defaultVerifyBudget());
        // Exhaust the budget before the call.
        tracker.findingsAttempted = tracker.budget.maxFindings;

        const result = await runVerifyLoop({
            finding: { type: 'xss', line: 5, evidence: 'innerHTML', why: 'tainted', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('budget-exhausted');
    });

    it('returns subVerdict=blocked when static safety check rejects the script', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'blocked',
            output: 'Test script blocked: eval() executes arbitrary strings as code',
            exitCode: -1,
        });

        const client = makeMockClient(
            { canTest: true, testScript: 'eval("x")', runner: 'node', description: 'test' },
            { verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false },
        );

        const result = await runVerifyLoop({
            finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('blocked');
        expect(result.reason).toContain('blocked');
    });

    it('returns subVerdict=aborted when AbortSignal fires', async () => {
        const ac = new AbortController();
        ac.abort();

        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node', description: 'test' },
        );

        const result = await runVerifyLoop({
            finding: { type: 'xss', line: 5, evidence: 'innerHTML', why: 'tainted', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client,
            signal: ac.signal,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('aborted');
        expect(result.reason).toContain('Cancelled');
    });

    it('retries on timeout and returns INCONCLUSIVE after exhausting rounds', async () => {
        // Each round: generate → runLocalTest(timeout) → no analyze (timeout is retryable)
        // The loop feeds the timeout error back to generate on the next round.
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'timeout',
            output: 'timed out',
            exitCode: -1,
        });

        const postJson = vi.fn();
        // Every generate call returns canTest:true
        postJson.mockResolvedValue({
            canTest: true,
            testScript: 'console.log("x")',
            runner: 'node',
            description: 'test',
        });

        // Use a budget with maxRoundsPerFinding: 2 to limit iterations
        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const budget = defaultVerifyBudget();
        budget.maxRoundsPerFinding = 2;
        budget.maxLlmCalls = 100; // plenty
        const tracker = new VerifyBudgetTracker(budget);

        const result = await runVerifyLoop({
            finding: { type: 'xss', line: 5, evidence: 'innerHTML', why: 'tainted', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client: { postJson } as unknown as ApiClient,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.roundsUsed).toBeGreaterThanOrEqual(2);
        expect(result.reason.toLowerCase()).toContain('timed out');
    });
});
