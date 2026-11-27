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

vi.mock('../src/utils/verificationSandbox', () => ({
    detectSandbox: () => ({ name: 'deno' }),
}));

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

vi.mock('../src/attack/mutationTest', () => ({
    runMutationTest: vi.fn().mockResolvedValue({ discriminating: true, mutatedVerdict: 'fail', reason: 'mutation test passed (discriminating)' }),
}));

import { runLocalTest } from '../src/utils/localTestRunner';

const VALID_PROOF_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"real-import"}:SECURECODE_PROOF_END';

describe('runVerifyLoop', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    it('returns PROVEN when test passes on first round', async () => {
        const passResult = {
            verdict: 'pass' as const,
            output: `PASS: exploit worked\n${VALID_PROOF_MARKER}`,
            exitCode: 0,
        };
        vi.mocked(runLocalTest).mockResolvedValue(passResult);

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
            .mockResolvedValue({ verdict: 'pass', output: `PASS: exploit worked\n${VALID_PROOF_MARKER}`, exitCode: 0 });

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

    it('retries a blocked script and returns subVerdict=blocked after the last round', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'blocked',
            output: 'Test script blocked: eval() executes arbitrary strings as code',
            exitCode: -1,
        });

        const client = makeMockClient(
            { canTest: true, testScript: 'eval("x")', runner: 'node', description: 'test' },
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
        expect(vi.mocked(runLocalTest).mock.calls.length).toBeGreaterThan(1);
        const lastGenerateBody = vi.mocked(client.postJson).mock.calls.at(-1)?.[1] as any;
        expect(lastGenerateBody.previousErrors.join(' ')).toContain('static safety check');
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
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'timeout',
            output: 'timed out',
            exitCode: -1,
        });

        const postJson = vi.fn();
        postJson.mockResolvedValue({
            canTest: true,
            testScript: 'console.log("x")',
            runner: 'node',
            description: 'test',
        });

        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const budget = defaultVerifyBudget();
        budget.maxRoundsPerFinding = 2;
        budget.maxLlmCalls = 100;
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
        expect(result.reason.toLowerCase()).toMatch(/timed? out|same failure twice.*timeout/);
    });
});

describe('runVerifyLoop — scan budget (runId)', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    const baseOpts = {
        finding: { type: 'command_injection', line: 10, evidence: 'exec(input)', why: 'user input', severity: 'high' },
        filePath: 'src/foo.ts',
        code: 'const x = 1;',
        relatedFiles: [],
        workspaceRoot: '/tmp/workspace',
        language: 'javascript',
    };

    function budgetError() {
        const err: any = new Error('Scan budget exhausted');
        err.status = 402;
        err.apiCode = 'AGENT_SCAN_BUDGET_EXHAUSTED';
        err.capReason = 'insufficient_credits';
        return err;
    }

    it('sends runId to /verify/generate and /verify/analyze', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({ verdict: 'fail', output: 'FAIL: guard blocked', exitCode: 0 });
        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log(1)', runner: 'node', description: 't' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false });

        await runVerifyLoop({ ...baseOpts, client: { postJson } as unknown as ApiClient, runId: 'run-9' });

        expect(postJson.mock.calls[0][0]).toBe('/verify/generate');
        expect(postJson.mock.calls[0][1].runId).toBe('run-9');
        expect(postJson.mock.calls[1][0]).toBe('/verify/analyze');
        expect(postJson.mock.calls[1][1].runId).toBe('run-9');
    });

    it('omits runId when none is given (old behaviour)', async () => {
        const postJson = vi.fn().mockResolvedValue({ canTest: false, skipReason: 'n/a' });

        await runVerifyLoop({ ...baseOpts, client: { postJson } as unknown as ApiClient });

        expect(postJson.mock.calls[0][1]).not.toHaveProperty('runId');
    });

    it('returns INCONCLUSIVE budget-exhausted on a 402 from /verify/generate instead of throwing', async () => {
        const postJson = vi.fn().mockRejectedValue(budgetError());

        const result = await runVerifyLoop({ ...baseOpts, client: { postJson } as unknown as ApiClient, runId: 'run-9' });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.subVerdict).toBe('budget-exhausted');
        expect(result.budgetExhaustedReason).toBe('scan-budget');
        expect(result.reason).toContain('top up credits');
        expect(result.roundsUsed).toBe(0);
    });

    it('returns INCONCLUSIVE budget-exhausted on a 402 from /verify/analyze', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({ verdict: 'pass', output: 'PASS', exitCode: 0 });
        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log(1)', runner: 'node', description: 't' })
            .mockRejectedValueOnce(budgetError());

        const result = await runVerifyLoop({ ...baseOpts, client: { postJson } as unknown as ApiClient, runId: 'run-9' });

        expect(result.subVerdict).toBe('budget-exhausted');
        expect(result.budgetExhaustedReason).toBe('scan-budget');
        expect(result.roundsUsed).toBe(1);
        expect(result.testScript).toBe('console.log(1)');
    });

    it('still throws other API errors', async () => {
        const err: any = new Error('server down');
        err.status = 503;
        const postJson = vi.fn().mockRejectedValue(err);

        await expect(runVerifyLoop({ ...baseOpts, client: { postJson } as unknown as ApiClient, runId: 'run-9' })).rejects.toThrow('server down');
    });
});

describe('runVerifyLoop — testValidity guard on UNPROVEN', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    const baseOpts = {
        finding: { type: 'race_condition', line: 69, evidence: 'concurrent transfer', why: 'no lock', severity: 'high' },
        filePath: 'src/wallet.ts',
        code: 'const x = 1;',
        relatedFiles: [],
        workspaceRoot: '/tmp/workspace',
        language: 'javascript',
    };

    const HARNESS_LOG_UNMATCHED = '\nSECURECODE_HARNESS_LOG:{"calls":[{"method":"POST","path":"/wallet/create","matched":false,"sent":false,"timedOut":false}]}:SECURECODE_HARNESS_END\n';
    const PROOF_BASELINE_PASS = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"fail","impact":"not-observed","targetReached":true}:SECURECODE_PROOF_END';
    const HARNESS_LOG_GOOD = '\nSECURECODE_HARNESS_LOG:{"calls":[{"method":"GET","path":"/transfer","matched":true,"sent":true,"status":200,"timedOut":false}]}:SECURECODE_HARNESS_END\n';

    it('UNPROVEN with unmatched-route harness log → retries then INCONCLUSIVE, never UNPROVEN', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'fail',
            output: `FAIL: blocked\n${PROOF_BASELINE_PASS}\n${HARNESS_LOG_UNMATCHED}`,
            exitCode: 0,
        });

        const postJson = vi.fn();
        postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return { canTest: true, testScript: 'console.log("test")', runner: 'node', description: 'test' };
            if (p === '/verify/analyze') return { verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false };
            throw new Error(`unexpected ${p}`);
        });

        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const budget = defaultVerifyBudget();
        budget.maxRoundsPerFinding = 3;
        budget.maxLlmCalls = 100;
        const tracker = new VerifyBudgetTracker(budget);

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
            budgetTracker: tracker,
        });

        expect(result.verdict).not.toBe('UNPROVEN');
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('invalid');
        expect(result.subVerdict).toBe('analyzed');

        const generateCalls = postJson.mock.calls.filter((c: any) => c[0] === '/verify/generate');
        expect(generateCalls.length).toBeGreaterThan(1);
        const lastGenBody = generateCalls[generateCalls.length - 1][1];
        expect(lastGenBody.previousErrors.some((e: string) => e.includes('/wallet/create'))).toBe(true);
    });

    it('UNPROVEN with a valid log + baseline pass stays UNPROVEN', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: `FAIL: guard blocked\n${PROOF_BASELINE_PASS}\n${HARNESS_LOG_GOOD}`,
            exitCode: 0,
        });

        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("test")', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false });

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
        });

        expect(result.verdict).toBe('UNPROVEN');
    });

    it('missing setup field does not invalidate an UNPROVEN result', async () => {
        const PROOF_NO_SETUP = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"fail","impact":"not-observed","targetReached":true}:SECURECODE_PROOF_END';
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: `FAIL: guard held\n${PROOF_NO_SETUP}\n${HARNESS_LOG_GOOD}`,
            exitCode: 0,
        });

        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("test")', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false });

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
        });

        expect(result.verdict).toBe('UNPROVEN');
    });

    it('UNPROVEN with setup=fail → retries then INCONCLUSIVE', async () => {
        const PROOF_SETUP_FAIL = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"fail","setup":"fail","setupNote":"POST /wallet/create returned 404"}:SECURECODE_PROOF_END';
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'fail',
            output: `FAIL: guard held\n${PROOF_SETUP_FAIL}\n${HARNESS_LOG_GOOD}`,
            exitCode: 0,
        });

        const postJson = vi.fn();
        postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return { canTest: true, testScript: 'console.log("test")', runner: 'node', description: 'test' };
            if (p === '/verify/analyze') return { verdict: 'UNPROVEN', reason: 'guard held', shouldRetry: false };
            throw new Error(`unexpected ${p}`);
        });

        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const budget = defaultVerifyBudget();
        budget.maxRoundsPerFinding = 2;
        budget.maxLlmCalls = 100;
        const tracker = new VerifyBudgetTracker(budget);

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('setup failed');
    });
});

describe('runVerifyLoop — engine validity guard on PROVEN', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    const baseOpts = {
        finding: { type: 'missing_auth', line: 20, evidence: 'no auth check', why: 'admin route', severity: 'high' },
        filePath: 'src/admin.ts',
        code: 'const x = 1;',
        relatedFiles: [],
        workspaceRoot: '/tmp/workspace',
        language: 'javascript',
    };

    const HARNESS_LOG_EMULATED_UNSUPPORTED = '\nSECURECODE_HARNESS_LOG:{"calls":[{"method":"GET","path":"/admin/config","matched":true,"sent":true,"status":200,"timedOut":false}],"engine":"emulated","unsupported":["wildcard path /admin/*path"]}:SECURECODE_HARNESS_END\n';

    it('PROVEN with emulated+unsupported log → INCONCLUSIVE', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass',
            output: `PASS: exploit worked\n${VALID_PROOF_MARKER}\n${HARNESS_LOG_EMULATED_UNSUPPORTED}`,
            exitCode: 0,
        });

        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("PASS")', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false });

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('cannot model');
        expect(result.reason).toContain('wildcard path');
        expect(result.subVerdict).toBe('analyzed');
    });

    it('PROVEN with real express engine → still PROVEN', async () => {
        const HARNESS_LOG_REAL = '\nSECURECODE_HARNESS_LOG:{"calls":[{"method":"GET","path":"/admin/config","matched":true,"sent":true,"status":401,"timedOut":false}],"engine":"express@5.0.1","unsupported":[]}:SECURECODE_HARNESS_END\n';
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass',
            output: `PASS: exploit worked\n${VALID_PROOF_MARKER}\n${HARNESS_LOG_REAL}`,
            exitCode: 0,
        });

        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("PASS")', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false });

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
        });

        expect(result.verdict).toBe('PROVEN');
    });

    it('PROVEN with emulated but empty unsupported → still PROVEN', async () => {
        const HARNESS_LOG_EMU_OK = '\nSECURECODE_HARNESS_LOG:{"calls":[{"method":"GET","path":"/admin/config","matched":true,"sent":true,"status":200,"timedOut":false}],"engine":"emulated","unsupported":[]}:SECURECODE_HARNESS_END\n';
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass',
            output: `PASS: exploit worked\n${VALID_PROOF_MARKER}\n${HARNESS_LOG_EMU_OK}`,
            exitCode: 0,
        });

        const postJson = vi.fn()
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("PASS")', runner: 'node', description: 'test' })
            .mockResolvedValueOnce({ verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false });

        const result = await runVerifyLoop({
            ...baseOpts,
            client: { postJson } as unknown as ApiClient,
        });

        expect(result.verdict).toBe('PROVEN');
    });
});
