import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mergeFixedCode } from '../src/attack/fixCodeMerge';
import { runFixVerifyLoop } from '../src/attack/fixVerifyLoop';
import type { ApiClient } from '../api/client';

// Mock localTestRunner — same pattern as verifyLoop.test.ts
vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

import { runLocalTest } from '../src/utils/localTestRunner';

const VALID_PROOF_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"real-import"}:SECURECODE_PROOF_END';

function makeMockClient(): ApiClient {
    const postJson = vi.fn();
    return { postJson } as unknown as ApiClient;
}

const ORIGINAL_CODE = 'line1\nline2\nline3\nline4\nline5\n';
const FIXED_CODE = 'line1\nfixed_line2\nfixed_line3\nline4\nline5\n';

// ── mergeFixedCode tests ─────────────────────────────────────────────────────

describe('mergeFixedCode', () => {
    it('replaces the declared line range with fixed code', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'replaced', { start_line: 2, end_line: 3 });
        expect(result.ok).toBe(true);
        if (result.ok) {
            const lines = result.mergedCode.split('\n');
            expect(lines[0]).toBe('line1');
            expect(lines[1]).toBe('replaced');
            expect(lines[2]).toBe('line4');
            expect(lines[3]).toBe('line5');
        }
    });

    it('replaces a single line', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'new_line', { start_line: 3, end_line: 3 });
        expect(result.ok).toBe(true);
        if (result.ok) {
            const lines = result.mergedCode.split('\n');
            expect(lines[2]).toBe('new_line');
        }
    });

    it('preserves lines before and after the replacement', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'X', { start_line: 2, end_line: 4 });
        expect(result.ok).toBe(true);
        if (result.ok) {
            const lines = result.mergedCode.split('\n');
            expect(lines[0]).toBe('line1');
            expect(lines[1]).toBe('X');
            expect(lines[2]).toBe('line5');
        }
    });

    it('handles multi-line fixed code', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'a\nb\nc', { start_line: 2, end_line: 3 });
        expect(result.ok).toBe(true);
        if (result.ok) {
            const lines = result.mergedCode.split('\n');
            expect(lines[1]).toBe('a');
            expect(lines[2]).toBe('b');
            expect(lines[3]).toBe('c');
            expect(lines[4]).toBe('line4');
        }
    });

    it('rejects start_line < 1', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'X', { start_line: 0, end_line: 1 });
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error).toContain('start_line');
    });

    it('rejects end_line < start_line', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'X', { start_line: 3, end_line: 2 });
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error).toContain('end_line');
    });

    it('rejects end_line exceeding file length', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'X', { start_line: 1, end_line: 100 });
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.error).toContain('exceeds file length');
    });

    it('rejects non-integer line numbers', () => {
        const result = mergeFixedCode(ORIGINAL_CODE, 'X', { start_line: 1.5, end_line: 2 });
        expect(result.ok).toBe(false);
    });
});

// ── runFixVerifyLoop tests ────────────────────────────────────────────────────

describe('runFixVerifyLoop', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    const baseOpts = {
        finding: { type: 'command_injection', line: 2, evidence: 'exec(input)', why: 'user input', severity: 'high' },
        originalCode: ORIGINAL_CODE,
        fixedCode: FIXED_CODE,
        replaceRange: { start_line: 2, end_line: 3 },
        filePath: 'src/foo.ts',
        relatedFiles: [],
        workspaceRoot: '/tmp/workspace',
        language: 'javascript',
    };

    it('returns closed when original PROVEN + fixed UNPROVEN', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: 'FAIL: guard held',
            exitCode: 0,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("FAIL")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'exploit blocked', shouldRetry: false });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
        });

        expect(result.status).toBe('closed');
        expect(result.originalVerdict).toBe('PROVEN');
        expect(result.fixedVerdict).toBe('UNPROVEN');
        expect(result.fixedCodeHash).toMatch(/^[0-9a-f]{16}$/);
    });

    it('returns still-vulnerable when original PROVEN + fixed PROVEN', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass',
            output: `PASS: exploit worked\n${VALID_PROOF_MARKER}`,
            exitCode: 0,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("PASS")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
        });

        expect(result.status).toBe('still-vulnerable');
        expect(result.fixedVerdict).toBe('PROVEN');
    });

    it('returns inconclusive when original PROVEN + fixed INCONCLUSIVE', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'error',
            output: 'TypeError',
            exitCode: 1,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("x")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'INCONCLUSIVE', reason: 'test crashed', shouldRetry: false });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
        });

        expect(result.status).toBe('inconclusive');
        expect(result.fixedVerdict).toBe('INCONCLUSIVE');
    });

    it('returns conservative inconclusive when original UNPROVEN + fixed UNPROVEN', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: 'FAIL: blocked',
            exitCode: 0,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("FAIL")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'blocked', shouldRetry: false });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'UNPROVEN',
        });

        expect(result.status).toBe('inconclusive');
        expect(result.reason).toContain('not PROVEN');
    });

    it('returns conservative inconclusive when original INCONCLUSIVE', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: 'FAIL: blocked',
            exitCode: 0,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("FAIL")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'blocked', shouldRetry: false });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'INCONCLUSIVE',
        });

        expect(result.status).toBe('inconclusive');
    });

    it('returns syntax-invalid when merge fails (bad line range)', async () => {
        const client = makeMockClient();

        const result = await runFixVerifyLoop({
            ...baseOpts,
            replaceRange: { start_line: 10, end_line: 100 },
            client,
            originalVerdict: 'PROVEN',
        });

        expect(result.status).toBe('syntax-invalid');
        expect(result.reason).toContain('merge failed');
        expect(result.roundsUsed).toBe(0);
    });

    it('returns sandbox-unavailable when no isolation backend exists', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'sandbox-unavailable',
            output: 'No verification sandbox backend (Docker or Deno) was detected.',
            exitCode: -1,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson).mockResolvedValue({
            canTest: true, testScript: 'console.log("x")', runner: 'node',
        });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
        });

        expect(result.status).toBe('sandbox-unavailable');
        expect(result.reason).toContain('sandbox');
    });

    it('returns cancelled when AbortSignal fires before starting', async () => {
        const ac = new AbortController();
        ac.abort();

        const client = makeMockClient();

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
            signal: ac.signal,
        });

        expect(result.status).toBe('cancelled');
        expect(result.reason).toContain('cancelled');
    });

    it('records the fixed code hash but not the full fixed code', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: 'FAIL: blocked',
            exitCode: 0,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("x")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'blocked', shouldRetry: false });

        const result = await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
        });

        expect(result.fixedCodeHash).toMatch(/^[0-9a-f]{16}$/);
        // The result should NOT contain the full fixed code
        expect(JSON.stringify(result)).not.toContain('fixed_line2');
    });

    it('passes verificationPhase=fix to the API', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'fail',
            output: 'FAIL: blocked',
            exitCode: 0,
        });

        const client = makeMockClient();
        vi.mocked(client.postJson)
            .mockResolvedValueOnce({ canTest: true, testScript: 'console.log("x")', runner: 'node' })
            .mockResolvedValueOnce({ verdict: 'UNPROVEN', reason: 'blocked', shouldRetry: false });

        await runFixVerifyLoop({
            ...baseOpts,
            client,
            originalVerdict: 'PROVEN',
        });

        // The first postJson call should be to /verify/generate with verificationPhase=fix
        const generateCall = vi.mocked(client.postJson).mock.calls[0];
        expect(generateCall[0]).toBe('/verify/generate');
        expect((generateCall[1] as any).verificationPhase).toBe('fix');

        // The second postJson call should be to /verify/analyze with verificationPhase=fix
        const analyzeCall = vi.mocked(client.postJson).mock.calls[1];
        expect(analyzeCall[0]).toBe('/verify/analyze');
        expect((analyzeCall[1] as any).verificationPhase).toBe('fix');
    });
});
