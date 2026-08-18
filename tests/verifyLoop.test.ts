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

describe('runVerifyLoop', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    it('returns PROVEN when test passes on first round', async () => {
        vi.mocked(runLocalTest).mockResolvedValueOnce({
            verdict: 'pass',
            output: 'PASS: exploit worked',
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
            .mockResolvedValueOnce({ verdict: 'pass', output: 'PASS: exploit worked', exitCode: 0 });

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
        vi.mocked(client.postJson)
            .mockResolvedValue({ canTest: true, testScript: 'console.log("test")', runner: 'node', description: 'test' })
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
    });
});
