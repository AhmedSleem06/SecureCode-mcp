import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

import { runMutationTest } from '../src/attack/mutationTest';
import { runLocalTest } from '../src/utils/localTestRunner';

describe('runMutationTest', () => {
    beforeEach(() => vi.clearAllMocks());

    it('returns not-run when no mutation operator is available', async () => {
        const result = await runMutationTest({
            vulnerableCode: 'function handler() {}',
            testScript: 'assert(true)',
            runner: 'node',
            workspaceRoot: os.tmpdir(),
            filePath: 'test.ts',
            vulnerabilityType: 'unknown_type',
            line: 1,
        });

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('not-run');
        expect(result.reason).toContain('No mutation operator');
    });

    it('returns discriminating when mutation makes the test fail', async () => {
        (runLocalTest as any).mockResolvedValue({
            verdict: 'fail',
            output: 'AssertionError: expected 403 but got 200',
        });

        const result = await runMutationTest({
            vulnerableCode: 'function handler(req, res) {\n  res.json({ data });\n}',
            testScript: 'assert(true)',
            runner: 'node',
            workspaceRoot: os.tmpdir(),
            filePath: 'test.ts',
            vulnerabilityType: 'missing_auth',
            line: 2,
        });

        expect(result.discriminating).toBe(true);
        expect(result.mutatedVerdict).toBe('fail');
        expect(result.reason).toContain('discriminates');
    });

    it('returns non-discriminating when mutation makes the test pass', async () => {
        (runLocalTest as any).mockResolvedValue({
            verdict: 'pass',
            output: 'all tests passed',
        });

        const result = await runMutationTest({
            vulnerableCode: 'function handler(req, res) {\n  res.json({ data });\n}',
            testScript: 'assert(true)',
            runner: 'node',
            workspaceRoot: os.tmpdir(),
            filePath: 'test.ts',
            vulnerabilityType: 'missing_auth',
            line: 2,
        });

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('pass');
        expect(result.reason).toContain('does not discriminate');
    });

    it('returns INCONCLUSIVE (not discriminating) when mutation errors', async () => {
        (runLocalTest as any).mockResolvedValue({
            verdict: 'error',
            output: 'SyntaxError: unexpected token',
        });

        const result = await runMutationTest({
            vulnerableCode: 'function handler(req, res) {\n  res.json({ data });\n}',
            testScript: 'assert(true)',
            runner: 'node',
            workspaceRoot: os.tmpdir(),
            filePath: 'test.ts',
            vulnerabilityType: 'missing_auth',
            line: 2,
        });

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('error');
        expect(result.reason).toContain('INCONCLUSIVE');
    });

    it('returns INCONCLUSIVE (not discriminating) when mutation times out', async () => {
        (runLocalTest as any).mockResolvedValue({
            verdict: 'timeout',
            output: 'timed out after 30s',
        });

        const result = await runMutationTest({
            vulnerableCode: 'function handler(req, res) {\n  res.json({ data });\n}',
            testScript: 'assert(true)',
            runner: 'node',
            workspaceRoot: os.tmpdir(),
            filePath: 'test.ts',
            vulnerabilityType: 'missing_auth',
            line: 2,
        });

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('timeout');
        expect(result.reason).toContain('INCONCLUSIVE');
    });
});
