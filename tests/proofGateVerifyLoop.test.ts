import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runVerifyLoop } from '../src/attack/verifyLoop';
import type { ApiClient } from '../api/client';

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

vi.mock('../src/attack/mutationTest', () => ({
    runMutationTest: vi.fn().mockResolvedValue({ discriminating: true, mutatedVerdict: 'fail', reason: 'ok' }),
}));

import { runLocalTest } from '../src/utils/localTestRunner';

function makeMockClient(genResp: any, analyzeResp?: any): ApiClient {
    const postJson = vi.fn();
    if (analyzeResp) {
        postJson.mockResolvedValueOnce(genResp).mockResolvedValueOnce(analyzeResp);
    } else {
        postJson.mockResolvedValue(genResp);
    }
    return { postJson } as unknown as ApiClient;
}

const VALID_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"real-import"}:SECURECODE_PROOF_END';
const SYNTHETIC_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"synthetic"}:SECURECODE_PROOF_END';
const NO_MARKER_OUTPUT = 'PASS: exploit worked';
const NO_BASELINE_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"fail","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"real-import"}:SECURECODE_PROOF_END';
const MOCKED_PATH_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":true,"sourceMode":"real-import"}:SECURECODE_PROOF_END';
const NO_IMPACT_MARKER = 'SECURECODE_PROOF_RESULT:{"baseline":"pass","exploit":"pass","impact":"not-observed","targetReached":true,"assertion":"deterministic","mockedVulnerablePath":false,"sourceMode":"real-import"}:SECURECODE_PROOF_END';

const BASE_OPTS = {
    finding: { type: 'broken_access_control', line: 10, evidence: 'no auth check', why: 'missing ownership', severity: 'high' },
    filePath: 'src/foo.ts',
    code: 'const x = 1;',
    relatedFiles: [],
    workspaceRoot: '/tmp/workspace',
    language: 'javascript',
};

describe('runVerifyLoop — proof gate enforcement', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    it('returns INCONCLUSIVE when proof marker is missing', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: NO_MARKER_OUTPUT, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.proofGateResult?.failedGates).toContain('proof-marker-missing');
    });

    it('returns INCONCLUSIVE for synthetic source mode', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: `PASS: ok\n${SYNTHETIC_MARKER}`, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.proofGateResult?.failedGates).toContain('synthetic-source');
    });

    it('returns INCONCLUSIVE when baseline fails', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: `PASS: ok\n${NO_BASELINE_MARKER}`, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.proofGateResult?.failedGates).toContain('baseline-failed');
    });

    it('returns INCONCLUSIVE when vulnerable path is mocked', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: `PASS: ok\n${MOCKED_PATH_MARKER}`, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.proofGateResult?.failedGates).toContain('mock-vulnerable-path');
    });

    it('returns UNPROVEN when impact not observed', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: `PASS: ok\n${NO_IMPACT_MARKER}`, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.verdict).toBe('UNPROVEN');
        expect(result.proofGateResult?.failedGates).toContain('impact-not-observed');
    });

    it('returns PROVEN with valid real-import proof marker', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: `PASS: ok\n${VALID_MARKER}`, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.verdict).toBe('PROVEN');
        expect(result.proofGateResult?.eligibleForProven).toBe(true);
        expect(result.proofEvidence?.sourceMode).toBe('real-import');
    });

    it('stores proof evidence and gate result on the result', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'pass', output: `PASS: ok\n${VALID_MARKER}`, exitCode: 0,
        });
        const client = makeMockClient(
            { canTest: true, testScript: 'console.log("PASS")', runner: 'node' },
            { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
        );
        const result = await runVerifyLoop({ ...BASE_OPTS, client });
        expect(result.proofEvidence).toBeDefined();
        expect(result.proofEvidence?.repeatedRuns).toBe(3);
        expect(result.proofEvidence?.repeatPasses).toBe(3);
        expect(result.proofGateResult).toBeDefined();
    });
});
