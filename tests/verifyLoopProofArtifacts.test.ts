import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runVerifyLoop } from '../src/attack/verifyLoop';
import type { ApiClient } from '../src/api/client';

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
const SCRIPT = 'const r = run("1 OR 1=1"); console.log("PASS: exploit");';

function client(...responses: any[]): ApiClient {
    const postJson = vi.fn();
    for (const r of responses) postJson.mockResolvedValueOnce(r);
    return { postJson } as unknown as ApiClient;
}

function readArtifacts(root: string): any[] {
    const dir = path.join(root, '.securecode', 'proofs');
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir).map((f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')));
}

describe('runVerifyLoop — proof artifacts', () => {
    let root: string;

    beforeEach(() => {
        root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-verify-art-'));
        vi.mocked(runLocalTest).mockReset();
    });

    afterEach(() => {
        fs.rmSync(root, { recursive: true, force: true });
    });

    const opts = () => ({
        finding: { type: 'sql_injection', line: 12, evidence: 'query(input)', why: 'tainted', severity: 'high' },
        filePath: 'src/db.ts',
        code: 'const x = 1;',
        relatedFiles: [],
        workspaceRoot: root,
        language: 'javascript',
    });

    it('saves an artifact with the test script for a PROVEN result and links it from proofEvidence', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({ verdict: 'pass', output: `PASS: exploit\n${VALID_PROOF_MARKER}`, exitCode: 0 });
        const result = await runVerifyLoop({
            ...opts(),
            client: client(
                { canTest: true, testScript: SCRIPT, setupScript: 'npm i', runner: 'node', description: 't' },
                { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: false },
            ),
        });

        expect(result.verdict).toBe('PROVEN');
        expect(result.proofEvidence?.artifactPath).toBe(`.securecode/proofs/${result.proofEvidence!.proofId}.json`);
        const saved = JSON.parse(fs.readFileSync(path.join(root, result.proofEvidence!.artifactPath!), 'utf8'));
        expect(saved.proofId).toBe(result.proofEvidence!.proofId);
        expect(saved.finding).toEqual({ file: 'src/db.ts', line: 12, type: 'sql_injection', severity: 'high' });
        expect(saved.rounds.length).toBe(3);
        expect(saved.rounds[0]).toMatchObject({ round: 1, testScript: SCRIPT, setupScript: 'npm i', runner: 'node', verdict: 'pass' });
        expect(saved.rounds[0].output).toContain('PASS: exploit');
        expect(saved.rounds[1].verdict).toBe('repeat-2:pass');
        expect(saved.mutation).toMatchObject({ mutatedVerdict: 'fail', reason: 'mutation test passed (discriminating)' });
        expect(saved.proofGate).toEqual({ failedGates: [], warnings: expect.any(Array) });
        expect(saved.finalVerdict).toBe('PROVEN');
    });

    it('saves an artifact with the test script for an INCONCLUSIVE result', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({ verdict: 'error', output: 'TypeError: x is not a function', exitCode: 1 });
        const result = await runVerifyLoop({
            ...opts(),
            client: client(
                { canTest: true, testScript: SCRIPT, runner: 'node', description: 't' },
                { verdict: 'INCONCLUSIVE', reason: 'type error', shouldRetry: false },
            ),
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        const artifacts = readArtifacts(root);
        expect(artifacts.length).toBe(1);
        expect(artifacts[0].rounds[0]).toMatchObject({ round: 1, testScript: SCRIPT, verdict: 'error' });
        expect(artifacts[0].rounds[0].output).toContain('TypeError');
        expect(artifacts[0].mutation).toBeNull();
        expect(artifacts[0].finalVerdict).toBe('INCONCLUSIVE');
        expect(artifacts[0].finalReason).toBe('type error');
    });

    it('accepts an old API PROVEN answer with shouldRetry=true instead of returning malformed INCONCLUSIVE', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({ verdict: 'pass', output: `PASS: exploit\n${VALID_PROOF_MARKER}`, exitCode: 0 });
        const result = await runVerifyLoop({
            ...opts(),
            client: client(
                { canTest: true, testScript: SCRIPT, runner: 'node', description: 't' },
                { verdict: 'PROVEN', reason: 'exploit succeeded', shouldRetry: true },
            ),
        });

        expect(result.verdict).toBe('PROVEN');
        expect(result.reason).not.toContain('malformed');
    });

    it('does not write an artifact when no test ran', async () => {
        const result = await runVerifyLoop({
            ...opts(),
            client: client({ canTest: false, skipReason: 'needs running server' }),
        });
        expect(result.subVerdict).toBe('cannot-test');
        expect(readArtifacts(root)).toEqual([]);
    });
});
