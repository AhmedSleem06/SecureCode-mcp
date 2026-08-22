import * as fs from 'fs';
import * as path from 'path';
import type { ApiClient } from '../api/client';
import { runLocalTest } from '../utils/localTestRunner';

export interface MutationTestOptions {
    testScript: string;
    runner: string;
    workspaceRoot: string;
    filePath: string;
    code: string;
    vulnerabilityType: string;
    line: number;
    evidence: string;
    why: string;
    client: ApiClient;
}

export interface MutationTestResult {
    discriminating: boolean;
    mutatedVerdict: 'pass' | 'fail' | 'error' | 'timeout' | 'not-run';
    reason: string;
}

export async function runMutationTest(opts: MutationTestOptions): Promise<MutationTestResult> {
    try {
        const mutationResp = await opts.client.postJson<any>('/verify/generate', {
            code: opts.code,
            language: 'typescript',
            vulnerabilityType: opts.vulnerabilityType,
            line: opts.line,
            evidence: opts.evidence,
            why: opts.why,
            filePath: opts.filePath,
            verificationPhase: 'mutation',
            projectRuntime: 'node',
            suggestedRunner: opts.runner,
        });

        if (!mutationResp || !mutationResp.canTest || !mutationResp.testScript) {
            return {
                discriminating: false,
                mutatedVerdict: 'not-run',
                reason: 'Could not generate a secure mutation test',
            };
        }

        const sandboxDir = path.join(opts.workspaceRoot, '.securecode');
        if (!fs.existsSync(sandboxDir)) fs.mkdirSync(sandboxDir, { recursive: true });

        const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
        const mutationFile = path.join(sandboxDir, `mutation-${suffix}.${opts.runner === 'python3' ? 'py' : 'js'}`);
        fs.writeFileSync(mutationFile, mutationResp.testScript, 'utf8');

        try {
            const result = await runLocalTest(mutationResp.testScript, mutationResp.runner || opts.runner, opts.workspaceRoot, {
                setupScript: null,
                timeoutMs: 30_000,
            });

            if (result.verdict === 'pass') {
                return {
                    discriminating: false,
                    mutatedVerdict: 'pass',
                    reason: `Mutation test PASSED — the test does not discriminate between vulnerable and secure code. ${result.output.slice(0, 200)}`,
                };
            }

            return {
                discriminating: true,
                mutatedVerdict: result.verdict === 'fail' ? 'fail' : 'error',
                reason: `Mutation test ${result.verdict === 'fail' ? 'FAILED' : 'errored'} — the test discriminates correctly. ${result.output.slice(0, 200)}`,
            };
        } finally {
            try { fs.unlinkSync(mutationFile); } catch { /* best effort */ }
        }
    } catch (err: any) {
        return {
            discriminating: false,
            mutatedVerdict: 'not-run',
            reason: `Mutation test failed to execute: ${err.message}`,
        };
    }
}
