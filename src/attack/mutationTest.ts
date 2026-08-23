import * as fs from 'fs';
import * as path from 'path';
import { runLocalTest } from '../utils/localTestRunner';
import { applyMutation } from './mutationOperators';

export interface MutationTestOptions {
    /** The original vulnerable code (the code being tested). */
    vulnerableCode: string;
    /** The test script that should catch the vulnerability. */
    testScript: string;
    /** The runner to use (node, python3, etc.). */
    runner: string;
    /** Workspace root for the sandbox. */
    workspaceRoot: string;
    /** File path of the vulnerable code (for error messages). */
    filePath: string;
    /** Vulnerability type (broken_access_control, sql_injection, etc.). */
    vulnerabilityType: string;
    /** Line number of the vulnerability. */
    line: number;
}

export interface MutationTestResult {
    discriminating: boolean;
    mutatedVerdict: 'pass' | 'fail' | 'error' | 'timeout' | 'not-run';
    reason: string;
}

/**
 * Run a mutation test:
 *
 * 1. Apply a security mutation to the vulnerable code (e.g., add an auth guard).
 * 2. Run the test script against the mutated (secure) code.
 * 3. If the test PASSES on the original but FAILS on the mutation → discriminating.
 * 4. If the test PASSES on both → non-discriminating (the test doesn't test security).
 * 5. If the test ERRORS on the mutation → INCONCLUSIVE (not discriminating).
 *
 * Never label mutation errors as successful discrimination.
 */
export async function runMutationTest(opts: MutationTestOptions): Promise<MutationTestResult> {
    const mutation = applyMutation(opts.vulnerableCode, opts.vulnerabilityType, opts.line);

    if (!mutation.mutated) {
        return {
            discriminating: false,
            mutatedVerdict: 'not-run',
            reason: `Mutation test skipped: ${mutation.description}`,
        };
    }

    const sandboxDir = path.join(opts.workspaceRoot, '.securecode');
    if (!fs.existsSync(sandboxDir)) fs.mkdirSync(sandboxDir, { recursive: true });

    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const ext = opts.runner === 'python3' ? 'py' : 'js';
    const mutationFile = path.join(sandboxDir, `mutation-${suffix}.${ext}`);

    try {
        // Write the mutated code to the sandbox file
        fs.writeFileSync(mutationFile, mutation.mutatedCode, 'utf8');

        // Run the test script against the mutated code
        const result = await runLocalTest(
            mutation.mutatedCode,
            opts.runner,
            opts.workspaceRoot,
            {
                setupScript: null,
                timeoutMs: 30_000,
            },
        );

        if (result.verdict === 'pass') {
            return {
                discriminating: false,
                mutatedVerdict: 'pass',
                reason: `Mutation test PASSED — the test does not discriminate between vulnerable and secure code. ${mutation.description}. ${result.output.slice(0, 200)}`,
            };
        }

        if (result.verdict === 'fail') {
            return {
                discriminating: true,
                mutatedVerdict: 'fail',
                reason: `Mutation test FAILED — the test correctly discriminates: ${mutation.description}. ${result.output.slice(0, 200)}`,
            };
        }

        // error or timeout → INCONCLUSIVE, not discriminating
        return {
            discriminating: false,
            mutatedVerdict: result.verdict === 'timeout' ? 'timeout' : 'error',
            reason: `Mutation test ${result.verdict === 'timeout' ? 'timed out' : 'errored'} — INCONCLUSIVE (not discriminating). ${mutation.description}. ${result.output.slice(0, 200)}`,
        };
    } catch (err: any) {
        return {
            discriminating: false,
            mutatedVerdict: 'error',
            reason: `Mutation test failed to execute: ${err.message || err}`,
        };
    } finally {
        try { fs.unlinkSync(mutationFile); } catch { /* best effort */ }
    }
}
