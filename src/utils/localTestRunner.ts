import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { checkTestSafety } from './testSafety';

export interface LocalTestResult {
    verdict: 'pass' | 'fail' | 'error' | 'timeout';
    output: string;
    exitCode: number;
}

const PASS_PATTERN = /^PASS:\s*(.+)$/m;
const FAIL_PATTERN = /^FAIL:\s*(.+)$/m;
const TIMEOUT_MS = 30_000;

export async function runLocalTest(
    script: string,
    runner: string,
    workspaceRoot: string,
): Promise<LocalTestResult> {
    const safety = checkTestSafety(script, workspaceRoot);
    if (!safety.allowed) {
        return { verdict: 'error', output: `Test script blocked: ${safety.reason}`, exitCode: -1 };
    }

    const testDir = path.join(workspaceRoot, '.securecode');
    if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });

    const ext = runner === 'tsx' || runner === 'ts' ? '.test.ts' : '.test.js';
    const testFile = path.join(testDir, `verify-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`);

    try {
        fs.writeFileSync(testFile, script, 'utf8');

        let stdout = '';
        let stderr = '';
        let exitCode = 0;
        let timedOut = false;

        try {
            const runnerBin = runner === 'tsx' ? 'npx' : runner;
            const runnerArgs = runner === 'tsx' ? ['tsx', testFile] : [testFile];
            stdout = execFileSync(runnerBin, runnerArgs, {
                cwd: workspaceRoot,
                timeout: TIMEOUT_MS,
                encoding: 'utf8',
                stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env, NODE_ENV: 'test' },
            });
        } catch (err: any) {
            stdout = err.stdout || '';
            stderr = err.stderr || '';
            exitCode = err.status ?? 1;
            if (err.signal === 'SIGTERM') timedOut = true;
        }

        const output = (stdout + '\n' + stderr).trim();

        if (timedOut) {
            return { verdict: 'timeout', output: 'Test timed out after 30s', exitCode: -1 };
        }

        if (PASS_PATTERN.test(output)) {
            return { verdict: 'pass', output, exitCode };
        }
        if (FAIL_PATTERN.test(output)) {
            return { verdict: 'fail', output, exitCode };
        }

        if (exitCode === 0) {
            return { verdict: 'error', output: output + '\nTest exited 0 but did not print PASS: or FAIL:', exitCode };
        }
        return { verdict: 'error', output, exitCode };
    } catch (err: any) {
        return { verdict: 'error', output: err.message || String(err), exitCode: -1 };
    } finally {
        try { fs.unlinkSync(testFile); } catch {}
    }
}
