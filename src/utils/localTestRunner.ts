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
    setupScript?: string | null,
): Promise<LocalTestResult> {
    const safety = checkTestSafety(script, workspaceRoot);
    if (!safety.allowed) {
        return { verdict: 'error', output: `Test script blocked: ${safety.reason}`, exitCode: -1 };
    }

    const testDir = path.join(workspaceRoot, '.securecode');
    if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });

    const isPython = runner === 'python' || runner === 'python3';
    const isTsRunner = runner === 'tsx' || runner === 'ts' || runner === 'bun' || runner === 'deno' || runner === 'pnpm-tsx' || runner === 'yarn-tsx';
    const ext = isPython ? '.py' : (isTsRunner ? '.test.ts' : '.test.js');
    const testFile = path.join(testDir, `verify-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`);

    const setupFile = setupScript
        ? path.join(testDir, `verify-setup-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`)
        : null;

    try {
        if (setupFile && setupScript) {
            const setupSafety = checkTestSafety(setupScript, workspaceRoot);
            if (!setupSafety.allowed) {
                return { verdict: 'error', output: `Setup script blocked: ${setupSafety.reason}`, exitCode: -1 };
            }
            fs.writeFileSync(setupFile, setupScript, 'utf8');
            try {
                const isWindows = process.platform === 'win32';
                let sRunnerBin: string;
                let sRunnerArgs: string[];
                if (runner === 'tsx') { sRunnerBin = 'npx'; sRunnerArgs = ['tsx', setupFile]; }
                else if (runner === 'bun' && isWindows) { sRunnerBin = 'npx'; sRunnerArgs = ['bun', setupFile]; }
                else { sRunnerBin = runner; sRunnerArgs = [setupFile]; }
                execFileSync(sRunnerBin, sRunnerArgs, {
                    cwd: workspaceRoot,
                    timeout: 10_000,
                    encoding: 'utf8',
                    stdio: ['pipe', 'pipe', 'pipe'],
                    env: { ...process.env, NODE_ENV: 'test' },
                    shell: isWindows,
                });
            } catch (err: any) {
                return { verdict: 'error', output: `Setup script failed: ${err.stderr || err.stdout || err.message}`, exitCode: -1 };
            }
        }

        fs.writeFileSync(testFile, script, 'utf8');

        let stdout = '';
        let stderr = '';
        let exitCode = 0;
        let timedOut = false;

        try {
            const isWindows = process.platform === 'win32';
            let runnerBin: string;
            let runnerArgs: string[];
            if (runner === 'tsx') {
                runnerBin = 'npx';
                runnerArgs = ['tsx', testFile];
            } else if (runner === 'pnpm-tsx') {
                runnerBin = 'pnpm';
                runnerArgs = ['exec', 'tsx', testFile];
            } else if (runner === 'yarn-tsx') {
                runnerBin = 'yarn';
                runnerArgs = ['tsx', testFile];
            } else if (runner === 'deno') {
                runnerBin = 'deno';
                runnerArgs = ['run', '--allow-read', '--allow-env', testFile];
            } else if (runner === 'bun' && isWindows) {
                runnerBin = 'npx';
                runnerArgs = ['bun', testFile];
            } else {
                runnerBin = runner;
                runnerArgs = [testFile];
            }
            stdout = execFileSync(runnerBin, runnerArgs, {
                cwd: workspaceRoot,
                timeout: TIMEOUT_MS,
                encoding: 'utf8',
                stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env, NODE_ENV: 'test' },
                shell: isWindows,
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
        if (setupFile) { try { fs.unlinkSync(setupFile); } catch {} }
    }
}
