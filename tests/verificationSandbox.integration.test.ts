// Sandbox integration tests — require Docker. Skipped automatically when
// Docker is not available. Run on a Docker-equipped machine or CI.

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

function dockerAvailable(): boolean {
    try {
        return spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 }).status === 0;
    } catch {
        return false;
    }
}

const HAS_DOCKER = dockerAvailable();
const describeDocker = HAS_DOCKER ? describe : describe.skip;

import { detectSandbox, _resetSandboxCacheForTests, type SandboxExecuteOptions } from '../src/utils/verificationSandbox';

function makeWorkspace(): string {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-int-'));
    fs.mkdirSync(path.join(ws, '.securecode'), { recursive: true });
    return ws;
}

function makeExecOpts(ws: string, script: string, runner = 'node', setupScript: string | null = null, timeoutMs = 30000): SandboxExecuteOptions {
    return {
        mode: 'script',
        script,
        runner,
        workspaceRoot: ws,
        setupScript,
        timeoutMs,
    };
}

describe('sandbox integration (Suite 3) — requires Docker', () => {
    let backend: ReturnType<typeof detectSandbox>;

    beforeAll(() => {
        _resetSandboxCacheForTests();
        backend = detectSandbox();
    });

    describeDocker('runner dispatch', () => {
        it('node runner executes via node', async () => {
            const ws = makeWorkspace();
            try {
                const result = await backend!.execute(makeExecOpts(
                    ws, 'console.log("PASS: node-" + process.version)',
                ));
                expect(result.verdict).toBe('pass');
                expect(result.output).toContain('node-');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });

        it('python3 runner executes via python', async () => {
            const ws = makeWorkspace();
            try {
                const result = await backend!.execute(makeExecOpts(
                    ws, 'import sys; print("PASS: python-" + sys.version.split(" ")[0])',
                    'python3',
                ));
                expect(result.verdict).toBe('pass');
                expect(result.output).toContain('python-');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });
    });

    describeDocker('network isolation', () => {
        it('blocks outbound network', async () => {
            const ws = makeWorkspace();
            try {
                const script = `
                    const http = require('http');
                    const req = http.get('http://1.2.3.4:80/', (res) => {
                        console.log("FAIL: network reachable, status=" + res.statusCode);
                    });
                    req.on('error', (e) => {
                        console.log("PASS: network blocked — " + e.code);
                    });
                    req.setTimeout(3000, () => {
                        req.destroy();
                        console.log("PASS: network blocked (timeout)");
                    });
                `;
                const result = await backend!.execute(makeExecOpts(ws, script, 'node', null, 15000));
                expect(result.verdict).toBe('pass');
                expect(result.output).toContain('network blocked');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });
    });

    describeDocker('workspace read-only', () => {
        it('cannot write to /workspace', async () => {
            const ws = makeWorkspace();
            try {
                const script = `
                    const fs = require('fs');
                    try {
                        fs.writeFileSync('/workspace/escape.txt', 'gotcha');
                        console.log("FAIL: wrote to /workspace");
                    } catch (e) {
                        console.log("PASS: workspace read-only — " + e.code);
                    }
                `;
                const result = await backend!.execute(makeExecOpts(ws, script));
                expect(result.verdict).toBe('pass');
                expect(result.output).toContain('read-only');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });
    });

    describeDocker('timeout kill', () => {
        it('kills the container at the timeout boundary', async () => {
            const ws = makeWorkspace();
            try {
                const result = await backend!.execute(makeExecOpts(
                    ws, 'setTimeout(() => {}, 60000);', 'node', null, 5000,
                ));
                expect(result.verdict).toBe('timeout');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        }, 20000);
    });

    describeDocker('abort → cancelled (not timeout)', () => {
        it('returns cancelled when AbortSignal fires mid-test', async () => {
            const ws = makeWorkspace();
            try {
                const controller = new AbortController();
                const opts = makeExecOpts(ws, 'setTimeout(() => {}, 60000);', 'node', null, 30000);
                opts.signal = controller.signal;
                const resultP = backend!.execute(opts);
                setTimeout(() => controller.abort(), 1000);
                const result = await resultP;
                expect(result.verdict).toBe('cancelled');
                expect(result.verdict).not.toBe('timeout');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        }, 20000);
    });

    describeDocker('setup-then-test sequencing', () => {
        it('runs setup before test and test sees setup side effects', async () => {
            const ws = makeWorkspace();
            try {
                const setup = `
                    const fs = require('fs');
                    fs.writeFileSync('/tmp/setup-marker.txt', 'setup-ran');
                    console.log('setup done');
                `;
                const test = `
                    const fs = require('fs');
                    try {
                        const marker = fs.readFileSync('/tmp/setup-marker.txt', 'utf8');
                        if (marker === 'setup-ran') {
                            console.log('PASS: setup ran before test');
                        } else {
                            console.log('FAIL: wrong marker: ' + marker);
                        }
                    } catch (e) {
                        console.log('FAIL: setup did not run — ' + e.code);
                    }
                `;
                const result = await backend!.execute(makeExecOpts(ws, test, 'node', setup, 15000));
                expect(result.verdict).toBe('pass');
                expect(result.output).toContain('setup ran before test');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });

        it('stops test execution when setup fails', async () => {
            const ws = makeWorkspace();
            try {
                const setup = `throw new Error("setup boom");`;
                const test = `console.log('PASS: should not reach');`;
                const result = await backend!.execute(makeExecOpts(ws, test, 'node', setup, 15000));
                expect(result.verdict).not.toBe('pass');
                expect(result.output).not.toContain('should not reach');
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });
    });

    describeDocker('temp file cleanup', () => {
        it('removes verify-test temp files after execution', async () => {
            const ws = makeWorkspace();
            try {
                await backend!.execute(makeExecOpts(ws, 'console.log("PASS: done")'));
                const sandboxDir = path.join(ws, '.securecode');
                const leftovers = fs.readdirSync(sandboxDir).filter(f => f.startsWith('verify-'));
                expect(leftovers).toHaveLength(0);
            } finally { fs.rmSync(ws, { recursive: true, force: true }); }
        });
    });
});
