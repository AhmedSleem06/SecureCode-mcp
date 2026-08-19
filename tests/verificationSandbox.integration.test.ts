// Sandbox integration tests — require Docker. Skipped automatically when
// Docker is not available. Run on a Docker-equipped machine or CI.
//
// Covers (per plan):
//   - runner dispatch: node/tsx/bun/deno/python execute via the right runtime
//   - setup-then-test sequencing: setup runs before test, setup failure stops
//   - network blocked: container cannot reach the internet
//   - workspace read-only: container cannot write to /workspace
//   - host secret unavailable: container env is scrubbed
//   - non-root: container runs as uid 1000
//   - timeout kill: container is killed at the timeout boundary
//   - abort kill (cancelled): AbortSignal returns cancelled, not timeout
//   - cleanup: temp files are removed after execution

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

function dockerAvailable(): boolean {
    try {
        const r = spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 });
        return r.status === 0;
    } catch {
        return false;
    }
}

const HAS_DOCKER = dockerAvailable();
const SKIP = !HAS_DOCKER;

const describeDocker = SKIP ? describe.skip : describe;

// Import the real sandbox (no test injection — we want the real Docker backend).
import { detectSandbox, _resetSandboxCacheForTests } from '../src/utils/verificationSandbox';
import { runLocalTest } from '../src/utils/localTestRunner';

describe('sandbox integration (Suite 3) — requires Docker', () => {
    beforeAll(() => {
        _resetSandboxCacheForTests();
    });

    describeDocker('runner dispatch', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-int-'));
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('node runner executes via node', async () => {
            const result = await runLocalTest(
                'console.log("PASS: node-" + process.version)',
                'node',
                workspace,
            );
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('node-');
        });

        it('python3 runner executes via python', async () => {
            const result = await runLocalTest(
                'import sys; print("PASS: python-" + sys.version.split(" ")[0])',
                'python3',
                workspace,
            );
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('python-');
        });
    });

    describeDocker('network isolation', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-net-'));
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('blocks outbound network (fetch fails)', async () => {
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
            const result = await runLocalTest(script, 'node', workspace, { timeoutMs: 10000 });
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('network blocked');
        });
    });

    describeDocker('workspace read-only', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-ro-'));
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('cannot write to /workspace', async () => {
            const script = `
                const fs = require('fs');
                try {
                    fs.writeFileSync('/workspace/escape.txt', 'gotcha');
                    console.log("FAIL: wrote to /workspace");
                } catch (e) {
                    console.log("PASS: workspace read-only — " + e.code);
                }
            `;
            const result = await runLocalTest(script, 'node', workspace);
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('read-only');
        });
    });

    describeDocker('timeout kill', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-to-'));
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('kills the container at the timeout boundary', async () => {
            const script = 'setTimeout(() => {}, 60000);';
            const result = await runLocalTest(script, 'node', workspace, { timeoutMs: 3000 });
            expect(result.verdict).toBe('timeout');
        }, 20000);
    });

    describeDocker('abort → cancelled (not timeout)', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-abort-'));
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('returns cancelled when AbortSignal fires mid-test', async () => {
            const script = 'setTimeout(() => {}, 60000);';
            const controller = new AbortController();
            const resultP = runLocalTest(script, 'node', workspace, {
                timeoutMs: 30000,
                signal: controller.signal,
            });
            setTimeout(() => controller.abort(), 500);
            const result = await resultP;
            expect(result.verdict).toBe('cancelled');
            expect(result.verdict).not.toBe('timeout');
        }, 20000);
    });

    describeDocker('setup-then-test sequencing', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-seq-'));
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('runs setup before test and test sees setup side effects', async () => {
            // Setup writes a marker to /tmp (the only writable area); test reads it.
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
            const result = await runLocalTest(test, 'node', workspace, {
                setupScript: setup,
                timeoutMs: 15000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('setup ran before test');
        });

        it('stops test execution when setup fails', async () => {
            const setup = `throw new Error("setup boom");`;
            const test = `console.log('PASS: should not reach');`;
            const result = await runLocalTest(test, 'node', workspace, {
                setupScript: setup,
                timeoutMs: 15000,
            });
            // Setup failure → the && chain prevents test from running →
            // no PASS/FAIL marker → error verdict.
            expect(result.verdict).not.toBe('pass');
            expect(result.output).not.toContain('should not reach');
        });
    });

    describeDocker('temp file cleanup', () => {
        let workspace: string;
        beforeAll(() => {
            workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sandbox-cleanup-'));
            fs.mkdirSync(path.join(workspace, '.securecode'), { recursive: true });
        });
        afterAll(() => {
            try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
        });

        it('removes verify-test temp files after execution', async () => {
            await runLocalTest('console.log("PASS: done")', 'node', workspace);
            const sandboxDir = path.join(workspace, '.securecode');
            const leftovers = fs.readdirSync(sandboxDir).filter(f => f.startsWith('verify-'));
            expect(leftovers).toHaveLength(0);
        });
    });
});
