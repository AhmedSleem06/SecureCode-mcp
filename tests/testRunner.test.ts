import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { validateRunTestsRequest, runTests } from '../src/utils/testRunner';
import { __UnsafeHostSandboxForTests, _setSandboxForTests } from '../src/utils/verificationSandbox';
import { ApprovalBroker } from '../src/approval/broker';
import * as http from 'http';

process.env.SECURECODE_TEST_MODE = '1';

let workspaceRoot: string;
let unsafeBackend: __UnsafeHostSandboxForTests;
let broker: ApprovalBroker;
let port: number;

function httpPost(url: string, body: any): Promise<{ status: number; data: any }> {
    return new Promise((resolve) => {
        const data = JSON.stringify(body);
        const req = http.request(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
                'Connection': 'close',
            },
        }, (res) => {
            let raw = '';
            res.on('data', (c) => { raw += c; });
            res.on('end', () => {
                try { resolve({ status: res.statusCode!, data: JSON.parse(raw) }); }
                catch { resolve({ status: res.statusCode!, data: raw }); }
            });
        });
        req.write(data);
        req.end();
    });
}

async function getDecisionToken(b: ApprovalBroker, p: number): Promise<string> {
    await new Promise((r) => setTimeout(r, 200));
    const pending = (b as any).pending as Map<string, any>;
    const reqId = [...pending.keys()][0];
    if (!reqId) throw new Error('No pending approval request');
    return new Promise<string>((resolve, reject) => {
        http.get(`http://127.0.0.1:${p}/details?id=${reqId}`, (res) => {
            let raw = '';
            res.on('data', (c) => { raw += c; });
            res.on('end', () => {
                try {
                    const data = JSON.parse(raw);
                    resolve(data.decisionToken);
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', reject);
    });
}

async function approvePending(b: ApprovalBroker, p: number): Promise<void> {
    const token = await getDecisionToken(b, p);
    const pending = (b as any).pending as Map<string, any>;
    const reqId = [...pending.keys()][0];
    await httpPost(`http://127.0.0.1:${p}/decide`, { id: reqId, decisionToken: token, approved: true });
}

async function denyPending(b: ApprovalBroker, p: number): Promise<void> {
    const token = await getDecisionToken(b, p);
    const pending = (b as any).pending as Map<string, any>;
    const reqId = [...pending.keys()][0];
    await httpPost(`http://127.0.0.1:${p}/decide`, { id: reqId, decisionToken: token, approved: false });
}

describe('runTests', () => {
    beforeEach(async () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-runner-int-'));
        fs.mkdirSync(path.join(workspaceRoot, 'tests'), { recursive: true });
        fs.writeFileSync(path.join(workspaceRoot, 'package.json'), '{"name":"test","scripts":{"test":"echo PASS"}}');
        fs.writeFileSync(path.join(workspaceRoot, 'tests/auth.test.ts'), 'console.log("PASS: ok")');

        unsafeBackend = new __UnsafeHostSandboxForTests();
        _setSandboxForTests(unsafeBackend);

        broker = new ApprovalBroker();
        port = await broker.start();
    });

    afterEach(async () => {
        _setSandboxForTests(null);
        try {
            await Promise.race([
                broker.stop(),
                new Promise<void>((r) => setTimeout(r, 3000)),
            ]);
        } catch { /* best effort */ }
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    }, 10000);

    describe('validateRunTestsRequest', () => {
        it('rejects invalid mode', () => {
            const result = validateRunTestsRequest({ mode: 'invalid' as any }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('mode');
        });

        it('validates existing mode with command policy', () => {
            const result = validateRunTestsRequest({
                mode: 'existing',
                packageManager: 'npm',
                testFiles: ['tests/auth.test.ts'],
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command).toBeDefined();
        });

        it('rejects existing mode with bad command', () => {
            const result = validateRunTestsRequest({
                mode: 'existing',
                testFiles: ['../../../etc/passwd'],
            }, workspaceRoot);
            expect(result.ok).toBe(false);
        });

        it('validates generated mode with script and runner', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'console.log("PASS: ok")',
                runner: 'node',
            }, workspaceRoot);
            expect(result.ok).toBe(true);
        });

        it('rejects generated mode without script', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                runner: 'node',
            } as any, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('script');
        });

        it('rejects generated mode with unknown runner', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'console.log("hi")',
                runner: 'bash',
            } as any, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('runner');
        });

        it('rejects generated mode with unsafe script (eval)', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'eval("console.log(1)")',
                runner: 'node',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('safety');
        });

        it('rejects oversized script', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'x'.repeat(65 * 1024),
                runner: 'node',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('too large');
        });
    });

    describe('approval flow', () => {
        it('denies execution when user denies', async () => {
            const promise = runTests(
                { mode: 'generated', script: 'console.log("PASS: ok")', runner: 'node' },
                workspaceRoot,
                { broker },
            );
            await denyPending(broker, port);
            const result = await promise;
            expect(result.approved).toBe(false);
            expect(result.status).toBe('denied');
            expect(result.exitCode).toBe(-1);
        });

        it('executes generated test when approved', async () => {
            const promise = runTests(
                { mode: 'generated', script: 'console.log("PASS: ok")', runner: 'node' },
                workspaceRoot,
                { broker },
            );
            await approvePending(broker, port);
            const result = await promise;
            expect(result.approved).toBe(true);
            expect(result.status).toBe('passed');
            expect(result.exitCode).toBe(0);
            expect(result.output).toContain('PASS');
        });

        it('reports failed test when script prints FAIL:', async () => {
            const promise = runTests(
                { mode: 'generated', script: 'console.log("FAIL: guard blocked")', runner: 'node' },
                workspaceRoot,
                { broker },
            );
            await approvePending(broker, port);
            const result = await promise;
            expect(result.approved).toBe(true);
            expect(result.status).toBe('failed');
        });
    });

    describe('sandbox unavailable', () => {
        it('returns sandbox-unavailable when no backend', async () => {
            _setSandboxForTests(null);
            const promise = runTests(
                { mode: 'generated', script: 'console.log("PASS: ok")', runner: 'node' },
                workspaceRoot,
                { broker },
            );
            await approvePending(broker, port);
            const result = await promise;
            expect(result.approved).toBe(true);
            expect(result.status).toBe('sandbox-unavailable');
        });
    });

    describe('validation errors', () => {
        it('returns denied status for validation errors', async () => {
            const result = await runTests(
                { mode: 'invalid' as any } as any,
                workspaceRoot,
                { broker },
            );
            expect(result.approved).toBe(false);
            expect(result.status).toBe('denied');
            expect(result.output).toContain('Validation error');
        });
    });
});
