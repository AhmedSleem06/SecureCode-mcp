import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { validateRunTestsRequest, formatRefusalMessage, runTests } from '../src/utils/testRunner';
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
                try { resolve(JSON.parse(raw).decisionToken); }
                catch (e) { reject(e); }
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

describe('run_tests refusal messages', () => {
    beforeEach(async () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'refusal-test-'));
        fs.writeFileSync(path.join(workspaceRoot, 'package.json'), '{"name":"test"}');
        unsafeBackend = new __UnsafeHostSandboxForTests();
        _setSandboxForTests(unsafeBackend);
        broker = new ApprovalBroker();
        port = await broker.start();
    });

    afterEach(async () => {
        _setSandboxForTests(null);
        try {
            await Promise.race([broker.stop(), new Promise<void>((r) => setTimeout(r, 3000))]);
        } catch {}
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    }, 10000);

    describe('formatRefusalMessage', () => {
        it('returns hint for fetch', () => {
            const msg = formatRefusalMessage('fetch() can exfiltrate data over the network');
            expect(msg).toContain('refused:');
            expect(msg).toContain('sc.invoke from ./expressRunner.cjs');
        });

        it('returns hint for http module', () => {
            const msg = formatRefusalMessage('module "http" is blocked');
            expect(msg).toContain('sc.invoke from ./expressRunner.cjs');
        });

        it('returns hint for process.env', () => {
            const msg = formatRefusalMessage('process.env access can leak host secrets');
            expect(msg).toContain('pass values explicitly');
        });

        it('returns hint for process.cwd', () => {
            const msg = formatRefusalMessage('process.cwd() exposes the host filesystem layout');
            expect(msg).toContain('__dirname');
        });
    });

    describe('validateRunTestsRequest safety refusal', () => {
        it('returns refusalRule on safety violation', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'const http = require("http"); http.createServer()',
                runner: 'node',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.refusalRule).toBe('network');
            }
        });

        it('returns refusalRule for fetch', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'fetch("http://example.com")',
                runner: 'node',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.refusalRule).toBe('network');
            }
        });

        it('returns refusalRule for process.cwd', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                script: 'const d = process.cwd()',
                runner: 'node',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.refusalRule).toBe('process.cwd');
            }
        });

        it('does not set refusalRule for non-safety validation errors', () => {
            const result = validateRunTestsRequest({
                mode: 'generated',
                runner: 'bash',
                script: 'echo hello',
            } as any, workspaceRoot);
            expect(result.ok).toBe(false);
            if (!result.ok) {
                expect(result.refusalRule).toBeUndefined();
            }
        });
    });

    describe('runTests returns refused status', () => {
        it('returns refused status with hint for safety violation', async () => {
            const result = await runTests(
                { mode: 'generated', script: 'fetch("http://evil.com")', runner: 'node' },
                workspaceRoot,
                { broker },
            );
            expect(result.approved).toBe(false);
            expect(result.status).toBe('refused');
            expect(result.refusalRule).toBe('network');
            expect(result.output).toContain('refused:');
            expect(result.output).toContain('sc.invoke from ./expressRunner.cjs');
        });
    });
});
