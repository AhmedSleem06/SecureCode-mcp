import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'http';
import { ApprovalBroker } from '../src/approval/broker';
import { hashOperation, createApprovalRequest, isExpired } from '../src/approval/types';
import { appendAudit, readAudit } from '../src/approval/auditLog';

process.env.SECURECODE_TEST_MODE = '1';

function httpPost(url: string, body: unknown): Promise<{ status: number; data: any }> {
    return new Promise((resolve, reject) => {
        const payload = JSON.stringify(body);
        const parsed = new URL(url);
        const req = http.request(
            {
                hostname: parsed.hostname,
                port: parsed.port,
                path: parsed.pathname,
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
            },
            (res) => {
                let raw = '';
                res.on('data', (c) => { raw += c; });
                res.on('end', () => {
                    try { resolve({ status: res.statusCode!, data: JSON.parse(raw) }); }
                    catch { resolve({ status: res.statusCode!, data: raw }); }
                });
            },
        );
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

function httpGetJson(url: string): Promise<{ status: number; data: any }> {
    return new Promise((resolve, reject) => {
        http.get(url, (res) => {
            let raw = '';
            res.on('data', (c) => { raw += c; });
            res.on('end', () => {
                try { resolve({ status: res.statusCode!, data: JSON.parse(raw) }); }
                catch { resolve({ status: res.statusCode!, data: raw }); }
            });
        }).on('error', reject);
    });
}

async function getDecisionToken(broker: ApprovalBroker, port: number): Promise<{ reqId: string; token: string }> {
    await new Promise((r) => setTimeout(r, 200));
    const pending = (broker as any).pending as Map<string, any>;
    const reqId = [...pending.keys()][0];
    expect(reqId).toBeDefined();
    const res = await httpGetJson(`http://127.0.0.1:${port}/details?id=${reqId}`);
    expect(res.data.ok).toBe(true);
    return { reqId, token: res.data.decisionToken };
}

describe('Approval types', () => {
    it('hashOperation produces a stable 16-char hex', () => {
        const h1 = hashOperation('securecode.fix', 'code', 'sql_injection', 1, 2);
        const h2 = hashOperation('securecode.fix', 'code', 'sql_injection', 1, 2);
        const h3 = hashOperation('securecode.fix', 'code', 'sql_injection', 1, 3);
        expect(h1).toBe(h2);
        expect(h1).not.toBe(h3);
        expect(h1).toMatch(/^[a-f0-9]{16}$/);
    });

    it('createApprovalRequest sets id, hash, token, and expiry', () => {
        const req = createApprovalRequest('securecode.fix', 'test summary', ['code'], 5000);
        expect(req.id).toMatch(/^[0-9a-f-]{36}$/);
        expect(req.tool).toBe('securecode.fix');
        expect(req.summary).toBe('test summary');
        expect(req.operationHash).toMatch(/^[a-f0-9]{16}$/);
        expect(req.expiresAt).toBeGreaterThan(req.createdAt);
        expect(req.decisionToken).toMatch(/^[a-f0-9]{32}$/);
        expect(req.category).toBe('paid-generation');
    });

    it('isExpired returns true after expiry', () => {
        const req = createApprovalRequest('test', 's', [], 100);
        expect(isExpired(req, req.createdAt + 200)).toBe(true);
        expect(isExpired(req, req.createdAt + 50)).toBe(false);
    });
});

describe('ApprovalBroker', () => {
    let broker: ApprovalBroker;
    let port: number;

    beforeAll(async () => {
        broker = new ApprovalBroker();
        port = await broker.start();
        expect(port).toBeGreaterThan(0);
    });

    afterAll(async () => {
        await broker.stop();
    });

    it('serves the approval page on GET /', async () => {
        const res = await new Promise<{ status: number; data: string }>((resolve) => {
            http.get(`http://127.0.0.1:${port}/`, (res) => {
                let raw = '';
                res.on('data', (c) => { raw += c; });
                res.on('end', () => resolve({ status: res.statusCode!, data: raw }));
            });
        });
        expect(res.status).toBe(200);
        expect(res.data).toContain('SecureCode MCP');
        expect(res.data).toContain('Approve');
        expect(res.data).toContain('Deny');
    });

    it('serves approval details from server-side state via /details', async () => {
        const approvalPromise = broker.requestApproval(
            'securecode.fix',
            'Fix xss at line 3',
            ['code-details', 'xss', 3, 4],
            10_000,
        );
        await new Promise((r) => setTimeout(r, 200));
        const pending = (broker as any).pending as Map<string, any>;
        const reqId = [...pending.keys()][0];
        const res = await httpGetJson(`http://127.0.0.1:${port}/details?id=${reqId}`);
        expect(res.data.ok).toBe(true);
        expect(res.data.tool).toBe('securecode.fix');
        expect(res.data.summary).toContain('xss');
        expect(res.data.decisionToken).toMatch(/^[a-f0-9]{32}$/);
        // Deny to clean up
        await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: res.data.decisionToken, approved: false });
        await approvalPromise;
    });

    it('approves a request when the user clicks approve', async () => {
        const approvalPromise = broker.requestApproval(
            'securecode.fix',
            'Fix sql_injection at line 1',
            ['code-test', 'sql_injection', 1, 2],
            10_000,
        );
        const { reqId, token } = await getDecisionToken(broker, port);
        const res = await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: token, approved: true });
        expect(res.status).toBe(200);
        expect(res.data.ok).toBe(true);
        const result = await approvalPromise;
        expect(result.approved).toBe(true);
        expect(result.reason).toBe('User approved');
        expect(result.requestId).toBe(reqId);
    });

    it('denies a request when the user clicks deny', async () => {
        const approvalPromise = broker.requestApproval(
            'securecode.fix',
            'Fix xss at line 5',
            ['code-xss', 'xss', 5, 6],
            10_000,
        );
        const { reqId, token } = await getDecisionToken(broker, port);
        await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: token, approved: false });
        const result = await approvalPromise;
        expect(result.approved).toBe(false);
        expect(result.reason).toBe('User denied');
    });

    it('returns error for unknown request ID', async () => {
        const res = await httpPost(`http://127.0.0.1:${port}/decide`, { id: 'nonexistent', decisionToken: 'x', approved: true });
        expect(res.data.ok).toBe(false);
        expect(res.data.error).toContain('not found');
    });

    it('rejects decision without valid token', async () => {
        const approvalPromise = broker.requestApproval(
            'securecode.fix',
            'Fix ssti at line 7',
            ['code', 'ssti', 7, 8],
            10_000,
        );
        const { reqId } = await getDecisionToken(broker, port);
        const res = await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: 'wrong-token', approved: true });
        expect(res.data.ok).toBe(false);
        expect(res.data.error).toContain('Invalid decision token');
        const result = await approvalPromise;
        expect(result.approved).toBe(false);
        expect(result.reason).toContain('Invalid decision token');
    });

    it('returns 404 for unknown paths', async () => {
        const res = await new Promise<{ status: number }>((resolve) => {
            http.get(`http://127.0.0.1:${port}/unknown`, (res) => {
                res.resume();
                resolve({ status: res.statusCode! });
            });
        });
        expect(res.status).toBe(404);
    });

    it('rejects POST without application/json content-type', async () => {
        const approvalPromise = broker.requestApproval(
            'securecode.fix',
            'Fix cmd at line 1',
            ['code', 'cmd', 1, 2],
            10_000,
        );
        await new Promise((r) => setTimeout(r, 200));
        const pending = (broker as any).pending as Map<string, any>;
        const reqId = [...pending.keys()][0];
        const payload = JSON.stringify({ id: reqId, decisionToken: 'x', approved: true });
        const res = await new Promise<{ status: number; data: any }>((resolve) => {
            const r = http.request(
                {
                    hostname: '127.0.0.1',
                    port,
                    path: '/decide',
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(payload) },
                },
                (res) => {
                    let raw = '';
                    res.on('data', (c) => { raw += c; });
                    res.on('end', () => { try { resolve({ status: res.statusCode!, data: JSON.parse(raw) }); } catch { resolve({ status: res.statusCode!, data: raw }); } });
                },
            );
            r.write(payload);
            r.end();
        });
        expect(res.status).toBe(400);
        expect(res.data.error).toContain('Content-Type');
        // Clean up
        const details = await httpGetJson(`http://127.0.0.1:${port}/details?id=${reqId}`);
        await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: details.data.decisionToken, approved: false });
        await approvalPromise;
    });
});

describe('ApprovalBroker lifecycle', () => {
    it('expired decision resolves the original promise as denied', async () => {
        const broker = new ApprovalBroker();
        await broker.start();
        try {
            const approvalPromise = broker.requestApproval(
                'securecode.fix',
                'Quick expire test',
                ['code', 'sqli', 1, 2],
                300,
            );
            const result = await approvalPromise;
            expect(result.approved).toBe(false);
            expect(result.reason).toBe('Request timed out');
        } finally {
            await broker.stop();
        }
    }, 15000);

    it('expired decision writes a timeout audit entry', async () => {
        const broker = new ApprovalBroker();
        await broker.start();
        try {
            const approvalPromise = broker.requestApproval(
                'securecode.fix',
                'Audit expire test',
                ['code', 'sqli', 1, 2],
                300,
            );
            await approvalPromise;
            await new Promise((r) => setTimeout(r, 100));
            const audit = readAudit(10);
            const last = audit[audit.length - 1];
            expect(last.reason).toBe('timeout');
            expect(last.approved).toBe(false);
        } finally {
            await broker.stop();
        }
    }, 15000);

    it('two concurrent decisions produce exactly one result', async () => {
        const broker = new ApprovalBroker();
        const port = await broker.start();
        try {
            const approvalPromise = broker.requestApproval(
                'securecode.fix',
                'Concurrent test',
                ['code', 'sqli', 1, 2],
                10_000,
            );
            const { reqId, token } = await getDecisionToken(broker, port);
            const [r1, r2] = await Promise.all([
                httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: token, approved: true }),
                httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, decisionToken: token, approved: false }),
            ]);
            expect(r1.data.ok).toBe(true);
            expect(r2.data.ok).toBe(false);
            expect(r2.data.error).toContain('already answered');
            const result = await approvalPromise;
            expect(result.approved).toBe(true);
        } finally {
            await broker.stop();
        }
    });

    it('broker shutdown resolves all pending as cancelled', async () => {
        const broker = new ApprovalBroker();
        const port = await broker.start();
        const p1 = broker.requestApproval('securecode.fix', 'P1', ['c1'], 30_000);
        const p2 = broker.requestApproval('securecode.fix', 'P2', ['c2'], 30_000);
        await new Promise((r) => setTimeout(r, 200));
        await broker.stop();
        const [r1, r2] = await Promise.all([p1, p2]);
        expect(r1.approved).toBe(false);
        expect(r1.reason).toContain('shutting down');
        expect(r2.approved).toBe(false);
        expect(r2.reason).toContain('shutting down');
    });

    it('too many pending requests returns immediate denial', async () => {
        const broker = new ApprovalBroker();
        const port = await broker.start();
        try {
            for (let i = 0; i < 16; i++) {
                broker.requestApproval('securecode.fix', `P${i}`, [`c${i}`], 30_000);
            }
            await new Promise((r) => setTimeout(r, 100));
            const result = await broker.requestApproval('securecode.fix', 'Overflow', ['overflow'], 30_000);
            expect(result.approved).toBe(false);
            expect(result.reason).toContain('Too many pending');
        } finally {
            await broker.stop();
        }
    });
});

describe('Audit log', () => {
    it('appendAudit and readAudit round-trip', () => {
        const before = readAudit().length;
        appendAudit({
            timestamp: new Date().toISOString(),
            requestId: 'test-' + Date.now(),
            tool: 'securecode.fix',
            operationHash: 'abcdef0123456789',
            category: 'paid-generation',
            workspaceId: null,
            approved: true,
            reason: 'approved',
            durationMs: 1234,
        });
        const after = readAudit();
        if (before < 200) {
            expect(after.length).toBeGreaterThan(before);
        }
        const last = after[after.length - 1];
        expect(last.tool).toBe('securecode.fix');
        expect(last.approved).toBe(true);
    });
});
