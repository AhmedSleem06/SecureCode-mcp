import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'http';
import { ApprovalBroker } from '../src/approval/broker';
import { hashOperation, createApprovalRequest, isExpired } from '../src/approval/types';
import { appendAudit, readAudit } from '../src/approval/auditLog';

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

describe('Approval types', () => {
    it('hashOperation produces a stable 16-char hex', () => {
        const h1 = hashOperation('securecode.fix', 'code', 'sql_injection', 1, 2);
        const h2 = hashOperation('securecode.fix', 'code', 'sql_injection', 1, 2);
        const h3 = hashOperation('securecode.fix', 'code', 'sql_injection', 1, 3);
        expect(h1).toBe(h2);
        expect(h1).not.toBe(h3);
        expect(h1).toMatch(/^[a-f0-9]{16}$/);
    });

    it('createApprovalRequest sets id, hash, and expiry', () => {
        const req = createApprovalRequest('securecode.fix', 'test summary', ['code'], 5000);
        expect(req.id).toMatch(/^[0-9a-f-]{36}$/);
        expect(req.tool).toBe('securecode.fix');
        expect(req.summary).toBe('test summary');
        expect(req.operationHash).toMatch(/^[a-f0-9]{16}$/);
        expect(req.expiresAt).toBeGreaterThan(req.createdAt);
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

    it('approves a request when the user clicks approve', async () => {
        const approvalPromise = broker.requestApproval(
            'securecode.fix',
            'Fix sql_injection at line 1',
            ['code-test', 'sql_injection', 1, 2],
            10_000,
        );

        // Wait for the broker to register the pending request
        await new Promise((r) => setTimeout(r, 200));

        // Find the pending request ID from the broker
        const pending = (broker as any).pending as Map<string, any>;
        const reqId = [...pending.keys()][0];
        expect(reqId).toBeDefined();

        const res = await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, approved: true });
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

        await new Promise((r) => setTimeout(r, 200));

        const pending = (broker as any).pending as Map<string, any>;
        const reqId = [...pending.keys()][0];

        await httpPost(`http://127.0.0.1:${port}/decide`, { id: reqId, approved: false });

        const result = await approvalPromise;
        expect(result.approved).toBe(false);
        expect(result.reason).toBe('User denied');
    });

    it('returns error for unknown request ID', async () => {
        const res = await httpPost(`http://127.0.0.1:${port}/decide`, { id: 'nonexistent', approved: true });
        expect(res.data.ok).toBe(false);
        expect(res.data.error).toContain('not found');
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
});

describe('Audit log', () => {
    it('appendAudit and readAudit round-trip', () => {
        const before = readAudit().length;
        appendAudit({
            timestamp: new Date().toISOString(),
            requestId: 'test-' + Date.now(),
            tool: 'securecode.fix',
            operationHash: 'abcdef0123456789',
            approved: true,
            reason: 'approved',
            durationMs: 1234,
        });
        const after = readAudit();
        expect(after.length).toBeGreaterThan(before);
        const last = after[after.length - 1];
        expect(last.tool).toBe('securecode.fix');
        expect(last.approved).toBe(true);
    });
});
