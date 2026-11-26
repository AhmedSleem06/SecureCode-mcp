import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import * as http from 'http';
import type { AuditEntry } from '../src/approval/types';

const auditEntries: AuditEntry[] = [];
vi.mock('../src/approval/auditLog', () => ({
    appendAudit: (entry: AuditEntry) => { auditEntries.push(entry); return true; },
    readAudit: () => [...auditEntries],
}));

import {
    ApprovalBroker,
    consumeSessionApproval,
    getSessionApproval,
    revokeSessionApproval,
} from '../src/approval/broker';
import { TOOL_POLICIES, resolveSessionApprovalPolicy } from '../src/approval/policy';

process.env.SECURECODE_TEST_MODE = '1';

function request(method: 'GET' | 'POST', url: string, body?: unknown): Promise<any> {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const payload = body === undefined ? '' : JSON.stringify(body);
        const req = http.request(
            {
                hostname: parsed.hostname,
                port: parsed.port,
                path: parsed.pathname + parsed.search,
                method,
                headers: method === 'POST'
                    ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
                    : {},
            },
            (res) => {
                let raw = '';
                res.on('data', (c) => { raw += c; });
                res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { resolve(raw); } });
            },
        );
        req.on('error', reject);
        if (payload) req.write(payload);
        req.end();
    });
}

async function waitForPending(broker: ApprovalBroker): Promise<string> {
    const pending = (broker as any).pending as Map<string, any>;
    for (let i = 0; i < 50 && pending.size === 0; i++) {
        await new Promise((r) => setTimeout(r, 10));
    }
    const id = [...pending.keys()][0];
    expect(id).toBeDefined();
    return id;
}

async function decide(broker: ApprovalBroker, port: number, approved: boolean): Promise<any> {
    const id = await waitForPending(broker);
    const details = await request('GET', `http://127.0.0.1:${port}/details?id=${id}`);
    expect(details.ok).toBe(true);
    await request('POST', `http://127.0.0.1:${port}/decide`, { id, decisionToken: details.decisionToken, approved });
    return details;
}

let counter = 0;
function newRunId(): string {
    counter++;
    return `run-fixgen-${Date.now()}-${counter}`;
}

describe('session approval — fix-generation tool', () => {
    let broker: ApprovalBroker;
    let port: number;

    beforeAll(async () => {
        broker = new ApprovalBroker();
        port = await broker.start();
    });

    afterAll(async () => {
        await broker.stop();
    });

    beforeEach(() => {
        auditEntries.length = 0;
    });

    it('fix-generation is a known session tool with paid-generation category', () => {
        const policy = TOOL_POLICIES['securecode.fix-generation'];
        expect(policy).toBeDefined();
        expect(policy.category).toBe('paid-generation');
        expect(policy.requiresApproval).toBe(true);
    });

    it('resolveSessionApprovalPolicy accepts fix-generation', () => {
        const result = resolveSessionApprovalPolicy('fix-generation');
        expect(result.action).toBe('prompt');
        if (result.action === 'prompt') {
            expect(result.policy.category).toBe('paid-generation');
        }
    });

    it('one approval grants runs and then exhausts for fix-generation', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval(
            { runId, tool: 'fix-generation', maxTests: 3, ttlMs: 60_000 },
            'Generate fixes for 3 findings',
        );
        const details = await decide(broker, port, true);
        expect(details.tool).toBe('securecode.fix-generation');

        const result = await pending;
        expect(result.granted).toBe(true);
        expect(result.state).toBe('granted');
        expect(result.remaining).toBe(3);

        expect(consumeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(false);
    });

    it('denied fix-generation grants nothing', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval(
            { runId, tool: 'fix-generation', maxTests: 5, ttlMs: 60_000 },
            'deny me',
        );
        await decide(broker, port, false);
        const result = await pending;
        expect(result.granted).toBe(false);
        expect(result.state).toBe('denied');
        expect(consumeSessionApproval(runId)).toBe(false);
    });

    it('audit entries use paid-generation category for fix-generation', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval(
            { runId, tool: 'fix-generation', maxTests: 2, ttlMs: 60_000 },
            'audit test',
            { workspaceRoot: 'D:/ws' },
        );
        await decide(broker, port, true);
        await pending;
        consumeSessionApproval(runId);
        consumeSessionApproval(runId);
        consumeSessionApproval(runId);

        const mine = auditEntries.filter((e) => e.runId === runId);
        expect(mine.map((e) => e.reason)).toEqual(['approved', 'session-consumed', 'session-consumed', 'session-exhausted']);
        for (const e of mine) {
            expect(e.category).toBe('paid-generation');
            expect(e.tool).toBe('securecode.fix-generation');
        }
    });

    it('revoke ends fix-generation grant', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval(
            { runId, tool: 'fix-generation', maxTests: 5, ttlMs: 60_000 },
            'revoke test',
        );
        await decide(broker, port, true);
        await pending;
        expect(consumeSessionApproval(runId)).toBe(true);
        expect(revokeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(false);
    });

    it('assurance-tests still works with sandboxed-verification category', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval(
            { runId, tool: 'assurance-tests', maxTests: 2, ttlMs: 60_000 },
            'assurance test',
            { workspaceRoot: 'D:/ws' },
        );
        await decide(broker, port, true);
        await pending;
        consumeSessionApproval(runId);

        const mine = auditEntries.filter((e) => e.runId === runId);
        for (const e of mine) {
            expect(e.category).toBe('sandboxed-verification');
        }
    });

    it('policy disable blocks fix-generation without prompting', async () => {
        const policy = TOOL_POLICIES['securecode.fix-generation'];
        policy.enabled = false;
        try {
            expect(resolveSessionApprovalPolicy('fix-generation').action).toBe('deny');
            const runId = newRunId();
            const onUrl = vi.fn();
            const result = await broker.requestSessionApproval(
                { runId, tool: 'fix-generation', maxTests: 5, ttlMs: 60_000 },
                'policy deny test',
                { onUrl },
            );
            expect(onUrl).not.toHaveBeenCalled();
            expect(result.granted).toBe(false);
            expect(result.state).toBe('policy-denied');
        } finally {
            delete policy.enabled;
        }
    });
});
