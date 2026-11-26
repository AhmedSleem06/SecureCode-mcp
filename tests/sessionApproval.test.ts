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
    pruneSessionApprovals,
    revokeSessionApproval,
    SESSION_APPROVAL_MAX_TESTS,
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
    return `run-${Date.now()}-${counter}`;
}

describe('session approval', () => {
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

    it('one approval grants exactly maxTests sandbox runs, then refuses', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval(
            { runId, tool: 'assurance-tests', maxTests: 3, ttlMs: 60_000 },
            'Run up to 3 attack tests in the sandbox for src/x.ts',
        );
        const details = await decide(broker, port, true);
        expect(details.tool).toBe('securecode.assurance-tests');
        expect(details.summary).toContain('Run up to 3 attack tests in the sandbox for src/x.ts');
        expect(details.summary).toContain('up to 3 sandbox run(s) for this scan only');

        const result = await pending;
        expect(result.granted).toBe(true);
        expect(result.state).toBe('granted');
        expect(result.remaining).toBe(3);
        expect(result.expiresAt).toBeGreaterThan(Date.now());

        expect(consumeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(false);
        expect(consumeSessionApproval(runId)).toBe(false);

        const after = getSessionApproval(runId);
        expect(after.granted).toBe(false);
        expect(after.state).toBe('exhausted');
        expect(after.reason).toBe('Attack test skipped: approval for this scan covered 3 attack test(s) and all were used.');
    });

    it('does not prompt again for the same run', async () => {
        const runId = newRunId();
        const first = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 2, ttlMs: 60_000 }, 'first');
        const concurrent = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 2, ttlMs: 60_000 }, 'concurrent');
        await decide(broker, port, true);
        const [a, b] = await Promise.all([first, concurrent]);
        expect(a.granted).toBe(true);
        expect(b.granted).toBe(true);
        expect(a.requestId).toBe(b.requestId);

        const onUrl = vi.fn();
        const again = await broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 20, ttlMs: 60_000 }, 'again', { onUrl });
        expect(onUrl).not.toHaveBeenCalled();
        expect(again.maxTests).toBe(2);
        expect((broker as any).pending.size).toBe(0);
        expect(auditEntries.filter((e) => e.reason === 'approved')).toHaveLength(1);
    });

    it('a grant expires after ttlMs', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 5, ttlMs: 1_000 }, 'expiry');
        await decide(broker, port, true);
        const result = await pending;
        expect(result.granted).toBe(true);
        const expiresAt = result.expiresAt!;

        expect(consumeSessionApproval(runId, expiresAt - 1)).toBe(true);
        expect(consumeSessionApproval(runId, expiresAt + 1)).toBe(false);

        const state = getSessionApproval(runId, expiresAt + 1);
        expect(state.state).toBe('expired');
        expect(state.reason).toBe('Attack test skipped: approval for this scan expired after 1 s — re-run the scan to approve again.');
        expect(auditEntries.filter((e) => e.reason === 'session-expired')).toHaveLength(1);
    });

    it('expired records are cleaned up after the retention window', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 1, ttlMs: 1_000 }, 'cleanup');
        await decide(broker, port, true);
        const result = await pending;
        pruneSessionApprovals(result.expiresAt! + 60_000);
        expect(getSessionApproval(runId).state).toBe('granted');
        pruneSessionApprovals(result.expiresAt! + 11 * 60_000);
        expect(getSessionApproval(runId).state).toBe('none');
        expect(consumeSessionApproval(runId)).toBe(false);
    });

    it('grants are isolated per run id', async () => {
        const runA = newRunId();
        const runB = newRunId();
        const pending = broker.requestSessionApproval({ runId: runA, tool: 'assurance-tests', maxTests: 1, ttlMs: 60_000 }, 'run A');
        await decide(broker, port, true);
        expect((await pending).granted).toBe(true);

        expect(consumeSessionApproval(runB)).toBe(false);
        expect(getSessionApproval(runB).reason).toBe('Attack test skipped: approval was not given for this scan.');
        expect(consumeSessionApproval(runA)).toBe(true);
        expect(consumeSessionApproval(runA)).toBe(false);
    });

    it('a denied request grants nothing and is not re-prompted', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 4, ttlMs: 60_000 }, 'deny me');
        await decide(broker, port, false);
        const result = await pending;
        expect(result.granted).toBe(false);
        expect(result.state).toBe('denied');
        expect(result.reason).toBe('Attack test skipped: approval was denied.');
        expect(result.detail).toBe('User denied');
        expect(consumeSessionApproval(runId)).toBe(false);

        const again = await broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 4, ttlMs: 60_000 }, 'again');
        expect(again.state).toBe('denied');
        expect((broker as any).pending.size).toBe(0);

        const denied = auditEntries.filter((e) => e.reason === 'denied');
        expect(denied).toHaveLength(1);
        expect(denied[0].runId).toBe(runId);
        expect(denied[0].category).toBe('sandboxed-verification');
    });

    it('a prompt that times out records the not-given wording', async () => {
        const runId = newRunId();
        const result = await broker.requestSessionApproval(
            { runId, tool: 'assurance-tests', maxTests: 2, ttlMs: 60_000 },
            'nobody answers',
            { timeoutMs: 1_000 },
        );
        expect(result.granted).toBe(false);
        expect(result.state).toBe('timeout');
        expect(result.reason).toBe('Attack test skipped: approval was not given within 1 s — re-run with someone available to approve, or verify manually.');
        expect(result.detail).toContain('Request timed out');
        expect(consumeSessionApproval(runId)).toBe(false);
    }, 15_000);

    it('policy deny refuses without prompting', async () => {
        const policy = TOOL_POLICIES['securecode.assurance-tests'];
        policy.enabled = false;
        try {
            expect(resolveSessionApprovalPolicy('assurance-tests').action).toBe('deny');
            const runId = newRunId();
            const onUrl = vi.fn();
            const result = await broker.requestSessionApproval(
                { runId, tool: 'assurance-tests', maxTests: 5, ttlMs: 60_000 },
                'policy says no',
                { onUrl },
            );
            expect(onUrl).not.toHaveBeenCalled();
            expect((broker as any).pending.size).toBe(0);
            expect(result.granted).toBe(false);
            expect(result.state).toBe('policy-denied');
            expect(result.reason).toBe('Attack test skipped: approval was not given — sandbox runs are turned off by policy.');
            expect(consumeSessionApproval(runId)).toBe(false);
            expect(auditEntries).toHaveLength(1);
            expect(auditEntries[0]).toMatchObject({ reason: 'policy-denied', approved: false, runId, tool: 'securecode.assurance-tests' });
        } finally {
            delete policy.enabled;
        }
    });

    it('invalid scopes are refused without prompting', async () => {
        const onUrl = vi.fn();
        const noRun = await broker.requestSessionApproval({ runId: '', tool: 'assurance-tests', maxTests: 5, ttlMs: 60_000 }, 'x', { onUrl });
        expect(noRun.state).toBe('invalid-scope');
        const runId = newRunId();
        const noTests = await broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 0, ttlMs: 60_000 }, 'x', { onUrl });
        expect(noTests.state).toBe('invalid-scope');
        const badTool = await broker.requestSessionApproval({ runId, tool: 'other' as any, maxTests: 5, ttlMs: 60_000 }, 'x', { onUrl });
        expect(badTool.state).toBe('invalid-scope');
        expect(onUrl).not.toHaveBeenCalled();
        expect(consumeSessionApproval(runId)).toBe(false);
    });

    it('maxTests is clamped to the cap', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 10_000, ttlMs: 60_000 }, 'big');
        await decide(broker, port, true);
        const result = await pending;
        expect(result.maxTests).toBe(SESSION_APPROVAL_MAX_TESTS);
        revokeSessionApproval(runId);
    });

    it('revoke ends a grant immediately', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 5, ttlMs: 60_000 }, 'revoke');
        await decide(broker, port, true);
        await pending;
        expect(consumeSessionApproval(runId)).toBe(true);
        expect(revokeSessionApproval(runId)).toBe(true);
        expect(consumeSessionApproval(runId)).toBe(false);
        expect(revokeSessionApproval(runId)).toBe(false);
        expect(auditEntries.filter((e) => e.reason === 'session-revoked')).toHaveLength(1);
    });

    it('revoking while the prompt is open discards a later approval', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 5, ttlMs: 60_000 }, 'revoke early');
        await waitForPending(broker);
        expect(revokeSessionApproval(runId)).toBe(true);
        await decide(broker, port, true);
        const result = await pending;
        expect(result.granted).toBe(false);
        expect(consumeSessionApproval(runId)).toBe(false);
    });

    it('writes audit entries for grant, each run and exhaustion', async () => {
        const runId = newRunId();
        const pending = broker.requestSessionApproval({ runId, tool: 'assurance-tests', maxTests: 2, ttlMs: 60_000 }, 'audit', { workspaceRoot: 'D:/ws' });
        await decide(broker, port, true);
        const result = await pending;
        consumeSessionApproval(runId);
        consumeSessionApproval(runId);
        consumeSessionApproval(runId);
        consumeSessionApproval(runId);

        const mine = auditEntries.filter((e) => e.runId === runId);
        expect(mine.map((e) => e.reason)).toEqual(['approved', 'session-consumed', 'session-consumed', 'session-exhausted']);
        expect(mine.map((e) => e.remaining)).toEqual([undefined, 1, 0, 0]);
        for (const e of mine) {
            expect(e.requestId).toBe(result.requestId);
            expect(e.tool).toBe('securecode.assurance-tests');
            expect(e.category).toBe('sandboxed-verification');
            expect(e.workspaceId).toMatch(/^[a-f0-9]{16}$/);
        }
        expect(new Set(mine.map((e) => e.operationHash)).size).toBe(1);
    });

    it('a broker that is not started refuses without prompting', async () => {
        const idle = new ApprovalBroker();
        const result = await idle.requestSessionApproval({ runId: newRunId(), tool: 'assurance-tests', maxTests: 2, ttlMs: 60_000 }, 'idle');
        expect(result.granted).toBe(false);
        expect(result.state).toBe('unavailable');
        expect(result.reason).toBe('Attack test skipped: approval was not given — approval broker unavailable.');
    });
});
