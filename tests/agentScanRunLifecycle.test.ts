import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('../src/attack/verifyLoop', () => ({
    runVerifyLoop: vi.fn(),
}));

vi.mock('../src/attack/agentScanLoop', () => ({
    runAgentScan: vi.fn(),
}));

vi.mock('../src/attack/fixVerifyLoop', () => ({
    runFixVerifyLoop: vi.fn(),
}));

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
    };
});

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'fix-approval', duration: 0 }),
    })),
}));

vi.mock('../src/project-map/mapContext', () => ({
    getEndpointContextForFile: vi.fn().mockResolvedValue([]),
    getRelatedFilesForFile: vi.fn().mockResolvedValue([]),
    getMap: vi.fn().mockResolvedValue(null),
}));

vi.mock('../src/project-map/fixTester', () => ({
    testFix: vi.fn().mockResolvedValue({
        passes: true,
        syntaxValid: true,
        fixEffective: true,
        newVulnerabilities: [],
        regressions: [],
        tests: [],
    }),
}));

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { runFixVerifyLoop } from '../src/attack/fixVerifyLoop';
import { ApiClient } from '../src/api/client';
import { toolAgentScan } from '../src/tools/agentScan';

const CODE = [
    'import express from "express";',
    'const app = express();',
    'app.post("/users", (req, res) => {',
    '  const q = "SELECT * FROM users WHERE id=" + req.body.id;',
    '  db.query(q);',
    '  res.send("ok");',
    '});',
].join('\n');

function finding(line: number) {
    return {
        type: 'sql_injection',
        line,
        lineEnd: line,
        evidence: 'const q = "SELECT * FROM users WHERE id=" + req.body.id;',
        why: 'user input concatenated into SQL',
        severity: 'high',
        confidence: 95,
    };
}

function agentResult(overrides: Record<string, unknown> = {}) {
    return {
        status: 'completed',
        terminationReason: 'agent_finish',
        findings: [finding(4)],
        transcript: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 5,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.05,
        summary: 'done',
        runId: 'run-77',
        creditsUsed: 5,
        baseCredits: 5,
        maxCredits: 15,
        creditExtensionsGranted: 0,
        ...overrides,
    } as any;
}

let workspaceRoot: string;
let order: string[];

function mockApi(handlers: Record<string, (body: any) => any> = {}) {
    const postJson = vi.fn(async (p: string, body: any) => {
        order.push(p);
        if (handlers[p]) return handlers[p](body);
        return {};
    });
    vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);
    return postJson;
}

function closeCalls(postJson: any) {
    return (postJson.mock.calls as any[]).filter(c => c[0] === '/agent/scan/close');
}

async function runScan(args: Record<string, unknown> = {}) {
    const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
    return toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript', _skipFix: true, _noCache: true, ...args }) as Promise<any>;
}

describe('toolAgentScan — API run lifecycle and scan budget', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-runlife-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), CODE);
        order = [];
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(runFixVerifyLoop).mockReset();
        vi.mocked(ApiClient).mockReset();
        vi.clearAllMocks();
        vi.mocked(runAgentScan).mockResolvedValue(agentResult());
        vi.mocked(runVerifyLoop).mockImplementation(async () => {
            order.push('verify');
            return { verdict: 'UNPROVEN', reason: 'guard held', roundsUsed: 1, testScript: '', testOutput: '' } as any;
        });
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    it('defers the close, sends runId to verify, and closes once after verification', async () => {
        const postJson = mockApi({
            '/agent/scan/close': () => ({ settlement: { creditsRefunded: 0, creditsUsed: 9, costSpentUsd: 0.9 } }),
        });

        const result = await runScan();

        expect(vi.mocked(runAgentScan).mock.calls[0][2]).toEqual(expect.objectContaining({ deferClose: true }));
        expect(vi.mocked(runVerifyLoop)).toHaveBeenCalledWith(expect.objectContaining({ runId: 'run-77' }));
        const closes = closeCalls(postJson);
        expect(closes).toHaveLength(1);
        expect(closes[0][1]).toEqual({ runId: 'run-77', status: 'completed', terminationReason: 'agent_finish' });
        expect(order.indexOf('/agent/scan/close')).toBeGreaterThan(order.indexOf('verify'));
        expect(result.creditsUsed).toBe(9);
        expect(result.creditExtensionsGranted).toBe(2);
        expect(result.creditsRefunded).toBe(0);
        expect(result.summary).toContain('This scan used 9 credits (5 + 2 extensions).');
    });

    it('closes after fix verification finishes and passes runId to fix verification', async () => {
        vi.mocked(runVerifyLoop).mockImplementation(async () => {
            order.push('verify');
            return { verdict: 'PROVEN', reason: 'exploit reproduced', roundsUsed: 1, testScript: '', testOutput: '', subVerdict: 'analyzed' } as any;
        });
        vi.mocked(runFixVerifyLoop).mockImplementation(async () => {
            order.push('fix-verify');
            return { status: 'closed', reason: 'fixed', originalVerdict: 'PROVEN', fixedVerdict: 'UNPROVEN', roundsUsed: 1, fixedCodeHash: 'h' } as any;
        });
        const postJson = mockApi({
            '/fix': () => ({ fixed_code: '  const q = "SELECT * FROM users WHERE id=?";', fix_summary: 'parameterize' }),
            '/agent/scan/close': () => ({ settlement: { creditsRefunded: 2, creditsUsed: 7 } }),
        });

        const result = await runScan({ _skipFix: false });

        expect(vi.mocked(runFixVerifyLoop)).toHaveBeenCalledWith(expect.objectContaining({ runId: 'run-77' }));
        expect(closeCalls(postJson)).toHaveLength(1);
        expect(order.indexOf('/agent/scan/close')).toBeGreaterThan(order.indexOf('fix-verify'));
        expect(result.creditsRefunded).toBe(2);
        expect(result.summary).toContain('2 credits were refunded.');
    });

    it('sends runId to the API sandbox fallback', async () => {
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'INCONCLUSIVE', reason: 'no sandbox', roundsUsed: 0, testScript: '', testOutput: '', subVerdict: 'sandbox-unavailable' } as any);
        const postJson = mockApi({
            '/sandbox/prove': () => ({ proven: 'UNPROVEN', rationale: 'safe' }),
        });

        await runScan();

        const prove = (postJson.mock.calls as any[]).find(c => c[0] === '/sandbox/prove');
        expect(prove[1].runId).toBe('run-77');
        expect(closeCalls(postJson)).toHaveLength(1);
    });

    it('closes exactly once when the investigation failed', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ status: 'failed', terminationReason: 'api_error', error: 'boom', findings: [] }));
        const postJson = mockApi();

        await expect(runScan()).rejects.toThrow('boom');

        const closes = closeCalls(postJson);
        expect(closes).toHaveLength(1);
        expect(closes[0][1]).toEqual({ runId: 'run-77', status: 'failed', terminationReason: 'api_error' });
    });

    it('closes exactly once when verification throws out of the tool', async () => {
        const postJson = mockApi();
        const progress = vi.fn((_c: number, _t: number, msg: string) => {
            if (msg.startsWith('Verifying sql_injection')) throw new Error('progress sink exploded');
        });

        await expect(runScan({ _progress: progress })).rejects.toThrow('progress sink exploded');

        expect(closeCalls(postJson)).toHaveLength(1);
    });

    it('closes exactly once when the user cancels during verification', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ findings: [finding(4), finding(5)] }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'INCONCLUSIVE', reason: 'Verification cancelled by user at round 1.', roundsUsed: 1, testScript: '', testOutput: '', subVerdict: 'cancelled' } as any);
        const postJson = mockApi();

        const result = await runScan();

        expect(result.agentFindings[1].proven).toBe('SKIPPED');
        expect(closeCalls(postJson)).toHaveLength(1);
    });

    it('stops verifying when the scan budget is exhausted and leaves the rest INCONCLUSIVE', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ findings: [finding(4), finding(5), finding(6)] }));
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE',
            reason: 'Verification budget exhausted (top up credits to verify the remaining findings).',
            roundsUsed: 0,
            testScript: '',
            testOutput: '',
            budgetExhaustedReason: 'scan-budget',
            subVerdict: 'budget-exhausted',
        } as any);
        const postJson = mockApi();

        const result = await runScan();

        expect(vi.mocked(runVerifyLoop)).toHaveBeenCalledTimes(1);
        expect(result.status).toBe('completed');
        expect(result.agentFindings).toHaveLength(3);
        for (const f of result.agentFindings) {
            expect(f.proven).toBe('INCONCLUSIVE');
            expect(f.provenReason).toContain('top up credits');
        }
        expect(result.verifyHint).toContain('Top up credits');
        expect(closeCalls(postJson)).toHaveLength(1);
    });

    it('treats a 402 budget error from the API sandbox as exhausted, not a crash', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ findings: [finding(4), finding(5)] }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'INCONCLUSIVE', reason: 'no sandbox', roundsUsed: 0, testScript: '', testOutput: '', subVerdict: 'sandbox-unavailable' } as any);
        mockApi({
            '/sandbox/prove': () => {
                const err: any = new Error('Scan budget exhausted');
                err.status = 402;
                err.apiCode = 'AGENT_SCAN_BUDGET_EXHAUSTED';
                throw err;
            },
        });

        const result = await runScan();

        expect(vi.mocked(runVerifyLoop)).toHaveBeenCalledTimes(1);
        expect(result.agentFindings.map((f: any) => f.proven)).toEqual(['INCONCLUSIVE', 'INCONCLUSIVE']);
        expect(result.agentFindings[1].provenReason).toContain('top up credits');
    });

    it('old API result (no runId, no credits) keeps working without a close call', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ runId: undefined, creditsUsed: undefined, baseCredits: undefined, maxCredits: undefined, creditExtensionsGranted: undefined }));
        const postJson = mockApi();

        const result = await runScan();

        expect(closeCalls(postJson)).toHaveLength(0);
        expect(vi.mocked(runVerifyLoop).mock.calls[0][0]).not.toHaveProperty('runId');
        expect(result.summary).toBe('done');
        expect(result).not.toHaveProperty('creditsUsed');
    });
});
