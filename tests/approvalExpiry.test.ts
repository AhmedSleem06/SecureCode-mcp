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

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
    };
});

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn(),
}));

vi.mock('../src/project-map/mapContext', () => ({
    getEndpointContextForFile: vi.fn().mockResolvedValue([]),
    getRelatedFilesForFile: vi.fn().mockResolvedValue([]),
    getMap: vi.fn().mockResolvedValue(null),
}));

vi.mock('../src/attack/runtimeProbe', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../src/attack/runtimeProbe')>();
    return {
        ...actual,
        detectDevServer: vi.fn(),
        executeProbePlan: vi.fn(),
        matchEndpointForFinding: vi.fn(),
    };
});

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { ApprovalBroker } from '../src/approval/broker';
import { detectDevServer, executeProbePlan, matchEndpointForFinding } from '../src/attack/runtimeProbe';
import { toolAgentScan } from '../src/tools/agentScan';

const NOT_GIVEN = 'Proof skipped: approval was not given within 120 s — re-run with someone available to approve, or verify manually.';
const DENIED = 'Proof skipped: approval was denied.';
const VERIFY_REASON = 'Test timed out after 12 rounds.';
const ENDPOINT = { method: 'POST', path: '/users', mountedPath: '/api/users', line: 10, params: [], authScheme: 'none', middleware: [] };
const PROBE_PLAN = { host: '127.0.0.1', port: 3000, requests: [] };

function makeFinding(overrides: Record<string, unknown> = {}) {
    return {
        type: 'sql_injection',
        line: 10,
        lineEnd: 12,
        evidence: "db.query('SELECT * FROM users WHERE id=' + req.body.id)",
        why: 'user input concatenated into SQL',
        severity: 'high',
        confidence: 95,
        ...overrides,
    };
}

function agentResult(findings: any[], overrides: Record<string, unknown> = {}) {
    return {
        status: 'completed',
        terminationReason: 'agent_finish',
        findings,
        transcript: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 1,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.05,
        summary: 'done',
        ...overrides,
    } as any;
}

function setupBroker(opts: { approved?: boolean; reason?: string; startFails?: boolean }) {
    const requestApproval = vi.fn().mockResolvedValue({
        approved: !!opts.approved,
        reason: opts.reason ?? '',
        requestId: 'probe-approval',
        duration: 0,
    });
    vi.mocked(ApprovalBroker).mockImplementation(() => ({
        start: opts.startFails ? vi.fn().mockRejectedValue(new Error('EADDRINUSE')) : vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval,
    }) as any);
    return requestApproval;
}

function setupPostJson() {
    const postJson = vi.fn(async (p: string) => {
        if (p === '/verify/probe-plan') return { canProbe: true, plan: PROBE_PLAN, costUsd: 0.01, scanCredits: 99 };
        return {};
    });
    vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);
    return postJson;
}

let workspaceRoot: string;

async function runScan(filePath = 'routes.ts') {
    const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
    return toolAgentScan(ctx, { filePath, language: 'typescript', _skipFix: true, _noCache: true }) as Promise<any>;
}

describe('toolAgentScan — proof approval not given', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-approval-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), 'export function createUser(req, res) {}\n');
        vi.clearAllMocks();
        vi.mocked(runAgentScan).mockResolvedValue(agentResult([
            makeFinding(),
            makeFinding({ type: 'ssrf', line: 22, severity: 'medium' }),
        ]));
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE',
            reason: VERIFY_REASON,
            roundsUsed: 12,
            testScript: '',
            testOutput: '',
            subVerdict: 'analyzed',
        } as any);
        vi.mocked(matchEndpointForFinding).mockReturnValue(ENDPOINT as any);
        vi.mocked(detectDevServer).mockResolvedValue({ host: '127.0.0.1', port: 3000, source: 'env' } as any);
        vi.mocked(executeProbePlan).mockResolvedValue({
            verdict: 'PROVEN',
            rule: 'sqli-error-based',
            reason: 'baseline 200 vs attack 500',
            evidence: 'live',
            requests: [],
        } as any);
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    it('marks findings when approval expires and adds the summary sentence', async () => {
        const requestApproval = setupBroker({ approved: false, reason: 'Request timed out after 120s.' });
        const postJson = setupPostJson();

        const result = await runScan();

        expect(requestApproval).toHaveBeenCalledWith(
            'securecode.runtime-probe', expect.any(String), expect.any(Array), 120_000, 'paid-generation', workspaceRoot, expect.any(Object),
        );
        expect(postJson.mock.calls.some(c => c[0] === '/verify/probe-plan')).toBe(false);
        expect(result.agentFindings).toHaveLength(2);
        for (const f of result.agentFindings) {
            expect(f.proven).toBe('INCONCLUSIVE');
            expect(f.provenReason.startsWith(`${NOT_GIVEN} ${VERIFY_REASON}`)).toBe(true);
        }
        expect(result.summary).toContain("2 finding(s) unproven because approval wasn't given.");
    });

    it('uses the denied reason when the user explicitly denies', async () => {
        setupBroker({ approved: false, reason: 'User denied' });
        setupPostJson();

        const result = await runScan();

        for (const f of result.agentFindings) {
            expect(f.provenReason.startsWith(`${DENIED} ${VERIFY_REASON}`)).toBe(true);
            expect(f.provenReason).not.toContain(NOT_GIVEN);
        }
        expect(result.summary).toContain("2 finding(s) unproven because approval wasn't given.");
    });

    it('treats a broker that cannot start as approval not given', async () => {
        const requestApproval = setupBroker({ startFails: true });
        setupPostJson();

        const result = await runScan();

        expect(requestApproval).not.toHaveBeenCalled();
        for (const f of result.agentFindings) {
            expect(f.provenReason.startsWith(NOT_GIVEN)).toBe(true);
        }
        expect(result.summary).toContain("2 finding(s) unproven because approval wasn't given.");
    });

    it('leaves the approved path unchanged', async () => {
        setupBroker({ approved: true, reason: 'User approved' });
        setupPostJson();

        const result = await runScan();

        expect(executeProbePlan).toHaveBeenCalledTimes(2);
        for (const f of result.agentFindings) {
            expect(f.proven).toBe('PROVEN');
            expect(f.provenReason).not.toContain('Proof skipped');
        }
        expect(result.summary).not.toContain('approval');
    });

    it('reports the count once in the merged summary of a split-file scan', async () => {
        const lines: string[] = [];
        for (let i = 0; i < 47; i++) {
            lines.push(`export function handler${i}(req: any, res: any) {`);
            for (let j = 0; j < 98; j++) lines.push(`    const v${j} = req.body.f${j};`);
            lines.push('}');
            lines.push('');
        }
        fs.writeFileSync(path.join(workspaceRoot, 'big.ts'), lines.join('\n'));
        vi.mocked(runAgentScan).mockImplementation(async (_ctx: any, _target: any, opts: any) => {
            const seg = opts.segment;
            const findings = seg.index === 1 || seg.index === 3
                ? [makeFinding({ line: seg.startLine + 5, lineEnd: seg.startLine + 5 })]
                : [];
            return agentResult(findings, { runId: `run-${seg.index}`, summary: `part ${seg.index} done` });
        });
        setupBroker({ approved: false, reason: 'Request timed out after 120s.' });
        setupPostJson();

        const result = await runScan('big.ts');

        expect(result.segments.length).toBeGreaterThan(1);
        expect(result.agentFindings).toHaveLength(2);
        const matches = result.summary.match(/finding\(s\) unproven because approval wasn't given\./g) ?? [];
        expect(matches).toHaveLength(1);
        expect(result.summary).toContain("2 finding(s) unproven because approval wasn't given.");
    });
});
