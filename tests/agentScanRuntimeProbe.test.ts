import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// Runtime-probe integration suite — mirrors the mocking style of
// agentScanSandboxFallback.test.ts. The verify loop returns INCONCLUSIVE with
// a probe-eligible reason ("timed out"), the agent loop returns findings, and
// the runtimeProbe module is PARTIALLY mocked: detectDevServer/executeProbePlan
// are stubbed, isProbeEligible/matchEndpointForFinding stay real so the
// eligibility gate is exercised.

vi.mock('../src/attack/verifyLoop', () => ({
    runVerifyLoop: vi.fn(),
}));

vi.mock('../src/attack/agentScanLoop', () => ({
    runAgentScan: vi.fn(),
}));

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'test auto-approve', requestId: 'test-approval', duration: 0 }),
    })),
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
    };
});

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { ApprovalBroker } from '../src/approval/broker';
import { getEndpointContextForFile } from '../src/project-map/mapContext';
import { detectDevServer, executeProbePlan } from '../src/attack/runtimeProbe';
import { toolAgentScan } from '../src/tools/agentScan';
import { loadReviewQueue } from '../src/audit/findingReviewQueue';

const DEV_SERVER = { host: '127.0.0.1', port: 3000, source: 'env' as const };

const ENDPOINTS = [
    {
        method: 'POST',
        path: '/users',
        mountedPath: '/api/users',
        line: 10,
        handlerName: 'createUser',
        sourceFile: 'routes.ts',
        params: [],
        authScheme: 'none',
        middleware: [],
    },
];

const PROBE_PLAN = {
    host: '127.0.0.1',
    port: 3000,
    requests: [
        { role: 'baseline', method: 'POST', path: '/api/users' },
        { role: 'attack', method: 'POST', path: "/api/users?id=1' OR '1'='1" },
    ],
};

const PROBE_EVIDENCE = `Rule 'sqli-error-based' → PROVEN: baseline 200 vs attack 500. ${'x'.repeat(400)}`;

const PROBE_RESULT = {
    verdict: 'PROVEN',
    rule: 'sqli-error-based',
    reason: 'baseline 200 vs attack 500 — SQL error leaked in the response body',
    baselineStatus: 200,
    attackStatus: 500,
    evidence: PROBE_EVIDENCE,
    requests: [],
};

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

let workspaceRoot: string;

function setupScan(findings: any[], endpoints: any[] = ENDPOINTS) {
    vi.mocked(runAgentScan).mockResolvedValue({
        status: 'completed',
        findings,
        transcript: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 1,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.05,
        summary: 'done',
    } as any);
    vi.mocked(runVerifyLoop).mockResolvedValue({
        verdict: 'INCONCLUSIVE',
        reason: 'Test timed out after 12 rounds.',
        roundsUsed: 12,
        testScript: '',
        testOutput: '',
        subVerdict: 'analyzed',
    } as any);
    vi.mocked(getEndpointContextForFile).mockResolvedValue(endpoints as any);
    vi.mocked(detectDevServer).mockResolvedValue({ ...DEV_SERVER });
    vi.mocked(executeProbePlan).mockResolvedValue({ ...PROBE_RESULT } as any);
}

function setupPostJson(response: any) {
    const mockPostJson = vi.fn().mockResolvedValue(response);
    vi.mocked(ApiClient).mockReturnValue({ postJson: mockPostJson } as any);
    return mockPostJson;
}

function setupApproval(approved: boolean) {
    const requestApproval = vi.fn().mockResolvedValue({
        approved,
        reason: approved ? 'User approved' : 'User denied',
        requestId: 'probe-approval',
        duration: 0,
    });
    vi.mocked(ApprovalBroker).mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval,
    }) as any);
    return requestApproval;
}

async function runScan(args: Record<string, unknown> = {}) {
    const ctx: any = {
        workspaceRoot,
        apiUrl: 'https://api.usesecurecode.tech',
        apiToken: 'test-token',
    };
    return toolAgentScan(ctx, {
        filePath: 'routes.ts',
        language: 'typescript',
        _skipFix: true,
        ...args,
    });
}

describe('toolAgentScan — runtime probe fallback', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-probe-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), 'export function createUser(req, res) {}\n');
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(getEndpointContextForFile).mockReset();
        vi.mocked(detectDevServer).mockReset();
        vi.mocked(executeProbePlan).mockReset();
        vi.mocked(ApiClient).mockReset();
        vi.mocked(ApprovalBroker).mockReset();
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
        vi.unstubAllEnvs();
    });

    it('probes an eligible INCONCLUSIVE finding and maps a PROVEN probe result', async () => {
        setupScan([makeFinding()]);
        const requestApproval = setupApproval(true);
        const mockPostJson = setupPostJson({ canProbe: true, plan: PROBE_PLAN, costUsd: 0.01, scanCredits: 99 });

        const result = await runScan();

        expect(mockPostJson).toHaveBeenCalledTimes(1);
        expect(mockPostJson).toHaveBeenCalledWith('/verify/probe-plan', expect.objectContaining({
            finding: expect.objectContaining({
                type: 'sql_injection',
                line: 10,
                lineEnd: 12,
                severity: 'high',
            }),
            endpoint: expect.objectContaining({
                method: 'POST',
                path: '/api/users',
                mountedPath: '/api/users',
                params: [],
                authScheme: 'none',
                middleware: [],
            }),
            devServerPort: 3000,
        }));
        expect(executeProbePlan).toHaveBeenCalledTimes(1);
        expect(vi.mocked(executeProbePlan).mock.calls[0][0]).toBe(PROBE_PLAN);

        expect(requestApproval).toHaveBeenCalledTimes(1);
        expect(requestApproval).toHaveBeenCalledWith(
            'securecode.runtime-probe',
            expect.stringContaining('Runtime probe verification: 1 finding(s) need live-server confirmation against 127.0.0.1:3000'),
            expect.any(Array),
            60_000,
            'paid-generation',
            workspaceRoot,
        );

        const finding = result.agentFindings[0];
        expect(finding.proven).toBe('PROVEN');
        expect(finding.verificationLevel).toBe('impact-confirmed');
        expect(finding.confidence).toBe(90);
        expect(finding.originalConfidence).toBe(95);
        expect(finding.probeEvidence).toBe(PROBE_EVIDENCE);
        expect(finding.probeRule).toBe('sqli-error-based');
        const expectedPrefix = `Runtime probe confirmed (sqli-error-based): ${PROBE_RESULT.reason} — live evidence: `;
        expect(finding.provenReason).toBe(expectedPrefix + PROBE_EVIDENCE.slice(0, 300) + '…');
        expect(result.reviewQueue.added).toHaveLength(0);
    });

    it('falls back to a derived endpoint when the map has none for the file (Effect-TS)', async () => {        // The deterministic map returns ZERO endpoints — the Effect-TS case.
        // The scanned file itself contains the route registration, so the
        // fallback derives the probe candidate from the code window.
        const effectCode = [
            "import { HttpApiEndpoint } from '@effect/platform'",
            '',
            "export const bootstrapApi = HttpApiEndpoint.post('bootstrap', () => {",
            '  // exchanges a bootstrap token for a session token without ownership checks',
            '})',
            '',
            '// pad',
            '// pad',
            '// pad',
            '// pad',
            'const vulnerableExchange = (token: string) => token // finding at line 12',
        ].join('\n');
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), effectCode);

        setupScan([makeFinding({ line: 12 })], []);
        const requestApproval = setupApproval(true);
        const mockPostJson = setupPostJson({ canProbe: true, plan: PROBE_PLAN, costUsd: 0.01, scanCredits: 99 });

        const result = await runScan();

        expect(mockPostJson).toHaveBeenCalledTimes(1);
        expect(mockPostJson).toHaveBeenCalledWith('/verify/probe-plan', expect.objectContaining({
            endpoint: expect.objectContaining({
                method: 'POST',
                path: '/bootstrap',
            }),
        }));
        expect(requestApproval).toHaveBeenCalledTimes(1);
        expect(executeProbePlan).toHaveBeenCalledTimes(1);

        const finding = result.agentFindings[0];
        expect(finding.proven).toBe('PROVEN');
        expect(finding.verificationLevel).toBe('impact-confirmed');
        expect(finding.probeRule).toBe('sqli-error-based');
    });

    it('requests endpoint context with the ABSOLUTE path (map lookup regression)', async () => {
        // Regression: the tool used to pass the raw (relative) filePath to
        // getEndpointContextForFile, producing a garbage relative-path key
        // and empty endpoint context even for supported frameworks.
        setupScan([makeFinding()], ENDPOINTS);
        setupApproval(false);

        await runScan();

        expect(vi.mocked(getEndpointContextForFile)).toHaveBeenCalledWith(
            path.join(workspaceRoot, 'routes.ts'),
            workspaceRoot,
        );
    });

    it('keeps INCONCLUSIVE and queues review when the API refuses a probe plan', async () => {
        setupScan([makeFinding()]);
        setupApproval(true);
        const mockPostJson = setupPostJson({ canProbe: false, skipReason: 'Framework not supported for runtime probing', plan: null, costUsd: 0, scanCredits: 100 });

        const result = await runScan();

        const finding = result.agentFindings[0];
        expect(finding.proven).toBe('INCONCLUSIVE');
        expect(finding.provenReason).toContain('Runtime probe skipped: Framework not supported for runtime probing');
        expect(executeProbePlan).not.toHaveBeenCalled();
        expect(result.verifyHint).toContain('1 finding(s) could be runtime-probe verified');
        expect(result.reviewQueue.added).toHaveLength(1);
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items[0].reviewReason).toBe('runtime-probe-pending');
    });

    it('keeps INCONCLUSIVE with the dev-server hint when no dev server is detected', async () => {
        setupScan([makeFinding()]);
        vi.mocked(detectDevServer).mockResolvedValue(null);
        const mockPostJson = setupPostJson(null);

        const result = await runScan();

        const finding = result.agentFindings[0];
        expect(finding.proven).toBe('INCONCLUSIVE');
        expect(finding.provenReason).toContain('Live-server probe available — start your dev server and re-scan to attempt runtime proof.');
        expect(result.verifyHint).toContain('start your dev server');
        expect(result.verifyHint).toContain('SECURECODE_DEV_SERVER_PORT');
        expect(mockPostJson).not.toHaveBeenCalled();
        expect(ApprovalBroker).not.toHaveBeenCalled();
        expect(executeProbePlan).not.toHaveBeenCalled();
        expect(result.reviewQueue.added).toHaveLength(1);
        expect(loadReviewQueue(workspaceRoot).items[0].reviewReason).toBe('runtime-probe-pending');
    });

    it('skips all eligible findings when approval is denied', async () => {
        setupScan([
            makeFinding({ type: 'sql_injection', line: 10 }),
            makeFinding({ type: 'ssrf', line: 22, severity: 'medium' }),
        ]);
        const requestApproval = setupApproval(false);
        const mockPostJson = setupPostJson(null);

        const result = await runScan();

        expect(requestApproval).toHaveBeenCalledTimes(1);
        expect(requestApproval).toHaveBeenCalledWith(
            'securecode.runtime-probe',
            expect.stringContaining('Runtime probe verification: 2 finding(s)'),
            expect.any(Array),
            expect.any(Number),
            'paid-generation',
            workspaceRoot,
        );
        expect(mockPostJson).not.toHaveBeenCalled();
        for (const finding of result.agentFindings) {
            expect(finding.proven).toBe('INCONCLUSIVE');
            expect(finding.provenReason).toContain('Live-server probe available — start your dev server and re-scan to attempt runtime proof.');
        }
        expect(result.verifyHint).toContain('2 finding(s) could be runtime-probe verified');
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items.map(i => i.reviewReason)).toEqual(['runtime-probe-pending', 'runtime-probe-pending']);
    });

    it('does not detect, probe, or request approval when SECURECODE_DISABLE_RUNTIME_PROBE=1', async () => {
        vi.stubEnv('SECURECODE_DISABLE_RUNTIME_PROBE', '1');
        setupScan([makeFinding()]);
        const mockPostJson = setupPostJson(null);

        const result = await runScan();

        expect(detectDevServer).not.toHaveBeenCalled();
        expect(executeProbePlan).not.toHaveBeenCalled();
        expect(ApprovalBroker).not.toHaveBeenCalled();
        expect(mockPostJson).not.toHaveBeenCalled();
        const finding = result.agentFindings[0];
        expect(finding.proven).toBe('INCONCLUSIVE');
        expect(finding.provenReason).not.toContain('Live-server probe available');
        expect(result.verifyHint).toBeUndefined();
    });

    it('never probes non-eligible finding types', async () => {
        setupScan([makeFinding({ type: 'hardcoded_secret', severity: 'medium' })]);
        const mockPostJson = setupPostJson(null);

        const result = await runScan();

        expect(detectDevServer).not.toHaveBeenCalled();
        expect(executeProbePlan).not.toHaveBeenCalled();
        expect(mockPostJson).not.toHaveBeenCalled();
        const finding = result.agentFindings[0];
        expect(finding.proven).toBe('INCONCLUSIVE');
        expect(finding.provenReason).toBe('Test timed out after 12 rounds.');
        expect(result.reviewQueue.added).toHaveLength(1);
        expect(loadReviewQueue(workspaceRoot).items[0].reviewReason).toBe('inconclusive-verification');
    });

    it('probes at most 3 findings per scan, severity-first', async () => {
        setupScan([
            makeFinding({ type: 'xss', line: 14, severity: 'medium' }),
            makeFinding({ type: 'sql_injection', line: 11, severity: 'critical' }),
            makeFinding({ type: 'ssrf', line: 12, severity: 'high' }),
            makeFinding({ type: 'open_redirect', line: 13, severity: 'high' }),
            makeFinding({ type: 'nosql_injection', line: 10, severity: 'medium' }),
        ]);
        setupApproval(true);
        const mockPostJson = setupPostJson({ canProbe: true, plan: PROBE_PLAN, costUsd: 0.01, scanCredits: 99 });

        const result = await runScan();

        const probeCalls = mockPostJson.mock.calls.filter(c => c[0] === '/verify/probe-plan');
        expect(probeCalls).toHaveLength(3);
        expect(probeCalls.map(c => (c[1] as any).finding.line)).toEqual([11, 12, 13]);
        expect(executeProbePlan).toHaveBeenCalledTimes(3);

        const byLine = new Map(result.agentFindings.map((f: any) => [f.line, f]));
        expect(byLine.get(11).proven).toBe('PROVEN');
        expect(byLine.get(12).proven).toBe('PROVEN');
        expect(byLine.get(13).proven).toBe('PROVEN');
        expect(byLine.get(10).proven).toBe('INCONCLUSIVE');
        expect(byLine.get(10).provenReason).toContain('Live-server probe budget reached (3 per scan)');
        expect(byLine.get(14).proven).toBe('INCONCLUSIVE');
        expect(result.verifyHint).toContain('2 finding(s) could be runtime-probe verified');
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items.filter(i => i.reviewReason === 'runtime-probe-pending')).toHaveLength(2);
    });
});
