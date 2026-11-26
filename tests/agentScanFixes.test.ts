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

const mockBrokerRequestSessionApproval = vi.fn();
const mockBrokerStart = vi.fn().mockResolvedValue(0);
const mockBrokerStop = vi.fn().mockResolvedValue(undefined);

vi.mock('../src/approval/broker', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApprovalBroker: vi.fn().mockImplementation(() => ({
            start: mockBrokerStart,
            stop: mockBrokerStop,
            requestSessionApproval: mockBrokerRequestSessionApproval,
            requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'fix-approval', duration: 0 }),
        })),
        consumeSessionApproval: vi.fn().mockReturnValue(true),
        revokeSessionApproval: vi.fn().mockReturnValue(true),
    };
});

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
import { consumeSessionApproval, revokeSessionApproval } from '../src/approval/broker';
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

function makeFinding(overrides: Record<string, any> = {}) {
    return {
        type: 'sql_injection',
        line: 4,
        lineEnd: 5,
        evidence: 'const q = "SELECT * FROM users WHERE id=" + req.body.id;',
        why: 'user input concatenated into SQL',
        severity: 'high',
        confidence: 95,
        ...overrides,
    };
}

function makeAssuranceCells() {
    return {
        cells: [{ id: 'c1', entryId: null, inputId: null, targetId: null, attackType: 'sqli', title: 'SQL injection', risk: 4, source: 'ai', status: 'open' }],
        scenarios: [{ id: 's1', cellId: 'c1', actor: 'anon', preconditions: [], steps: [], payloads: [], expectSecure: '', risk: 4 }],
        redteamRounds: 1,
        warnings: [],
    };
}

function setupVerify(proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE') {
    vi.mocked(runVerifyLoop).mockResolvedValue({
        verdict: proven,
        reason: 'exploit reproduced',
        roundsUsed: 2,
        testScript: '',
        testOutput: '',
        subVerdict: 'analyzed',
    } as any);
}

let workspaceRoot: string;

describe('toolAgentScan — fix generation with session approval', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-fixes-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), CODE);
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(ApiClient).mockReset();
        vi.mocked(consumeSessionApproval).mockReset().mockReturnValue(true);
        vi.mocked(revokeSessionApproval).mockReset().mockReturnValue(true);
        mockBrokerRequestSessionApproval.mockReset();
        vi.clearAllMocks();
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
        vi.unstubAllEnvs();
    });

    function setupAgentResult(overrides: Record<string, any> = {}) {
        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [makeFinding()],
            transcript: [],
            investigationNotes: [],
            coverageGaps: [],
            stepsUsed: 5,
            stepsGranted: 40,
            extensionsGranted: 0,
            costSpentUsd: 0.05,
            summary: 'done',
            ...overrides,
        } as any);
    }

    function mockFixResponses(responses: any[]) {
        const postJson = vi.fn();
        for (const r of responses) postJson.mockResolvedValueOnce(r);
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);
        return postJson;
    }

    async function runScan(extraArgs: Record<string, any> = {}) {
        const ctx: any = {
            workspaceRoot,
            apiUrl: 'https://api.usesecurecode.tech',
            apiToken: 'test-token',
        };
        return toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript', ...extraArgs });
    }

    it('assurance mode: no approval requested, fixesAvailable populated', async () => {
        setupAgentResult({ assurance: makeAssuranceCells() });
        setupVerify('PROVEN');
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const result: any = await runScan();

        expect(mockBrokerRequestSessionApproval).not.toHaveBeenCalled();
        const fixCalls = postJson.mock.calls.filter((c: any) => c[0] === '/fix');
        expect(fixCalls).toHaveLength(0);

        const finding = result.agentFindings[0];
        expect(finding.fixStatus).toBe('available');
        expect(result.fixesAvailable).toBeDefined();
        expect(result.fixesAvailable.count).toBe(1);
        expect(result.fixesAvailable.findings[0]).toMatchObject({ type: 'sql_injection', line: 4, severity: 'high' });
        expect(result.fixesAvailable.next).toContain('generateFixes');
        expect(result.summary).toContain('fix(es) available');
    });

    it('assurance mode with generateFixes: true generates fixes with session approval', async () => {
        setupAgentResult({ assurance: makeAssuranceCells() });
        setupVerify('PROVEN');
        mockBrokerRequestSessionApproval.mockResolvedValue({
            granted: true, state: 'granted', reason: 'ok', detail: '', requestId: 'sess-fix-1',
            runId: 'r', maxTests: 10, remaining: 10, expiresAt: Date.now() + 60_000,
        });
        const postJson = mockFixResponses([
            { fixed_code: 'fix-1', fix_summary: 's1', confidence: 80, replace_range: { start_line: 4, end_line: 5 } },
        ]);
        vi.mocked(runFixVerifyLoop).mockResolvedValue({
            status: 'closed', reason: 'ok', originalVerdict: 'PROVEN', fixedVerdict: 'UNPROVEN', roundsUsed: 1, fixedCodeHash: 'h',
        } as any);

        const result: any = await runScan({ generateFixes: true });

        expect(mockBrokerRequestSessionApproval).toHaveBeenCalledTimes(1);
        const fixCalls = postJson.mock.calls.filter((c: any) => c[0] === '/fix');
        expect(fixCalls).toHaveLength(1);
        expect(result.agentFindings[0].fixStatus).toBe('fix-verified-closed');
    });

    it('standard mode: exactly one session approval for N findings', async () => {
        setupAgentResult({ findings: [makeFinding(), makeFinding({ type: 'xss', line: 10 })] });
        setupVerify('PROVEN');
        mockBrokerRequestSessionApproval.mockResolvedValue({
            granted: true, state: 'granted', reason: 'ok', detail: '', requestId: 'sess-fix-1',
            runId: 'r', maxTests: 10, remaining: 10, expiresAt: Date.now() + 60_000,
        });
        const postJson = mockFixResponses([
            { fixed_code: 'fix-1', fix_summary: 's1', confidence: 80 },
            { fixed_code: 'fix-2', fix_summary: 's2', confidence: 80 },
        ]);
        vi.mocked(runFixVerifyLoop).mockResolvedValue({
            status: 'closed', reason: 'ok', originalVerdict: 'PROVEN', fixedVerdict: 'UNPROVEN', roundsUsed: 1, fixedCodeHash: 'h',
        } as any);

        const result: any = await runScan();

        expect(mockBrokerRequestSessionApproval).toHaveBeenCalledTimes(1);
        const sessionArg = mockBrokerRequestSessionApproval.mock.calls[0][0];
        expect(sessionArg.tool).toBe('fix-generation');
        expect(sessionArg.maxTests).toBe(4);

        const fixCalls = postJson.mock.calls.filter((c: any) => c[0] === '/fix');
        expect(fixCalls).toHaveLength(2);
    });

    it('denial: all findings get fix-denied', async () => {
        setupAgentResult({ findings: [makeFinding(), makeFinding({ type: 'xss', line: 10 })] });
        setupVerify('PROVEN');
        mockBrokerRequestSessionApproval.mockResolvedValue({
            granted: false, state: 'denied', reason: 'User denied', detail: 'denied', requestId: 'sess-fix-2',
            runId: 'r', maxTests: 0, remaining: 0, expiresAt: null,
        });
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const result: any = await runScan();

        const fixCalls = postJson.mock.calls.filter((c: any) => c[0] === '/fix');
        expect(fixCalls).toHaveLength(0);
        for (const f of result.agentFindings) {
            expect(f.fixStatus).toBe('fix-denied');
            expect(f.fixDeniedReason).toContain('denied');
        }
    });

    it('revokes session approval at the end', async () => {
        setupAgentResult();
        setupVerify('PROVEN');
        mockBrokerRequestSessionApproval.mockResolvedValue({
            granted: true, state: 'granted', reason: 'ok', detail: '', requestId: 'sess-fix-1',
            runId: 'r', maxTests: 10, remaining: 10, expiresAt: Date.now() + 60_000,
        });
        mockFixResponses([{ fixed_code: 'fix-1', fix_summary: 's1', confidence: 80 }]);
        vi.mocked(runFixVerifyLoop).mockResolvedValue({
            status: 'closed', reason: 'ok', originalVerdict: 'PROVEN', fixedVerdict: 'UNPROVEN', roundsUsed: 1, fixedCodeHash: 'h',
        } as any);

        await runScan();

        expect(vi.mocked(revokeSessionApproval)).toHaveBeenCalled();
    });
});

describe('toolAgentScan — exploited-finding mapping', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-efmap-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), CODE);
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(ApiClient).mockReset();
        vi.mocked(consumeSessionApproval).mockReset().mockReturnValue(true);
        vi.mocked(revokeSessionApproval).mockReset().mockReturnValue(true);
        mockBrokerRequestSessionApproval.mockReset();
        vi.clearAllMocks();
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
        vi.unstubAllEnvs();
    });

    async function runScan(agentOverrides: Record<string, any> = {}) {
        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [makeFinding()],
            transcript: [],
            investigationNotes: [],
            coverageGaps: [],
            stepsUsed: 5,
            stepsGranted: 40,
            extensionsGranted: 0,
            costSpentUsd: 0.05,
            summary: 'done',
            assurance: makeAssuranceCells(),
            ...agentOverrides,
        } as any);
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'PROVEN', reason: 'exploit reproduced', roundsUsed: 2,
            testScript: '', testOutput: '', subVerdict: 'analyzed',
        } as any);
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const { runAssuranceAttackTests } = await import('../src/assurance/attackTests');
        return { postJson, runScan: toolAgentScan };
    }

    it('observedType and severity from exploitedFinding fields are used', async () => {
        const attackMod = await import('../src/assurance/attackTests');
        vi.spyOn(attackMod, 'runAssuranceAttackTests').mockResolvedValue({
            scenarioUpdates: [],
            cellUpdates: [],
            exploitedFindings: [{
                cellId: 'c1', scenarioId: 's1', type: 'auth_bypass', line: 20,
                title: 'missing rate limit', why: 'no limit on signup',
                observedType: 'missing_rate_limiting', severity: 'medium', confidence: 92,
            }],
            approval: { granted: true, reason: 'ok' },
            ran: 1, blocked: 0, exploited: 1, untestable: 0, skipped: 0, costUsd: 0,
        });

        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed', findings: [],
            transcript: [], investigationNotes: [], coverageGaps: [],
            stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.05, summary: 'done',
            assurance: makeAssuranceCells(),
        } as any);
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        const result: any = await toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript' });

        const ef = result.agentFindings.find((f: any) => f.type === 'missing_rate_limiting');
        expect(ef).toBeDefined();
        expect(ef.severity).toBe('medium');
        expect(ef.confidence).toBe(92);
        expect(ef.proven).toBe('PROVEN');

        vi.restoreAllMocks();
    });

    it('severity falls back to cell risk when not on the exploited finding', async () => {
        const attackMod = await import('../src/assurance/attackTests');
        vi.spyOn(attackMod, 'runAssuranceAttackTests').mockResolvedValue({
            scenarioUpdates: [],
            cellUpdates: [],
            exploitedFindings: [{
                cellId: 'c1', scenarioId: 's1', type: 'auth_bypass', line: 20,
                title: 'bypass auth', why: 'no guard',
            }],
            approval: { granted: true, reason: 'ok' },
            ran: 1, blocked: 0, exploited: 1, untestable: 0, skipped: 0, costUsd: 0,
        });

        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed', findings: [],
            transcript: [], investigationNotes: [], coverageGaps: [],
            stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.05, summary: 'done',
            assurance: makeAssuranceCells(),
        } as any);
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        const result: any = await toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript' });

        const ef = result.agentFindings.find((f: any) => f.line === 20);
        expect(ef).toBeDefined();
        expect(ef.severity).toBe('high');
        expect(ef.confidence).toBe(85);

        vi.restoreAllMocks();
    });

    it('merges into existing nearby finding instead of duplicating', async () => {
        const attackMod = await import('../src/assurance/attackTests');
        vi.spyOn(attackMod, 'runAssuranceAttackTests').mockResolvedValue({
            scenarioUpdates: [],
            cellUpdates: [],
            exploitedFindings: [{
                cellId: 'c1', scenarioId: 's1', type: 'sql_injection', line: 5,
                title: 'SQL injection', why: 'no parameterization',
                observedType: 'sql_injection', severity: 'critical',
            }],
            approval: { granted: true, reason: 'ok' },
            ran: 1, blocked: 0, exploited: 1, untestable: 0, skipped: 0, costUsd: 0,
        });

        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [makeFinding()],
            transcript: [], investigationNotes: [], coverageGaps: [],
            stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.05, summary: 'done',
            assurance: makeAssuranceCells(),
        } as any);
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE', reason: 'could not reproduce', roundsUsed: 2,
            testScript: '', testOutput: '', subVerdict: 'analyzed',
        } as any);
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        const result: any = await toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript' });

        const sqlFindings = result.agentFindings.filter((f: any) => f.type === 'sql_injection');
        expect(sqlFindings).toHaveLength(1);
        expect(sqlFindings[0].proven).toBe('PROVEN');
        expect(sqlFindings[0].severity).toBe('high');
        expect(sqlFindings[0].provenReason).toContain('Attack test exploited');

        vi.restoreAllMocks();
    });

    it('merges related types (mass_assignment ~ broken_access_control)', async () => {
        const attackMod = await import('../src/assurance/attackTests');
        vi.spyOn(attackMod, 'runAssuranceAttackTests').mockResolvedValue({
            scenarioUpdates: [],
            cellUpdates: [],
            exploitedFindings: [{
                cellId: 'c1', scenarioId: 's1', type: 'bac', line: 4,
                title: 'mass assignment', why: 'no guard',
                observedType: 'mass_assignment', severity: 'high',
            }],
            approval: { granted: true, reason: 'ok' },
            ran: 1, blocked: 0, exploited: 1, untestable: 0, skipped: 0, costUsd: 0,
        });

        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [makeFinding({ type: 'broken_access_control', line: 4 })],
            transcript: [], investigationNotes: [], coverageGaps: [],
            stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.05, summary: 'done',
            assurance: makeAssuranceCells(),
        } as any);
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE', reason: 'could not reproduce', roundsUsed: 2,
            testScript: '', testOutput: '', subVerdict: 'analyzed',
        } as any);
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        const result: any = await toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript' });

        const bacFindings = result.agentFindings.filter((f: any) =>
            f.type === 'broken_access_control' || f.type === 'mass_assignment'
        );
        expect(bacFindings).toHaveLength(1);
        expect(bacFindings[0].proven).toBe('PROVEN');
        expect(bacFindings[0].provenReason).toContain('Attack test exploited');

        vi.restoreAllMocks();
    });

    it.each([
        ['hardcoded_secret', 7, 'insecure_default_configuration', 7, 'critical'],
        ['broken_authentication', 105, 'missing_authorization', 106, 'high'],
    ])('merges %s L%i with attack-test %s L%i and does not raise severity above the cell risk', async (agentType, agentLine, observedType, testLine, observedSeverity) => {
        const attackMod = await import('../src/assurance/attackTests');
        vi.spyOn(attackMod, 'runAssuranceAttackTests').mockResolvedValue({
            scenarioUpdates: [],
            cellUpdates: [],
            exploitedFindings: [{
                cellId: 'c1', scenarioId: 's1', type: 'auth_bypass', line: testLine as number,
                title: 'attack', why: 'exploited',
                observedType: observedType as string, severity: observedSeverity as any,
            }],
            approval: { granted: true, reason: 'ok' },
            ran: 1, blocked: 0, exploited: 1, untestable: 0, skipped: 0, costUsd: 0,
        });
        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [makeFinding({ type: agentType as string, line: agentLine as number, severity: 'medium' })],
            transcript: [], investigationNotes: [], coverageGaps: [],
            stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.05, summary: 'done',
            assurance: makeAssuranceCells(),
        } as any);
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE', reason: 'could not reproduce', roundsUsed: 2,
            testScript: '', testOutput: '', subVerdict: 'analyzed',
        } as any);
        const postJson = vi.fn();
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);

        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        const result: any = await toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript' });

        expect(result.agentFindings).toHaveLength(1);
        expect(result.agentFindings[0].type).toBe(agentType);
        expect(result.agentFindings[0].severity).toBe('medium');
        expect(result.agentFindings[0].proven).toBe('PROVEN');
        expect(result.agentFindings[0].provenReason).toContain(`observed ${observedType}`);

        vi.restoreAllMocks();
    });
});
