import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

process.env.SECURECODE_TEST_MODE = '1';

const mocks = vi.hoisted(() => ({
    postJson: vi.fn(),
    runLocalTest: vi.fn(),
    detectRuntime: vi.fn(),
    detectSandbox: vi.fn(),
    requestSessionApproval: vi.fn(),
    consumeSessionApproval: vi.fn(),
    getSessionApproval: vi.fn(),
    revokeSessionApproval: vi.fn(),
    getRelatedFilesForFile: vi.fn(),
}));

vi.mock('../src/api/client', () => ({
    ApiClient: class {
        postJson(p: string, body: unknown, signal?: AbortSignal) { return mocks.postJson(p, body, signal); }
    },
}));
vi.mock('../src/utils/localTestRunner', () => ({ runLocalTest: mocks.runLocalTest }));
vi.mock('../src/utils/runtimeDetect', () => ({
    detectRuntime: mocks.detectRuntime,
    computeRelativeImportPath: () => '../src/target.js',
}));
vi.mock('../src/utils/verificationSandbox', () => ({ detectSandbox: mocks.detectSandbox }));
vi.mock('../src/project-map/mapContext', () => ({ getRelatedFilesForFile: mocks.getRelatedFilesForFile }));
vi.mock('../src/approval/broker', async (importOriginal) => {
    const real: any = await importOriginal();
    return {
        ...real,
        ApprovalBroker: class {
            async start() { return 1; }
            async stop() {}
            requestSessionApproval(...args: unknown[]) { return mocks.requestSessionApproval(...args); }
        },
        consumeSessionApproval: mocks.consumeSessionApproval,
        getSessionApproval: mocks.getSessionApproval,
        revokeSessionApproval: mocks.revokeSessionApproval,
    };
});

import {
    runAssuranceAttackTests,
    DEEP_SANDBOX_RUN_CAP,
    type AssuranceAttackTestInput,
} from '../src/assurance/attackTests';
import type { GridCell, Scenario } from '../src/attack/agentScanProtocol';

function cell(id: string, risk: GridCell['risk'], status: GridCell['status'], closure?: GridCell['closure']): GridCell {
    return { id, entryId: 'e1', inputId: 'i1', targetId: 't1', attackType: 'idor', title: `cell ${id}`, risk, source: 'seed', status, ...(closure ? { closure } : {}) };
}
function scen(id: string, cellId: string, risk: Scenario['risk'] = 3): Scenario {
    return { id, cellId, actor: 'user B', preconditions: ['A owns doc 1'], steps: ['GET /doc/1 as B'], payloads: ['1'], expectSecure: 'B is refused', risk };
}

const marker = (o: Record<string, unknown>) => `SECURECODE_SCENARIO_RESULT:${JSON.stringify(o)}:SECURECODE_SCENARIO_END`;
const BLOCKED_RUN = { verdict: 'fail', output: `FAIL: blocked\n${marker({ verdict: 'BLOCKED', targetReached: true, targetCalls: 2, controlOk: true })}`, exitCode: 0, backend: 'docker' };
const GEN_OK = { canTest: true, testScript: 'console.log("FAIL: blocked")', runner: 'node', description: 'd', costUsd: 0.1 };
const AN_BLOCKED = { verdict: 'UNPROVEN', scenarioVerdict: 'BLOCKED', targetReached: true, reason: '403 for user B', shouldRetry: false, failureLine: null, costUsd: 0.02 };

let workspace: string;

function baseInput(cells: GridCell[], scenarios: Scenario[], extra: Partial<AssuranceAttackTestInput> = {}): AssuranceAttackTestInput {
    return {
        ctx: { apiUrl: 'http://api', apiToken: 't', workspaceRoot: workspace },
        runId: 'run-1',
        target: { filePath: 'src/target.js', language: 'javascript', fileContent: Array.from({ length: 20 }, (_, i) => `// ${i + 1}`).join('\n') },
        cells,
        scenarios,
        ...extra,
    };
}

beforeEach(() => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'deep-approval-'));
    for (const m of Object.values(mocks)) m.mockReset();
    mocks.detectRuntime.mockReturnValue({ runtime: 'node', runner: 'node', canRunLocally: true, framework: null, frameworkVersion: null, testabilityTier: 1, packageManager: 'npm', depsInstalled: true });
    mocks.detectSandbox.mockReturnValue({ name: 'docker' });
    mocks.consumeSessionApproval.mockReturnValue(true);
    mocks.getRelatedFilesForFile.mockResolvedValue([]);
});

afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
});

describe('deep scan approval reuse', () => {
    it('DEEP_SANDBOX_RUN_CAP is 60', () => {
        expect(DEEP_SANDBOX_RUN_CAP).toBe(60);
    });

    it('uses deep-scan approval when deepScanRunId is provided, skips its own prompt', async () => {
        mocks.getSessionApproval.mockReturnValue({ granted: true, state: 'granted', reason: 'User approved' });
        mocks.runLocalTest.mockResolvedValue(BLOCKED_RUN);
        mocks.postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return GEN_OK;
            if (p === '/verify/analyze') return AN_BLOCKED;
            throw new Error(`unexpected ${p}`);
        });

        const cells = [cell('c1', 5, 'safe', 'traced')];
        const scenarios = [scen('s1', 'c1')];
        const out = await runAssuranceAttackTests(baseInput(cells, scenarios, { deepScanRunId: 'deep-123' }));

        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
        expect(mocks.getSessionApproval).toHaveBeenCalledWith('deep-123');
        expect(out.approval.granted).toBe(true);
        expect(out.scenarioUpdates[0].test).toBe('blocked');
        expect(mocks.consumeSessionApproval).toHaveBeenCalledWith('deep-123');
        expect(mocks.revokeSessionApproval).not.toHaveBeenCalledWith('run-1');
    });

    it('skips all tests when deep-scan approval was not granted', async () => {
        mocks.getSessionApproval.mockReturnValue({ granted: false, state: 'timeout', reason: 'approval timed out' });

        const cells = [cell('c1', 5, 'safe', 'traced'), cell('c2', 4, 'safe')];
        const scenarios = [scen('s1', 'c1'), scen('s2', 'c2')];
        const out = await runAssuranceAttackTests(baseInput(cells, scenarios, { deepScanRunId: 'deep-denied' }));

        expect(out.approval).toEqual({ granted: false, reason: 'approval timed out' });
        expect(out.scenarioUpdates.every(u => u.test === 'skipped')).toBe(true);
        expect(mocks.postJson).not.toHaveBeenCalled();
        expect(mocks.runLocalTest).not.toHaveBeenCalled();
    });

    it('without deepScanRunId, falls back to its own approval prompt', async () => {
        mocks.requestSessionApproval.mockResolvedValue({ granted: true, state: 'granted', reason: 'User approved' });
        mocks.runLocalTest.mockResolvedValue(BLOCKED_RUN);
        mocks.postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return GEN_OK;
            if (p === '/verify/analyze') return AN_BLOCKED;
            throw new Error(`unexpected ${p}`);
        });

        const cells = [cell('c1', 5, 'safe', 'traced')];
        const scenarios = [scen('s1', 'c1')];
        const out = await runAssuranceAttackTests(baseInput(cells, scenarios));

        expect(mocks.requestSessionApproval).toHaveBeenCalledTimes(1);
        expect(mocks.getSessionApproval).not.toHaveBeenCalled();
        expect(out.approval.granted).toBe(true);
    });

    it('pending → approved later: attack tests run after the approval resolves as granted', async () => {
        let resolveApproval!: (v: any) => void;
        const approvalPromise = new Promise<any>(r => { resolveApproval = r; });
        mocks.getSessionApproval.mockReturnValue({ granted: true, state: 'granted', reason: 'User approved', remaining: 60 });
        mocks.runLocalTest.mockResolvedValue(BLOCKED_RUN);
        mocks.postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return GEN_OK;
            if (p === '/verify/analyze') return AN_BLOCKED;
            throw new Error(`unexpected ${p}`);
        });

        const cells = [cell('c1', 5, 'safe', 'traced')];
        const scenarios = [scen('s1', 'c1')];
        const out = await runAssuranceAttackTests(baseInput(cells, scenarios, { deepScanRunId: 'deep-pending' }));

        expect(out.approval.granted).toBe(true);
        expect(out.scenarioUpdates[0].test).toBe('blocked');
        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
    });

    it('pending → timeout: "not tested" when deep-scan approval timed out', async () => {
        mocks.getSessionApproval.mockReturnValue({ granted: false, state: 'timeout', reason: 'approval timed out after 600s' });

        const cells = [cell('c1', 5, 'safe', 'traced')];
        const scenarios = [scen('s1', 'c1')];
        const out = await runAssuranceAttackTests(baseInput(cells, scenarios, { deepScanRunId: 'deep-timeout' }));

        expect(out.approval.granted).toBe(false);
        expect(out.approval.reason).toContain('timed out');
        expect(out.scenarioUpdates[0].test).toBe('skipped');
        expect(mocks.postJson).not.toHaveBeenCalled();
        expect(mocks.runLocalTest).not.toHaveBeenCalled();
    });

    it('denied → no wait, all tests skipped immediately', async () => {
        mocks.getSessionApproval.mockReturnValue({ granted: false, state: 'denied', reason: 'Attack test skipped: approval was denied.' });

        const cells = [cell('c1', 5, 'safe', 'traced'), cell('c2', 4, 'safe')];
        const scenarios = [scen('s1', 'c1'), scen('s2', 'c2')];
        const out = await runAssuranceAttackTests(baseInput(cells, scenarios, { deepScanRunId: 'deep-nope' }));

        expect(out.approval).toEqual({ granted: false, reason: 'Attack test skipped: approval was denied.' });
        expect(out.scenarioUpdates.every(u => u.test === 'skipped')).toBe(true);
        expect(out.scenarioUpdates[0].testNote).toContain('denied');
        expect(mocks.postJson).not.toHaveBeenCalled();
        expect(mocks.runLocalTest).not.toHaveBeenCalled();
        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
    });
});
