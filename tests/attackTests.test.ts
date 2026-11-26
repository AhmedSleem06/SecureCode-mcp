import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

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
    selectAssuranceScenarios,
    decideScenarioVerdict,
    parseScenarioMarker,
    type AssuranceAttackTestInput,
} from '../src/assurance/attackTests';
import type { GridCell, Scenario } from '../src/attack/agentScanProtocol';

function cell(id: string, risk: GridCell['risk'], status: GridCell['status'], closure?: GridCell['closure'], extra: Partial<GridCell> = {}): GridCell {
    return { id, entryId: 'e1', inputId: 'i1', targetId: 't1', attackType: 'idor', title: `cell ${id}`, risk, source: 'seed', status, ...(closure ? { closure } : {}), ...extra };
}
function scen(id: string, cellId: string, risk: Scenario['risk'] = 3, extra: Partial<Scenario> = {}): Scenario {
    return { id, cellId, actor: 'user B', preconditions: ['A owns doc 1'], steps: ['GET /doc/1 as B'], payloads: ['1'], expectSecure: 'B is refused', risk, ...extra };
}
const marker = (o: Record<string, unknown>) => `SECURECODE_SCENARIO_RESULT:${JSON.stringify(o)}:SECURECODE_SCENARIO_END`;
const BLOCKED_RUN = { verdict: 'fail', output: `FAIL: blocked — 403\n${marker({ verdict: 'BLOCKED', targetReached: true, targetCalls: 2, controlOk: true })}`, exitCode: 0, backend: 'docker' };
const EXPLOITED_RUN = { verdict: 'pass', output: `PASS: exploited — got doc\n${marker({ verdict: 'EXPLOITED', targetReached: true, targetCalls: 1, controlOk: true })}`, exitCode: 0, backend: 'docker' };
const UNREACHED_RUN = { verdict: 'fail', output: `FAIL: blocked\n${marker({ verdict: 'BLOCKED', targetReached: false, targetCalls: 0 })}`, exitCode: 0, backend: 'docker' };
const CRASH_RUN = { verdict: 'error', output: 'Error: Cannot find module ../src/targt.js', exitCode: 1, backend: 'docker' };

const GEN_OK = { canTest: true, testScript: 'console.log("FAIL: blocked")', runner: 'node', description: 'd', costUsd: 0.1 };
const AN = {
    blocked: { verdict: 'UNPROVEN', scenarioVerdict: 'BLOCKED', targetReached: true, reason: '403 for user B', shouldRetry: false, failureLine: null, costUsd: 0.02 },
    exploited: { verdict: 'PROVEN', scenarioVerdict: 'EXPLOITED', targetReached: true, reason: 'B read doc 1', shouldRetry: false, failureLine: 7, costUsd: 0.02 },
};

let workspace: string;

function setupApi(analyzeQueue: unknown[], genQueue: unknown[] = []) {
    mocks.postJson.mockImplementation(async (p: string) => {
        if (p === '/verify/generate') return genQueue.length > 0 ? genQueue.shift() : GEN_OK;
        if (p === '/verify/analyze') return analyzeQueue.shift();
        throw new Error(`unexpected ${p}`);
    });
}

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
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'attack-tests-'));
    for (const m of Object.values(mocks)) m.mockReset();
    mocks.detectRuntime.mockReturnValue({ runtime: 'node', runner: 'node', canRunLocally: true, framework: null, frameworkVersion: null, testabilityTier: 1, packageManager: 'npm', depsInstalled: true });
    mocks.detectSandbox.mockReturnValue({ name: 'docker' });
    mocks.requestSessionApproval.mockResolvedValue({ granted: true, state: 'granted', reason: 'User approved' });
    mocks.consumeSessionApproval.mockReturnValue(true);
    mocks.getSessionApproval.mockReturnValue({ granted: false, reason: 'Attack test skipped: approval for this scan covered 1 attack test(s) and all were used.' });
    mocks.getRelatedFilesForFile.mockResolvedValue([]);
});

afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
});

describe('selectAssuranceScenarios', () => {
    it('picks safe risk>=3 cells and depends/reasoning risk>=4 cells, highest risk first, breadth-first, max 3 per cell', () => {
        const cells = [
            cell('c1', 3, 'safe', 'traced'),
            cell('c2', 5, 'safe', 'traced'),
            cell('c3', 2, 'safe', 'reasoning'),
            cell('c4', 4, 'depends'),
            cell('c5', 3, 'depends'),
            cell('c6', 5, 'safe', 'tested'),
            cell('c7', 5, 'vulnerable', 'traced'),
            cell('c8', 4, 'untestable', 'reasoning'),
            cell('c9', 5, 'open'),
        ];
        const scenarios = [
            scen('s1', 'c1'), scen('s2', 'c2', 3), scen('s3', 'c2', 5), scen('s4', 'c2'), scen('s5', 'c2'),
            scen('s6', 'c3'), scen('s7', 'c4'), scen('s8', 'c5'), scen('s9', 'c6'), scen('s10', 'c7'), scen('s11', 'c8'),
            scen('s12', 'c9'), scen('s13', 'c1', 3, { test: 'blocked' }), scen('s14', 'c1', 3, { test: 'skipped' }),
        ];
        const picked = selectAssuranceScenarios(cells, scenarios, 20).map((p) => p.scenario.id);
        expect(picked).toEqual(['s3', 's7', 's11', 's1', 's2', 's14', 's4']);
        expect(picked.filter((id) => ['s2', 's3', 's4', 's5'].includes(id))).toHaveLength(3);
        expect(selectAssuranceScenarios(cells, scenarios, 2).map((p) => p.scenario.id)).toEqual(['s3', 's7']);
    });

    it('returns nothing when no cell qualifies', () => {
        expect(selectAssuranceScenarios([cell('c1', 2, 'safe', 'traced')], [scen('s1', 'c1')])).toEqual([]);
    });
});

describe('decideScenarioVerdict', () => {
    it('accepts BLOCKED only with an agreeing reaching marker and a FAIL run', () => {
        expect(decideScenarioVerdict(AN.blocked as any, BLOCKED_RUN as any).verdict).toBe('BLOCKED');
        expect(decideScenarioVerdict(AN.blocked as any, UNREACHED_RUN as any)).toMatchObject({ verdict: 'UNTESTABLE', retryable: true });
        expect(decideScenarioVerdict(AN.blocked as any, { verdict: 'fail', output: 'FAIL: blocked' } as any).verdict).toBe('UNTESTABLE');
        expect(decideScenarioVerdict(AN.blocked as any, EXPLOITED_RUN as any).verdict).toBe('UNTESTABLE');
        expect(decideScenarioVerdict({ ...AN.blocked, targetReached: false } as any, BLOCKED_RUN as any).verdict).toBe('UNTESTABLE');
        expect(decideScenarioVerdict(AN.exploited as any, EXPLOITED_RUN as any).verdict).toBe('EXPLOITED');
    });

    it('maps legacy analyzer verdicts when scenarioVerdict is absent', () => {
        expect(decideScenarioVerdict({ verdict: 'UNPROVEN', reason: 'r', shouldRetry: false } as any, BLOCKED_RUN as any).verdict).toBe('BLOCKED');
        expect(decideScenarioVerdict({ verdict: 'INCONCLUSIVE', reason: 'r', shouldRetry: false } as any, BLOCKED_RUN as any)).toMatchObject({ verdict: 'UNTESTABLE', retryable: false });
    });

    it('parses the scenario marker', () => {
        expect(parseScenarioMarker(BLOCKED_RUN.output)).toMatchObject({ found: true, verdict: 'BLOCKED', targetReached: true, controlOk: true });
        expect(parseScenarioMarker('nothing').found).toBe(false);
    });
});

describe('runAssuranceAttackTests', () => {
    it('asks one approval for the batch, maps verdicts to scenario/cell updates and findings, writes artifacts', async () => {
        const cells = [cell('c1', 5, 'safe', 'traced', { evidenceLines: [4, 6] }), cell('c2', 4, 'safe', 'reasoning'), cell('c3', 4, 'depends')];
        const scenarios = [scen('s1', 'c1'), scen('s2', 'c2'), scen('s3', 'c3')];
        mocks.runLocalTest
            .mockResolvedValueOnce(BLOCKED_RUN)
            .mockResolvedValueOnce({ verdict: 'fail', output: `FAIL: untestable — needs a real DB\n${marker({ verdict: 'UNTESTABLE', targetReached: false })}`, exitCode: 0 })
            .mockResolvedValueOnce(EXPLOITED_RUN);
        setupApi([AN.blocked, { verdict: 'INCONCLUSIVE', scenarioVerdict: 'UNTESTABLE', targetReached: false, reason: 'needs a real database', shouldRetry: false, costUsd: 0.02 }, AN.exploited]);
        const progress = vi.fn();

        const out = await runAssuranceAttackTests(baseInput(cells, scenarios, { progress }));

        expect(mocks.requestSessionApproval).toHaveBeenCalledTimes(1);
        const [scope, summary] = mocks.requestSessionApproval.mock.calls[0];
        expect(scope).toMatchObject({ runId: 'run-1', tool: 'assurance-tests', maxTests: 3 });
        expect(summary).toContain('src/target.js');
        expect(summary).toContain('Run up to 3 attack tests for src/target.js in the Docker sandbox');
        expect(mocks.consumeSessionApproval).toHaveBeenCalledTimes(3);
        expect(mocks.revokeSessionApproval).toHaveBeenCalledWith('run-1');
        expect(out.approval).toEqual({ granted: true, reason: 'User approved' });

        expect(out.scenarioUpdates.map((u) => [u.scenarioId, u.test])).toEqual([['s1', 'blocked'], ['s3', 'untestable'], ['s2', 'exploited']]);
        expect(out.cellUpdates).toEqual([
            expect.objectContaining({ cellId: 'c1', status: 'safe', closure: 'tested', evidenceLines: [4, 6] }),
            expect.objectContaining({ cellId: 'c2', status: 'vulnerable', closure: 'tested', evidenceLines: [7] }),
        ]);
        expect(out.exploitedFindings).toEqual([
            expect.objectContaining({ cellId: 'c2', scenarioId: 's2', type: 'idor', line: 7, title: 'cell c2' }),
        ]);
        expect(out.exploitedFindings[0].artifactPath).toMatch(/^\.securecode\/proofs\/assurance-run-1-s2-/);
        expect(out.costUsd).toBeCloseTo(0.36, 5);
        expect(progress).toHaveBeenCalledWith(expect.stringContaining('Attack test 1/3'));

        const genBody = mocks.postJson.mock.calls.find((c) => c[0] === '/verify/generate')![1];
        expect(genBody).toMatchObject({ mode: 'expect-blocked', scenario: { id: 's1', expectSecure: 'B is refused' }, runId: 'run-1', line: 4, lineEnd: 6, vulnerabilityType: 'idor', sandboxBackend: 'docker' });
        const anBody = mocks.postJson.mock.calls.find((c) => c[0] === '/verify/analyze')![1];
        expect(anBody).toMatchObject({ mode: 'expect-blocked', scenario: { id: 's1' }, filePath: 'src/target.js' });
        expect(anBody.targetCode).toContain('// 1');

        const files = fs.readdirSync(path.join(workspace, '.securecode', 'proofs')).filter((f) => f.endsWith('.json'));
        expect(files).toHaveLength(3);
        const art = JSON.parse(fs.readFileSync(path.join(workspace, out.scenarioUpdates[0].artifactPath!), 'utf8'));
        expect(art.phase).toBe('assurance');
        expect(art.scenario).toMatchObject({ id: 's1', cellId: 'c1' });
        expect(art.finalVerdict).toBe('BLOCKED');
        expect(art.rounds[0].verdict).toBe('fail:BLOCKED');
    });

    it('untestable result only closes a cell that has no better closure', async () => {
        const cells = [cell('c1', 5, 'safe', 'traced'), cell('c2', 4, 'untestable', 'reasoning')];
        mocks.runLocalTest.mockResolvedValue({ verdict: 'fail', output: `FAIL: untestable\n${marker({ verdict: 'UNTESTABLE', targetReached: false })}`, exitCode: 0 });
        const untestable = { verdict: 'INCONCLUSIVE', scenarioVerdict: 'UNTESTABLE', targetReached: false, reason: 'needs browser', shouldRetry: false };
        setupApi([untestable, untestable]);
        const out = await runAssuranceAttackTests(baseInput(cells, [scen('s1', 'c1'), scen('s2', 'c2')]));
        expect(out.scenarioUpdates.map((u) => u.test)).toEqual(['untestable', 'untestable']);
        expect(out.cellUpdates).toEqual([]);

        const fresh = [cell('c3', 5, 'safe')];
        setupApi([untestable]);
        const out2 = await runAssuranceAttackTests(baseInput(fresh, [scen('s3', 'c3')]));
        expect(out2.cellUpdates).toEqual([expect.objectContaining({ cellId: 'c3', status: 'untestable', closure: 'untestable' })]);
    });

    it('treats BLOCKED that never reached the target as untestable, after one retry', async () => {
        mocks.runLocalTest.mockResolvedValue(UNREACHED_RUN);
        setupApi([AN.blocked, AN.blocked]);
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe', 'traced')], [scen('s1', 'c1')]));
        expect(out.scenarioUpdates[0].test).toBe('untestable');
        expect(out.scenarioUpdates[0].testNote).toContain('did not reach the real target code');
        expect(mocks.postJson.mock.calls.filter((c) => c[0] === '/verify/generate')).toHaveLength(2);
        expect(out.cellUpdates).toEqual([]);
    });

    it('retries once on a harness crash without analysing it, and not after a definitive verdict', async () => {
        mocks.runLocalTest.mockResolvedValueOnce(CRASH_RUN).mockResolvedValueOnce(BLOCKED_RUN).mockResolvedValueOnce(BLOCKED_RUN);
        setupApi([AN.blocked, AN.blocked]);
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe', 'traced'), cell('c2', 5, 'safe', 'traced')], [scen('s1', 'c1'), scen('s2', 'c2')]));
        expect(out.scenarioUpdates.map((u) => u.test)).toEqual(['blocked', 'blocked']);
        const gens = mocks.postJson.mock.calls.filter((c) => c[0] === '/verify/generate');
        expect(gens).toHaveLength(3);
        expect(gens[1][1].previousErrors[0]).toContain('Cannot find module');
        expect(gens[2][1].previousErrors).toBeUndefined();
        expect(mocks.postJson.mock.calls.filter((c) => c[0] === '/verify/analyze')).toHaveLength(2);
    });

    it('a crash on both attempts is untestable', async () => {
        mocks.runLocalTest.mockResolvedValue(CRASH_RUN);
        setupApi([]);
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe')], [scen('s1', 'c1')]));
        expect(out.scenarioUpdates[0]).toMatchObject({ test: 'untestable' });
        expect(out.scenarioUpdates[0].testNote).toContain('Cannot find module');
    });

    it('approval denied → every scenario skipped with the reason, no API calls', async () => {
        mocks.requestSessionApproval.mockResolvedValue({ granted: false, state: 'denied', reason: 'Attack test skipped: approval was denied.' });
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe', 'traced')], [scen('s1', 'c1'), scen('s2', 'c1')]));
        expect(out.approval).toEqual({ granted: false, reason: 'Attack test skipped: approval was denied.' });
        expect(out.scenarioUpdates).toEqual([
            { scenarioId: 's1', test: 'skipped', testNote: 'Attack test skipped: approval was denied.', backend: 'docker', isolation: 'full' },
            { scenarioId: 's2', test: 'skipped', testNote: 'Attack test skipped: approval was denied.', backend: 'docker', isolation: 'full' },
        ]);
        expect(out.cellUpdates).toEqual([]);
        expect(mocks.postJson).not.toHaveBeenCalled();
        expect(mocks.revokeSessionApproval).toHaveBeenCalledWith('run-1');
    });

    it('approval exhausted → remaining scenarios skipped with the broker reason', async () => {
        mocks.consumeSessionApproval.mockReturnValueOnce(true).mockReturnValue(false);
        mocks.runLocalTest.mockResolvedValue(BLOCKED_RUN);
        setupApi([AN.blocked]);
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe', 'traced'), cell('c2', 4, 'safe', 'traced')], [scen('s1', 'c1'), scen('s2', 'c2')]));
        expect(out.scenarioUpdates.map((u) => u.test)).toEqual(['blocked', 'skipped']);
        expect(out.scenarioUpdates[1].testNote).toContain('all were used');
        expect(out.cellUpdates.map((u) => u.cellId)).toEqual(['c1']);
    });

    it('abort stops after the current test and skips the rest', async () => {
        const ac = new AbortController();
        mocks.runLocalTest.mockImplementation(async () => { ac.abort(); return BLOCKED_RUN; });
        setupApi([AN.blocked]);
        const out = await runAssuranceAttackTests(baseInput(
            [cell('c1', 5, 'safe', 'traced'), cell('c2', 5, 'safe', 'traced'), cell('c3', 5, 'safe', 'traced')],
            [scen('s1', 'c1'), scen('s2', 'c2'), scen('s3', 'c3')],
            { signal: ac.signal },
        ));
        expect(out.scenarioUpdates.map((u) => u.test)).toEqual(['blocked', 'skipped', 'skipped']);
        expect(out.scenarioUpdates[1].testNote).toMatch(/Cancelled/);
        expect(mocks.runLocalTest).toHaveBeenCalledTimes(1);
        expect(mocks.revokeSessionApproval).toHaveBeenCalled();
    });

    it('already-aborted signal → no approval prompt', async () => {
        const ac = new AbortController();
        ac.abort();
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe')], [scen('s1', 'c1')], { signal: ac.signal }));
        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
        expect(out.scenarioUpdates[0].test).toBe('skipped');
    });

    it('target that cannot run locally → untestable without asking for approval', async () => {
        mocks.detectRuntime.mockReturnValue({ runtime: 'node', runner: 'node', canRunLocally: false, skipReason: 'react-native needs Metro' });
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe')], [scen('s1', 'c1')]));
        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
        expect(out.approval.granted).toBe(false);
        expect(out.scenarioUpdates[0]).toMatchObject({ test: 'untestable' });
        expect(out.cellUpdates).toEqual([expect.objectContaining({ cellId: 'c1', status: 'untestable', closure: 'untestable' })]);
    });

    it('no sandbox → skipped without asking for approval', async () => {
        mocks.detectSandbox.mockReturnValue(null);
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe')], [scen('s1', 'c1')]));
        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
        expect(out.scenarioUpdates[0].test).toBe('skipped');
        expect(out.cellUpdates).toEqual([]);
    });

    it('scan budget exhausted → current and remaining scenarios skipped', async () => {
        mocks.postJson.mockRejectedValue(Object.assign(new Error('budget'), { apiCode: 'AGENT_SCAN_BUDGET_EXHAUSTED' }));
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe'), cell('c2', 5, 'safe')], [scen('s1', 'c1'), scen('s2', 'c2')]));
        expect(out.scenarioUpdates.map((u) => u.test)).toEqual(['skipped', 'skipped']);
        expect(out.scenarioUpdates[1].testNote).toContain('budget');
        expect(mocks.postJson).toHaveBeenCalledTimes(1);
    });

    it('canTest:false is untestable with the generator reason and no retry', async () => {
        setupApi([], [{ canTest: false, skipReason: 'Effect runtime required', costUsd: 0.05 }]);
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 5, 'safe')], [scen('s1', 'c1')]));
        expect(out.scenarioUpdates[0]).toMatchObject({ test: 'untestable' });
        expect(out.scenarioUpdates[0].testNote).toContain('Effect runtime required');
        expect(out.scenarioUpdates[0].artifactPath).toBeUndefined();
        expect(out.costUsd).toBeCloseTo(0.05, 5);
        expect(mocks.runLocalTest).not.toHaveBeenCalled();
    });

    it('nothing eligible → no approval, empty outcome', async () => {
        const out = await runAssuranceAttackTests(baseInput([cell('c1', 2, 'safe')], [scen('s1', 'c1')]));
        expect(mocks.requestSessionApproval).not.toHaveBeenCalled();
        expect(out).toMatchObject({ scenarioUpdates: [], cellUpdates: [], exploitedFindings: [], costUsd: 0, approval: { granted: false } });
    });
});
