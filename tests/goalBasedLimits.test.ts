import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
    selectAssuranceScenarios,
    DEEP_SANDBOX_RUN_CAP,
    ASSURANCE_SANDBOX_TIME_BUDGET_MS,
    ASSURANCE_AI_COST_BUDGET_USD,
    ASSURANCE_PER_TEST_COST_ESTIMATE_USD,
} from '../src/assurance/attackTests';
import { computeFailureSignature, runVerifyLoop } from '../src/attack/verifyLoop';
import {
    evaluateFinishGate,
    newFinishLoopTracker,
    trackFinishRejection,
    finishLoopEscaped,
    FINISH_LOOP_ESCAPE_THRESHOLD,
} from '../src/attack/finishGate';
import { createScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { InvestigationState } from '../src/attack/investigationState';
import type { GridCell, Scenario } from '../src/attack/agentScanProtocol';
import type { LocalTestResult } from '../src/utils/localTestRunner';

function cell(id: string, risk: GridCell['risk'], status: GridCell['status'], closure?: GridCell['closure'], extra: Partial<GridCell> = {}): GridCell {
    return { id, entryId: 'e1', inputId: 'i1', targetId: 't1', attackType: 'idor', title: `cell ${id}`, risk, source: 'seed', status, ...(closure ? { closure } : {}), ...extra };
}
function scen(id: string, cellId: string, risk: Scenario['risk'] = 3, extra: Partial<Scenario> = {}): Scenario {
    return { id, cellId, actor: 'user B', preconditions: ['A owns doc 1'], steps: ['GET /doc/1 as B'], payloads: ['1'], expectSecure: 'B is refused', risk, ...extra };
}

describe('selectAssuranceScenarios — goal-based selection', () => {
    it('selects risk >= 4 cells first, then risk 3, then second scenarios for risk >= 4', () => {
        const cells = [
            cell('c1', 3, 'safe', 'traced'),
            cell('c2', 5, 'safe', 'traced'),
            cell('c3', 4, 'depends'),
            cell('c4', 3, 'safe', 'reasoning'),
        ];
        const scenarios = [
            scen('s1a', 'c1', 3), scen('s1b', 'c1', 2),
            scen('s2a', 'c2', 5), scen('s2b', 'c2', 4),
            scen('s3a', 'c3', 4), scen('s3b', 'c3', 3),
            scen('s4a', 'c4', 3),
        ];
        const picked = selectAssuranceScenarios(cells, scenarios, 60);
        const ids = picked.map(p => p.scenario.id);
        const risk4PlusFirst = ids.indexOf('s2a');
        const risk3First = ids.indexOf('s1a');
        const risk4Second = ids.indexOf('s2b');
        expect(risk4PlusFirst).toBeLessThan(risk3First);
        expect(risk3First).toBeLessThan(risk4Second);
        expect(ids).toContain('s2a');
        expect(ids).toContain('s3a');
        expect(ids).toContain('s1a');
        expect(ids).toContain('s4a');
        expect(ids).toContain('s2b');
        expect(ids).toContain('s3b');
    });

    it('respects the DEEP_SANDBOX_RUN_CAP hard cap', () => {
        expect(DEEP_SANDBOX_RUN_CAP).toBe(60);
        const cells: GridCell[] = [];
        const scenarios: Scenario[] = [];
        for (let i = 0; i < 80; i++) {
            const c = cell(`c${i}`, 5, 'safe', 'traced');
            cells.push(c);
            scenarios.push(scen(`s${i}`, `c${i}`, 5));
        }
        const picked = selectAssuranceScenarios(cells, scenarios, 999);
        expect(picked).toHaveLength(DEEP_SANDBOX_RUN_CAP);
    });

    it('every risk >= 4 cell gets a scenario before any risk 3 cell', () => {
        const cells = [
            cell('r3a', 3, 'safe', 'traced'),
            cell('r3b', 3, 'safe', 'traced'),
            cell('r4', 4, 'safe', 'reasoning'),
            cell('r5', 5, 'safe', 'traced'),
        ];
        const scenarios = [
            scen('s-r3a', 'r3a'), scen('s-r3b', 'r3b'),
            scen('s-r4', 'r4'), scen('s-r5', 'r5'),
        ];
        const picked = selectAssuranceScenarios(cells, scenarios, 10);
        const ids = picked.map(p => p.scenario.id);
        expect(ids.indexOf('s-r5')).toBeLessThan(ids.indexOf('s-r3a'));
        expect(ids.indexOf('s-r4')).toBeLessThan(ids.indexOf('s-r3a'));
    });

    it('hardening scenarios are excluded', () => {
        const cells = [cell('c1', 5, 'safe', 'traced')];
        const scenarios = [
            scen('s1', 'c1', 5, { classification: 'hardening' } as any),
            scen('s2', 'c1', 4),
        ];
        const picked = selectAssuranceScenarios(cells, scenarios, 10);
        expect(picked.map(p => p.scenario.id)).toEqual(['s2']);
    });

    it('cells not tested due to budget have no scenario (untested by budget)', () => {
        const cells = Array.from({ length: 70 }, (_, i) => cell(`c${i}`, 5, 'safe', 'traced'));
        const scenarios = cells.map((c, i) => scen(`s${i}`, c.id, 5));
        const picked = selectAssuranceScenarios(cells, scenarios, 10);
        expect(picked).toHaveLength(10);
        const selectedIds = new Set(picked.map(p => p.cell.id));
        const notTested = cells.filter(c => !selectedIds.has(c.id));
        expect(notTested.length).toBe(60);
    });
});

describe('selectAssuranceScenarios — constants', () => {
    it('exports budget constants', () => {
        expect(ASSURANCE_SANDBOX_TIME_BUDGET_MS).toBe(15 * 60 * 1000);
        expect(ASSURANCE_AI_COST_BUDGET_USD).toBe(2.00);
        expect(ASSURANCE_PER_TEST_COST_ESTIMATE_USD).toBe(0.10);
    });
});

describe('computeFailureSignature', () => {
    it('blocked → "blocked"', () => {
        const result: LocalTestResult = { verdict: 'blocked', output: 'eval() not allowed', exitCode: -1 };
        expect(computeFailureSignature(result)).toBe('blocked');
    });

    it('timeout → "timeout"', () => {
        const result: LocalTestResult = { verdict: 'timeout', output: 'timed out', exitCode: -1 };
        expect(computeFailureSignature(result)).toBe('timeout');
    });

    it('error with import problem → "import-error:..."', () => {
        const result: LocalTestResult = { verdict: 'error', output: 'Cannot find module ../src/target.js\nat ...', exitCode: 1 };
        expect(computeFailureSignature(result)).toMatch(/^import-error:/);
    });

    it('error with mock problem → "mock-error:..."', () => {
        const result: LocalTestResult = { verdict: 'error', output: 'mock is not a function\nat ...', exitCode: 1 };
        expect(computeFailureSignature(result)).toMatch(/^mock-error:/);
    });

    it('pass with invalid test → "invalid:..."', () => {
        const result: LocalTestResult = { verdict: 'pass', output: 'PASS', exitCode: 0 };
        const sig = computeFailureSignature(result, undefined, { valid: false, reason: 'proof baseline did not pass' });
        expect(sig).toContain('invalid');
        expect(sig).toContain('proof baseline');
    });

    it('same error on consecutive rounds produces the same signature', () => {
        const r1: LocalTestResult = { verdict: 'error', output: 'Cannot find module ../src/target.js\nat L1\nat L2', exitCode: 1 };
        const r2: LocalTestResult = { verdict: 'error', output: 'Cannot find module ../src/target.js\nat different line', exitCode: 1 };
        expect(computeFailureSignature(r1)).toBe(computeFailureSignature(r2));
    });
});

vi.mock('../src/utils/verificationSandbox', () => ({
    detectSandbox: () => ({ name: 'deno' }),
}));

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

vi.mock('../src/attack/mutationTest', () => ({
    runMutationTest: vi.fn().mockResolvedValue({ discriminating: true, mutatedVerdict: 'fail', reason: 'mutation test passed' }),
}));

import { runLocalTest } from '../src/utils/localTestRunner';
import type { ApiClient } from '../src/api/client';

describe('verifyLoop — same failure twice early stop', () => {
    beforeEach(() => {
        vi.mocked(runLocalTest).mockReset();
    });

    it('stops after two consecutive rounds with the same import error', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'error',
            output: 'Cannot find module ../src/target.js\nat stack',
            exitCode: 1,
        });

        const postJson = vi.fn();
        postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return { canTest: true, testScript: 'console.log("x")', runner: 'node', description: 'test' };
            if (p === '/verify/analyze') return { verdict: 'INCONCLUSIVE', reason: 'import error', shouldRetry: true };
            throw new Error(`unexpected ${p}`);
        });

        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const budget = defaultVerifyBudget();
        budget.maxRoundsPerFinding = 12;
        budget.maxLlmCalls = 100;
        const tracker = new VerifyBudgetTracker(budget);

        const result = await runVerifyLoop({
            finding: { type: 'xss', line: 5, evidence: 'innerHTML', why: 'tainted', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client: { postJson } as unknown as ApiClient,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toMatch(/same failure twice/);
        expect(result.reason).toContain('import-error');
        expect(result.roundsUsed).toBeLessThanOrEqual(4);
    });

    it('stops after two consecutive blocked rounds', async () => {
        vi.mocked(runLocalTest).mockResolvedValue({
            verdict: 'blocked',
            output: 'eval() not allowed',
            exitCode: -1,
        });

        const postJson = vi.fn();
        postJson.mockResolvedValue({
            canTest: true,
            testScript: 'eval("x")',
            runner: 'node',
            description: 'test',
        });

        const result = await runVerifyLoop({
            finding: { type: 'xss', line: 5, evidence: 'innerHTML', why: 'tainted', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client: { postJson } as unknown as ApiClient,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toMatch(/same failure twice.*blocked/);
        expect(result.roundsUsed).toBe(2);
    });

    it('12 rounds ceiling still applies when failures differ', async () => {
        let callCount = 0;
        vi.mocked(runLocalTest).mockImplementation(async () => {
            callCount++;
            return { verdict: 'timeout', output: `timed out run ${callCount}`, exitCode: -1 };
        });

        const postJson = vi.fn();
        postJson.mockImplementation(async (p: string) => {
            if (p === '/verify/generate') return { canTest: true, testScript: 'x', runner: 'node', description: 't' };
            return { verdict: 'INCONCLUSIVE', reason: `r${callCount}`, shouldRetry: true };
        });

        const { VerifyBudgetTracker, defaultVerifyBudget } = await import('../src/attack/agentScanProtocol');
        const budget = defaultVerifyBudget();
        budget.maxRoundsPerFinding = 12;
        budget.maxLlmCalls = 200;
        budget.maxWallClockMs = 600_000;
        const tracker = new VerifyBudgetTracker(budget);

        const result = await runVerifyLoop({
            finding: { type: 'xss', line: 5, evidence: 'innerHTML', why: 'tainted', severity: 'high' },
            filePath: 'src/foo.ts',
            code: 'const x = 1;',
            relatedFiles: [],
            workspaceRoot: '/tmp/workspace',
            language: 'javascript',
            client: { postJson } as unknown as ApiClient,
            budgetTracker: tracker,
        });

        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('same failure twice');
        expect(result.roundsUsed).toBe(2);
    });
});

describe('finishGate — evidence mode done rules', () => {
    const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
    const target = { filePath: 'test.ts', language: 'typescript', fileContent: 'export function handler() {}' };
    const finishProposal: any = { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' };

    function makeInput(overrides?: Partial<any>) {
        const state = createScanRunState('run-1', target, budget);
        return {
            proposal: finishProposal,
            state,
            evidence: new EvidenceLedger(),
            workItems: new WorkItemQueue(),
            handlers: new HandlerInventory(),
            candidates: new CandidateStore(),
            investigation: new InvestigationState(),
            scheduler: { kind: 'finish-ready' as const, reason: 'no work' },
            target: { filePath: 'test.ts' },
            ...overrides,
        };
    }

    it('rejects finish when connected auth file was not read (first rejection)', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [
                    { file: 'middleware/auth.ts', relation: 'middleware', reason: 'authentication middleware' },
                ],
                gridCells: [],
                doneRuleRejections: 0,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code === 'connected-file-unread')).toBe(true);
    });

    it('accepts finish on second rejection for same connected files (as coverage gaps)', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [
                    { file: 'middleware/auth.ts', relation: 'middleware', reason: 'authentication middleware' },
                ],
                gridCells: [],
                doneRuleRejections: 1,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code === 'connected-file-unread')).toBe(false);
        expect(result.coverageGaps?.some(g => g.title.includes('middleware/auth.ts'))).toBe(true);
    });

    it('rejects finish when risk >= 4 cell has no evidence lines (first rejection)', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [],
                gridCells: [cell('c1', 5, 'safe', 'traced'), cell('c2', 3, 'safe')],
                doneRuleRejections: 0,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code === 'high-risk-cell-no-evidence')).toBe(true);
        const highRiskReasons = result.reasons.filter(r => r.code === 'high-risk-cell-no-evidence');
        expect(highRiskReasons).toHaveLength(1);
        expect(highRiskReasons[0].description).toContain('c1');
    });

    it('does not reject for risk >= 4 cells that have evidence lines', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [],
                gridCells: [cell('c1', 5, 'safe', 'traced', { evidenceLines: [10, 20] })],
                doneRuleRejections: 0,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code === 'high-risk-cell-no-evidence')).toBe(false);
    });

    it('does not block for non-auth/data-store connected files', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [
                    { file: 'utils/format.ts', relation: 'imports', reason: 'string formatting utility' },
                ],
                gridCells: [],
                doneRuleRejections: 0,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code === 'connected-file-unread')).toBe(false);
    });

    it('passes when connected auth file was already read', () => {
        const investigation = new InvestigationState();
        investigation.recordRead('middleware/auth.ts', 1, 50, 50);
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [
                    { file: 'middleware/auth.ts', relation: 'middleware', reason: 'authentication middleware' },
                ],
                gridCells: [],
                doneRuleRejections: 0,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code === 'connected-file-unread')).toBe(false);
    });
});

describe('finishGate — no forced_incomplete regression', () => {
    const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
    const target = { filePath: 'test.ts', language: 'typescript', fileContent: 'export function handler() {}' };
    const finishProposal: any = { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' };

    function makeInput(overrides?: Partial<any>) {
        const state = createScanRunState('run-1', target, budget);
        return {
            proposal: finishProposal,
            state,
            evidence: new EvidenceLedger(),
            workItems: new WorkItemQueue(),
            handlers: new HandlerInventory(),
            candidates: new CandidateStore(),
            investigation: new InvestigationState(),
            scheduler: { kind: 'finish-ready' as const, reason: 'no work' },
            target: { filePath: 'test.ts' },
            ...overrides,
        };
    }

    it('FINISH_LOOP_ESCAPE_THRESHOLD still allows the loop to escape when done rules block repeatedly', () => {
        const finishLoop = newFinishLoopTracker();
        const reasons = [
            { code: 'connected-file-unread', description: 'x' },
            { code: 'high-risk-cell-no-evidence', description: 'y' },
        ];
        trackFinishRejection(finishLoop, reasons);
        expect(finishLoopEscaped(finishLoop)).toBe(false);
        trackFinishRejection(finishLoop, reasons);
        expect(finishLoopEscaped(finishLoop)).toBe(false);
        trackFinishRejection(finishLoop, reasons);
        expect(finishLoopEscaped(finishLoop)).toBe(false);
        trackFinishRejection(finishLoop, reasons);
        expect(finishLoopEscaped(finishLoop)).toBe(true);
    });

    it('done rules alone do NOT cause forced_incomplete on the second rejection — they become coverage gaps', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            gateMode: 'evidence',
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 100 }],
                targetRange: { start: 1, end: 100 },
                openLeadsRejectedOnce: false,
                connectedFiles: [
                    { file: 'db/models.ts', relation: 'imports', reason: 'database model' },
                ],
                gridCells: [cell('c1', 4, 'safe')],
                doneRuleRejections: 1,
            },
        });
        const result = evaluateFinishGate(input);
        const hasDoneRuleBlock = result.reasons.some(r =>
            r.code === 'connected-file-unread' || r.code === 'high-risk-cell-no-evidence');
        expect(hasDoneRuleBlock).toBe(false);
        expect(result.coverageGaps?.some(g => g.title.includes('db/models.ts'))).toBe(true);
        expect(result.coverageGaps?.some(g => g.title.includes('c1'))).toBe(true);
    });
});
