import { describe, it, expect } from 'vitest';
import { evaluateFinishGate, type FinishGateInput, type AssuranceGateInput } from '../src/attack/finishGate';
import { GridState, type GridGateProblems } from '../src/assurance/gridState';
import type { GridCell, AgentScanFinishAction } from '../src/attack/agentScanProtocol';

function cell(id: string, risk: GridCell['risk'], overrides: Partial<GridCell> = {}): GridCell {
    return { id, entryId: 'e1', inputId: 'i1', targetId: 's1', attackType: 'idor', title: `cell ${id}`, risk, source: 'seed', status: 'open', ...overrides };
}

function makeProposal(overrides: Partial<AgentScanFinishAction> = {}): AgentScanFinishAction {
    return {
        type: 'finish',
        findings: [],
        summary: 'All safe',
        selfCritique: 'Thorough investigation.',
        investigationNotes: [],
        coverageGaps: [],
        ...overrides,
    };
}

function makeBaseInput(overrides: Partial<FinishGateInput> = {}): FinishGateInput {
    return {
        proposal: makeProposal(),
        state: {
            runId: 'r1',
            phase: 'investigating' as any,
            phaseReason: '',
            budget: { stepsUsed: 5, stepsRemaining: 10, stepsGranted: 40, extensionsGranted: 0, hardMaxSteps: 80, costSpentUsd: 0.1, costCapUsd: 5, wallClockMs: 2700000, startedAt: Date.now() },
            finishAttempts: 0,
            recovery: { consecutiveBlockedActions: 0, totalBlockedActions: 0, consecutiveModelBlockedActions: 0, totalModelBlockedActions: 0, consecutiveRecoveryFailures: 0, totalRecoveryAttempts: 0, successfulRecoveryAttempts: 0, meaningfulProgressSinceRecovery: true },
        } as any,
        evidence: { getUnsatisfiedRequirements: () => [], recordEvidence: () => {}, addRequirements: () => {}, markHandlersReviewed: () => {}, markInventoryEmpty: () => {} } as any,
        workItems: { getExecutable: () => [], size: () => 0, all: () => [] } as any,
        handlers: { getAll: () => [], getUnreviewedSensitiveCount: () => 0, size: () => 0 } as any,
        candidates: { allReadyForJuror: () => true, getBlocking: () => [], getAll: () => [], getActive: () => [], size: () => 0 } as any,
        investigation: { getIncompleteSteps: () => [], getCompletedSteps: () => ['all-steps'] as any, getUnresolvedTasks: () => [], getUncoveredRanges: () => [], getCoverage: () => null, formatChecklistForPrompt: () => '' } as any,
        scheduler: { kind: 'finish-ready', reason: '' } as any,
        target: { filePath: 'test.ts' },
        gateMode: 'evidence',
        evidenceGate: {
            currentLeads: [],
            deliveredRanges: [{ start: 1, end: 100 }],
            targetRange: { start: 1, end: 100 },
            openLeadsRejectedOnce: false,
        },
        ...overrides,
    };
}

describe('assurance finish gate', () => {
    it('accepts when grid is fully closed and redteam is done', () => {
        const input = makeBaseInput({
            assuranceGate: {
                problems: { open: [], weak: [] },
                isFullyClosed: true,
                redteamDone: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.reasons.filter(r => r.code.startsWith('assurance-'))).toHaveLength(0);
    });

    it('rejects when open cells remain', () => {
        const input = makeBaseInput({
            assuranceGate: {
                problems: { open: [cell('c1', 5), cell('c2', 4)], weak: [] },
                isFullyClosed: false,
                redteamDone: false,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        const openReasons = result.reasons.filter(r => r.code === 'assurance-open-cell');
        expect(openReasons.length).toBe(2);
        expect(openReasons[0].description).toContain('c1');
    });

    it('rejects when risk>=4 safe cells lack traced closure', () => {
        const input = makeBaseInput({
            assuranceGate: {
                problems: {
                    open: [],
                    weak: [cell('c1', 4, { status: 'safe', closure: 'reasoning' })],
                },
                isFullyClosed: true,
                redteamDone: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        const weakReasons = result.reasons.filter(r => r.code === 'assurance-weak-cell');
        expect(weakReasons.length).toBe(1);
        expect(weakReasons[0].description).toContain('Risk 4');
    });

    it('accepts a closed grid before the red team so the loop can run the red team pass', () => {
        const input = makeBaseInput({
            assuranceGate: {
                problems: { open: [], weak: [] },
                isFullyClosed: true,
                redteamDone: false,
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.reasons.some(r => r.code.startsWith('assurance-'))).toBe(false);
    });

    it('forces-incomplete when no budget remains even with open cells', () => {
        const input = makeBaseInput({
            assuranceGate: {
                problems: { open: [cell('c1', 5)], weak: [] },
                isFullyClosed: false,
                redteamDone: false,
            },
        });
        input.state.budget.stepsRemaining = 0;
        input.state.budget.costSpentUsd = 5;
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('forced-incomplete');
    });

    it('standard mode without assuranceGate is unaffected', () => {
        const input = makeBaseInput();
        delete (input as any).assuranceGate;
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.reasons.filter(r => r.code.startsWith('assurance-'))).toHaveLength(0);
    });

    it('plan failure fallback: no assuranceGate means standard behaviour', () => {
        const input = makeBaseInput({ assuranceGate: undefined });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
    });
});

describe('downgrade rule integration', () => {
    it('downgrading traced to reasoning causes the gate to flag it as weak', () => {
        const grid = new GridState([cell('c1', 5)]);
        grid.applyCellUpdates(
            [{ cellId: 'c1', status: 'safe', closure: 'traced', evidenceLines: [50] }],
            [{ start: 1, end: 20 }],
        );
        const problems = grid.gateProblems();
        expect(problems.weak.some((c: GridCell) => c.id === 'c1')).toBe(true);
    });
});

describe('split-file cell assignment', () => {
    it('assigns line-less cells to all parts', () => {
        const grid = new GridState([
            cell('c1', 5, { entryId: null, inputId: null, targetId: null }),
        ]);
        const scope1 = grid.scopeForRange({ startLine: 1, endLine: 100 });
        const scope2 = grid.scopeForRange({ startLine: 101, endLine: 200 });
        expect(scope1.has('c1')).toBe(true);
        expect(scope2.has('c1')).toBe(true);
    });
});
