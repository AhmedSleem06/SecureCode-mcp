import { describe, it, expect } from 'vitest';
import {
    createScanRunState,
    transitionScanPhase,
    terminateScan,
    isScanTerminal,
    hasBudgetRemaining,
    hasWallClockRemaining,
    canExecuteWork,
    snapshotState,
    type ScanPhase,
} from '../src/attack/scanState';

const budget = {
    stepsRemaining: 40,
    costSpentUsd: 0,
    costCapUsd: 1.20,
    stepsGranted: 40,
    hardMaxSteps: 80,
    extensionsGranted: 0,
};

const target = {
    filePath: 'test.ts',
    language: 'typescript',
    fileContent: 'export function handler() {}',
};

describe('ScanRunState', () => {
    it('creates state in planning phase', () => {
        const state = createScanRunState('run-1', target, budget);
        expect(state.phase).toBe('planning');
        expect(state.budget.stepsRemaining).toBe(40);
        expect(state.recovery.consecutiveBlockedActions).toBe(0);
        expect(state.finishAttempts).toBe(0);
    });

    it('transitions through valid phases', () => {
        const state = createScanRunState('run-1', target, budget);
        transitionScanPhase(state, 'surveying', 'start survey');
        expect(state.phase).toBe('surveying');
        transitionScanPhase(state, 'tracing', 'start tracing');
        expect(state.phase).toBe('tracing');
        transitionScanPhase(state, 'candidate_investigation', 'found candidate');
        expect(state.phase).toBe('candidate_investigation');
        transitionScanPhase(state, 'finish_review', 'model requested finish');
        expect(state.phase).toBe('finish_review');
        transitionScanPhase(state, 'verifying', 'finish approved');
        expect(state.phase).toBe('verifying');
        transitionScanPhase(state, 'finalizing', 'verification done');
        expect(state.phase).toBe('finalizing');
        transitionScanPhase(state, 'completed', 'scan complete');
        expect(state.phase).toBe('completed');
    });

    it('rejects invalid transitions', () => {
        const state = createScanRunState('run-1', target, budget);
        expect(() => transitionScanPhase(state, 'verifying', 'skip')).toThrow('Invalid scan phase transition');
    });

    it('allows evidence_recovery from verifying', () => {
        const state = createScanRunState('run-1', target, budget);
        transitionScanPhase(state, 'surveying', 'survey');
        transitionScanPhase(state, 'tracing', 'trace');
        transitionScanPhase(state, 'candidate_investigation', 'candidate');
        transitionScanPhase(state, 'finish_review', 'finish');
        transitionScanPhase(state, 'verifying', 'verify');
        transitionScanPhase(state, 'evidence_recovery', 'need more evidence');
        expect(state.phase).toBe('evidence_recovery');
    });

    it('allows finish_review to go back to surveying/tracing', () => {
        const state = createScanRunState('run-1', target, budget);
        transitionScanPhase(state, 'surveying', 'survey');
        transitionScanPhase(state, 'tracing', 'trace');
        transitionScanPhase(state, 'candidate_investigation', 'candidate');
        transitionScanPhase(state, 'finish_review', 'finish');
        transitionScanPhase(state, 'surveying', 'rejected, survey more');
        expect(state.phase).toBe('surveying');
    });

    it('terminates with reason', () => {
        const state = createScanRunState('run-1', target, budget);
        terminateScan(state, 'cost_cap', 'budget exhausted');
        expect(state.phase).toBe('terminated');
        expect(state.termination?.reason).toBe('cost_cap');
        expect(state.termination?.summary).toBe('budget exhausted');
    });

    it('isScanTerminal returns true for completed and terminated', () => {
        const state1 = createScanRunState('run-1', target, budget);
        expect(isScanTerminal(state1)).toBe(false);
        transitionScanPhase(state1, 'surveying', 'survey');
        transitionScanPhase(state1, 'tracing', 'trace');
        transitionScanPhase(state1, 'candidate_investigation', 'candidate');
        transitionScanPhase(state1, 'finish_review', 'finish');
        transitionScanPhase(state1, 'verifying', 'verify');
        transitionScanPhase(state1, 'finalizing', 'finalize');
        transitionScanPhase(state1, 'completed', 'done');
        expect(isScanTerminal(state1)).toBe(true);

        const state2 = createScanRunState('run-2', target, budget);
        terminateScan(state2, 'cancelled', 'user cancelled');
        expect(isScanTerminal(state2)).toBe(true);
    });

    it('hasBudgetRemaining checks steps and cost', () => {
        const state = createScanRunState('run-1', target, budget);
        expect(hasBudgetRemaining(state)).toBe(true);
        state.budget.stepsRemaining = 0;
        expect(hasBudgetRemaining(state)).toBe(false);
    });

    it('hasBudgetRemaining returns false when cost cap reached', () => {
        const state = createScanRunState('run-1', target, budget);
        state.budget.costSpentUsd = 1.30;
        expect(hasBudgetRemaining(state)).toBe(false);
    });

    it('hasWallClockRemaining returns false when time expired', () => {
        const state = createScanRunState('run-1', target, budget);
        state.budget.startedAt = Date.now() - 800_000;
        expect(hasWallClockRemaining(state)).toBe(false);
    });

    it('canExecuteWork requires budget, wall clock, and non-terminal', () => {
        const state = createScanRunState('run-1', target, budget);
        expect(canExecuteWork(state)).toBe(true);
        state.budget.stepsRemaining = 0;
        expect(canExecuteWork(state)).toBe(false);
    });

    it('snapshotState produces JSON with key fields', () => {
        const state = createScanRunState('run-1', target, budget);
        const snap = snapshotState(state);
        const parsed = JSON.parse(snap);
        expect(parsed.runId).toBe('run-1');
        expect(parsed.phase).toBe('planning');
        expect(parsed.stepsRemaining).toBe(40);
    });

    it('completed and terminated phases have no valid transitions', () => {
        const state1 = createScanRunState('run-1', target, budget);
        transitionScanPhase(state1, 'surveying', 's');
        transitionScanPhase(state1, 'tracing', 't');
        transitionScanPhase(state1, 'candidate_investigation', 'c');
        transitionScanPhase(state1, 'finish_review', 'f');
        transitionScanPhase(state1, 'verifying', 'v');
        transitionScanPhase(state1, 'finalizing', 'fi');
        transitionScanPhase(state1, 'completed', 'done');
        expect(() => transitionScanPhase(state1, 'planning', 'restart')).toThrow();

        const state2 = createScanRunState('run-2', target, budget);
        terminateScan(state2, 'cancelled', 'bye');
        expect(() => transitionScanPhase(state2, 'planning', 'restart')).toThrow();
    });
});
