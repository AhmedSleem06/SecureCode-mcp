/**
 * Tests for the hard finish gate — verifies that premature finishes are
 * rejected and forced-incomplete finishes are allowed when budget is exhausted.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { evaluateFinishGate } from '../src/attack/finishGate';
import { createScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue, createProfileWorkItem } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { InvestigationState } from '../src/attack/investigationState';

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

describe('Finish Gate', () => {
    it('accepts finish when all requirements are met', () => {
        const investigation = new InvestigationState();
        // Complete all default required steps
        investigation.recordRead('test.ts', 1, 50, 50);
        investigation.recordToolUse('check_policy');
        investigation.recordToolUse('search_code');
        investigation.recordToolUse('get_endpoints');
        investigation.recordToolUse('trace_flow_cross_file');
        investigation.recordFlowVerification('test.ts', 'trace_flow_cross_file', 'confirmed', 1, 'flows found');
        investigation.recordToolUse('read_config');
        investigation.markAllHandlersReviewed();
        investigation.markCandidatesVerified();
        const input = makeInput({ investigation });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('complete');
    });

    it('rejects finish with incomplete checklist when budget remains', () => {
        const investigation = new InvestigationState();
        // Don't complete any steps — checklist is incomplete
        const input = makeInput({ investigation });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.mode).toBe('continue');
        expect(result.reasons.some(r => r.code === 'incomplete-checklist')).toBe(true);
    });

    it('rejects finish with findings when checklist is incomplete', () => {
        const investigation = new InvestigationState();
        const input = makeInput({
            investigation,
            proposal: { type: 'finish', findings: [{ line: 10, type: 'xss', severity: 'high', confidence: 85, evidence: 'x', why: 'y' }], summary: 'found', selfCritique: 'done' },
        });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.mode).toBe('continue');
    });

    it('accepts forced-incomplete finish when budget is exhausted', () => {
        const investigation = new InvestigationState();
        const state = createScanRunState('run-1', target, { ...budget, stepsRemaining: 0 });
        const input = makeInput({ investigation, state });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('forced-incomplete');
        expect(result.coverageGaps?.length).toBeGreaterThan(0);
    });

    it('reports unresolved tasks for both finding and non-finding finishes', () => {
        const investigation = new InvestigationState();
        investigation.addInvestigationTasks([{
            id: 'task-1',
            targetFiles: ['test.ts'],
            claim: 'No rate limiting',
            requiredTools: ['search_code'],
            requiredEvidence: ['Trace the code path'],
            status: 'pending',
        }]);

        // Non-finding finish
        const input1 = makeInput({ investigation });
        const result1 = evaluateFinishGate(input1);
        expect(result1.reasons.some(r => r.code === 'unresolved-task')).toBe(true);

        // Finding-bearing finish
        const input2 = makeInput({
            investigation,
            proposal: { type: 'finish', findings: [{ line: 10, type: 'xss', severity: 'high', confidence: 85, evidence: 'x', why: 'y' }], summary: 'found', selfCritique: 'done' },
        });
        const result2 = evaluateFinishGate(input2);
        expect(result2.reasons.some(r => r.code === 'unresolved-task')).toBe(true);
    });

    it('rejects finish when candidates are non-terminal', () => {
        const candidates = new CandidateStore();
        candidates.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'high',
            locations: [], claim: 'XSS vulnerability',
        });
        const input = makeInput({ candidates });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.reasons.some(r => r.code === 'non-terminal-candidate')).toBe(true);
    });

    it('rejects finish when unreviewed security-sensitive handlers exist', () => {
        const handlers = new HandlerInventory();
        handlers.add({
            filePath: 'test.ts',
            symbol: 'handleLogin',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        const input = makeInput({ handlers });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.reasons.some(r => r.code === 'unreviewed-handlers')).toBe(true);
    });

    it('rejects finish when scheduler has a deterministic action', () => {
        const input = makeInput({
            scheduler: {
                kind: 'deterministic-action',
                action: { type: 'check_policy', filePath: 'test.ts', rationale: 'r' } as any,
                reason: 'Missing policy check',
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.reasons.some(r => r.code === 'scheduler-has-action')).toBe(true);
    });

    it('returns recovery action from scheduler when finish is rejected', () => {
        const recoveryAction = { type: 'check_policy', filePath: 'test.ts', rationale: 'r' } as any;
        const input = makeInput({
            investigation: new InvestigationState(), // incomplete checklist
            scheduler: {
                kind: 'deterministic-action',
                action: recoveryAction,
                reason: 'Missing policy check',
            },
        });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.recoveryAction).toBeDefined();
        expect(result.recoveryAction?.type).toBe('check_policy');
    });

    it('accepts forced-incomplete when wall clock is exhausted', () => {
        const investigation = new InvestigationState();
        const state = createScanRunState('run-1', target, budget);
        state.budget.startedAt = Date.now() - 800_000; // past wall clock
        const input = makeInput({ investigation, state });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('forced-incomplete');
    });
});
