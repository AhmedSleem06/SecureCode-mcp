/**
 * Tests for the hard finish gate — verifies that premature finishes are
 * rejected and forced-incomplete finishes are allowed when budget is exhausted.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { evaluateFinishGate, newFinishLoopTracker, trackFinishRejection, finishLoopEscaped, FINISH_LOOP_ESCAPE_THRESHOLD, FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD, FINISH_LOOP_CANDIDATE_ESCAPE_THRESHOLD, finishLoopEscapeThreshold, isLandingBudget, textHasActorAndEffect, transcriptHasRuntimeEvidence } from '../src/attack/finishGate';
import { AGENT_SCAN_DEFAULTS } from '../src/attack/agentScanProtocol';
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

    it('accepts finish at the soft deadline (75% of wall clock spent) even with budget remaining', () => {
        const investigation = new InvestigationState();
        const state = createScanRunState('run-1', target, { ...budget, stepsRemaining: 40 });
        // Simulate 80% of a 45-minute wall clock already spent
        (state.budget as any).startedAt = Date.now() - 36 * 60 * 1000;
        (state.budget as any).wallClockMs = 45 * 60 * 1000;
        const input = makeInput({ investigation, state });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('forced-incomplete');
        expect(result.coverageGaps?.length).toBeGreaterThan(0);
    });

    it('rejects finish before the soft deadline when budget remains', () => {
        const investigation = new InvestigationState();
        const state = createScanRunState('run-1', target, { ...budget, stepsRemaining: 40 });
        (state.budget as any).startedAt = Date.now() - 10 * 60 * 1000;
        (state.budget as any).wallClockMs = 45 * 60 * 1000;
        const input = makeInput({ investigation, state });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(false);
        expect(result.mode).toBe('continue');
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

describe('Finish Loop Tracker', () => {
    const reasons = (codes: string[]) => codes.map(code => ({ code, description: 'x' }));

    it('the same reason-code signature climbs to the escape threshold at exactly 4', () => {
        const t = newFinishLoopTracker();
        trackFinishRejection(t, reasons(['non-terminal-candidate', 'unreviewed-handlers']));
        trackFinishRejection(t, reasons(['non-terminal-candidate', 'unreviewed-handlers']));
        trackFinishRejection(t, reasons(['non-terminal-candidate', 'unreviewed-handlers']));
        expect(finishLoopEscaped(t)).toBe(false);
        trackFinishRejection(t, reasons(['non-terminal-candidate', 'unreviewed-handlers']));
        expect(finishLoopEscaped(t)).toBe(true);
    });

    it('candidate-only rejections escape after 2 identical rejections', () => {
        expect(FINISH_LOOP_CANDIDATE_ESCAPE_THRESHOLD).toBe(2);
        const t = newFinishLoopTracker();
        trackFinishRejection(t, reasons(['non-terminal-candidate']), 1);
        expect(finishLoopEscaped(t)).toBe(false);
        trackFinishRejection(t, reasons(['non-terminal-candidate', 'non-terminal-candidate']), 2);
        expect(finishLoopEscaped(t)).toBe(false);
        trackFinishRejection(t, reasons(['non-terminal-candidate', 'non-terminal-candidate']), 2);
        expect(finishLoopEscaped(t)).toBe(true);
    });

    it('a changed signature resets the counter — genuine progress keeps the gate strict', () => {
        const t = newFinishLoopTracker();
        for (let i = 0; i < 3; i++) trackFinishRejection(t, reasons(['non-terminal-candidate']));
        trackFinishRejection(t, reasons(['incomplete-checklist'])); // changed → reset to 1
        expect(finishLoopEscaped(t)).toBe(false);
        expect(t.rejections).toBe(1);
        trackFinishRejection(t, reasons(['incomplete-checklist']));
        trackFinishRejection(t, reasons(['incomplete-checklist']));
        trackFinishRejection(t, reasons(['incomplete-checklist']));
        expect(finishLoopEscaped(t)).toBe(true);
    });

    it('the signature is order-insensitive across code sets', () => {
        const t = newFinishLoopTracker();
        trackFinishRejection(t, reasons(['a', 'b']));
        trackFinishRejection(t, reasons(['b', 'a']));
        expect(t.rejections).toBe(2);
    });

    it('a shrinking code set (progress) resets the counter', () => {
        const t = newFinishLoopTracker();
        for (let i = 0; i < 3; i++) trackFinishRejection(t, reasons(['non-terminal-candidate', 'unsatisfied-evidence-requirement']));
        trackFinishRejection(t, reasons(['non-terminal-candidate'])); // one blocker resolved
        expect(t.rejections).toBe(1);
        expect(finishLoopEscaped(t)).toBe(false);
    });
});

describe('Finish Gate — landing mode', () => {
    it('accepts a finish as forced-incomplete when landing, with gate reasons as coverage gaps', () => {
        const investigation = new InvestigationState();
        const state = createScanRunState('run-1', target, { ...budget, stepsRemaining: 40 });
        (state.budget as any).startedAt = Date.now() - 60 * 1000;
        (state.budget as any).wallClockMs = 45 * 60 * 1000;
        const rejected = evaluateFinishGate(makeInput({ investigation, state }));
        expect(rejected.accepted).toBe(false);
        const landed = evaluateFinishGate(makeInput({ investigation, state, landing: true }));
        expect(landed.accepted).toBe(true);
        expect(landed.mode).toBe('forced-incomplete');
        expect(landed.reasons.length).toBeGreaterThan(0);
        expect(landed.coverageGaps?.length).toBeGreaterThan(0);
    });

    it('isLandingBudget: only when no extension fits AND under 3 steps of cost remain', () => {
        const est = AGENT_SCAN_DEFAULTS.perStepEstimateUsd;
        expect(est).toBe(0.06);
        expect(isLandingBudget({ creditsUsed: 15, maxCredits: 15, costSpentUsd: 3.9, costCapUsd: 4.0 })).toBe(true);
        expect(isLandingBudget({ creditsUsed: 14, maxCredits: 15, costSpentUsd: 3.9, costCapUsd: 4.0 })).toBe(true);
        expect(isLandingBudget({ creditsUsed: 13, maxCredits: 15, costSpentUsd: 3.9, costCapUsd: 4.0 })).toBe(false);
        expect(isLandingBudget({ creditsUsed: 15, maxCredits: 15, costSpentUsd: 3.0, costCapUsd: 4.0 })).toBe(false);
        expect(isLandingBudget(undefined)).toBe(false);
    });
});

describe('Finish Gate — segment scope', () => {
    const content = Array.from({ length: 3000 }, (_, i) => (i >= 2499 && i < 2510 ? 'const token = session.authenticate(req)' : `line ${i + 1}`)).join('\n');

    it('ignores unread high-priority ranges and unreviewed handlers outside the part', () => {
        const investigation = new InvestigationState();
        investigation.setRequiredSteps(['initial-read']);
        investigation.setScope('big.ts', { start: 1, end: 1500 });
        investigation.recordActualRead('big.ts', 1, 1500, 3000, false);
        const handlers = new HandlerInventory();
        handlers.add({ filePath: 'big.ts', symbol: 'post', range: { start: 2600, end: 2600 }, kind: 'http-handler', securitySensitive: true });
        const scoped = evaluateFinishGate(makeInput({
            investigation, handlers,
            target: { filePath: 'big.ts', fileContent: content, segment: { startLine: 1, endLine: 1500 } },
        }));
        expect(scoped.accepted).toBe(true);
        expect(scoped.mode).toBe('complete');

        const unscopedState = new InvestigationState();
        unscopedState.setRequiredSteps(['initial-read']);
        unscopedState.recordActualRead('big.ts', 1, 1500, 3000, false);
        const unscoped = evaluateFinishGate(makeInput({
            investigation: unscopedState, handlers,
            target: { filePath: 'big.ts', fileContent: content },
        }));
        expect(unscoped.accepted).toBe(false);
        expect(unscoped.reasons.map(r => r.code)).toEqual(expect.arrayContaining(['unreviewed-handlers', 'high-priority-unread-range']));
    });

    it('still blocks on unread high-priority code and handlers inside the part', () => {
        const investigation = new InvestigationState();
        investigation.setRequiredSteps(['initial-read']);
        investigation.setScope('big.ts', { start: 1501, end: 3000 });
        investigation.recordActualRead('big.ts', 1501, 2000, 3000, false);
        const handlers = new HandlerInventory();
        handlers.add({ filePath: 'big.ts', symbol: 'post', range: { start: 2600, end: 2600 }, kind: 'http-handler', securitySensitive: true });
        const result = evaluateFinishGate(makeInput({
            investigation, handlers,
            target: { filePath: 'big.ts', fileContent: content, segment: { startLine: 1501, endLine: 3000 } },
        }));
        expect(result.accepted).toBe(false);
        expect(result.reasons.map(r => r.code)).toEqual(expect.arrayContaining(['unreviewed-handlers', 'high-priority-unread-range']));
    });
});

describe('Finish Gate — traced flow readiness (verification is post-finish)', () => {
    function completedInvestigation(): InvestigationState {
        const investigation = new InvestigationState();
        investigation.recordActualRead('test.ts', 1, 50, 50, false);
        investigation.recordToolUse('check_policy');
        investigation.recordToolUse('search_code');
        investigation.recordToolUse('get_endpoints');
        investigation.recordToolUse('read_config');
        investigation.recordFlowVerification('test.ts', 'trace_flow_cross_file', 'refuted', 0, 'no cross-file flows');
        investigation.markAllHandlersReviewed();
        investigation.markCandidatesVerified();
        return investigation;
    }

    it('accepts the 5-bug shape on the first finish: SQLi by string concat with a traced flow and no guard', () => {
        const investigation = completedInvestigation();
        investigation.recordToolUse('trace_flow');
        investigation.recordFlowVerification('test.ts', 'trace_flow', 'confirmed', 2, '2 hop(s)', {
            source: { filePath: 'test.ts', symbol: 'req.query.cmd', line: 30 },
            sink: { filePath: 'test.ts', symbol: 'exec', line: 31 },
            hops: [],
            flows: [
                { source: { filePath: 'test.ts', symbol: 'req.query.cmd', line: 30 }, sink: { filePath: 'test.ts', symbol: 'exec', line: 31 }, hops: [] },
                { source: { filePath: 'test.ts', symbol: 'req.query.id', line: 10 }, sink: { filePath: 'test.ts', symbol: 'db.query', line: 12 }, hops: [{ filePath: 'test.ts', line: 11, description: 'concat' }] },
            ],
        });
        const candidates = new CandidateStore();
        const sqli = candidates.register({
            rootCauseId: 'sqli-concat', type: 'sql_injection', severity: 'critical',
            locations: [{ filePath: 'test.ts', line: 12 }], claim: 'SQL injection via string concatenation',
        });
        candidates.addEvidence(sqli, 'backfill:source', 'source', 'source');
        candidates.applyFlowEvidence(investigation.getTracedFlowPaths(), investigation.getGuardResults());
        const result = evaluateFinishGate(makeInput({
            investigation, candidates,
            proposal: { type: 'finish', findings: [{ line: 12, type: 'sql_injection', severity: 'critical', confidence: 90, evidence: 'db.query("..." + id)', why: 'concat' }], summary: 's', selfCritique: 'c' },
        }));
        expect(result.reasons).toEqual([]);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('complete');
    });

    it('high/critical candidates are not blocked by the verification dimension', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        const id = candidates.register({
            rootCauseId: 'rc-exec', type: 'command_injection', severity: 'high',
            locations: [{ filePath: 'test.ts', line: 31 }], claim: 'Command injection',
        });
        for (const dim of ['source', 'reachability', 'control', 'threat-model', 'impact'] as const) {
            candidates.addEvidence(id, `ev-${dim}`, undefined, dim);
        }
        expect(candidates.get(id)!.satisfiedDimensions).not.toContain('verification');
        const result = evaluateFinishGate(makeInput({ investigation, candidates }));
        expect(result.reasons.some(r => r.code === 'non-terminal-candidate')).toBe(false);
        expect(result.accepted).toBe(true);
    });

    it('a candidate without a traced flow still blocks, and the reason names the missing flow (not verification)', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        candidates.register({
            rootCauseId: 'rc-x', type: 'sql_injection', severity: 'critical',
            locations: [{ filePath: 'test.ts', line: 12 }], claim: 'SQLi',
        });
        const result = evaluateFinishGate(makeInput({ investigation, candidates }));
        expect(result.accepted).toBe(false);
        const reason = result.reasons.find(r => r.code === 'non-terminal-candidate')!;
        expect(reason.description).toContain('no traced source-to-sink flow');
        expect(reason.description).not.toContain('verification');
    });

    it('a traced candidate with an effective guard still blocks', () => {
        const investigation = completedInvestigation();
        investigation.recordFlowVerification('test.ts', 'trace_flow', 'confirmed', 1, '1 hop(s)', {
            source: { filePath: 'test.ts', line: 10 }, sink: { filePath: 'test.ts', line: 12 }, hops: [],
        });
        investigation.recordGuardResult({ filePath: 'test.ts', guardName: 'escapeSql', attackType: 'sql_injection', effective: true, reason: 'escapes quotes' });
        const candidates = new CandidateStore();
        candidates.register({
            rootCauseId: 'rc-x', type: 'sql_injection', severity: 'critical',
            locations: [{ filePath: 'test.ts', line: 12 }], claim: 'SQLi',
        });
        candidates.applyFlowEvidence(investigation.getTracedFlowPaths(), investigation.getGuardResults());
        const result = evaluateFinishGate(makeInput({ investigation, candidates }));
        expect(result.accepted).toBe(false);
        expect(result.reasons.find(r => r.code === 'non-terminal-candidate')!.description).toContain('effective guard');
    });
});

describe('Finish Loop Tracker — checklist-only escape', () => {
    const reasons = (codes: string[]) => codes.map(code => ({ code, description: 'x' }));

    it('escapes at 2 when only checklist reasons block and there are no candidates', () => {
        expect(FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD).toBe(2);
        const t = newFinishLoopTracker();
        trackFinishRejection(t, reasons(['unsatisfied-evidence-requirement', 'incomplete-checklist']), 0);
        expect(finishLoopEscaped(t)).toBe(false);
        trackFinishRejection(t, reasons(['unsatisfied-evidence-requirement', 'incomplete-checklist']), 0);
        expect(finishLoopEscaped(t)).toBe(true);
    });

    it('stays at 4 when a candidate is active', () => {
        const t = newFinishLoopTracker();
        for (let i = 0; i < 3; i++) trackFinishRejection(t, reasons(['unsatisfied-evidence-requirement']), 1);
        expect(finishLoopEscaped(t)).toBe(false);
        trackFinishRejection(t, reasons(['unsatisfied-evidence-requirement']), 1);
        expect(finishLoopEscaped(t)).toBe(true);
    });

    it('stays at 4 when a high-priority unread range or other blocker is present', () => {
        expect(finishLoopEscapeThreshold(reasons(['unsatisfied-evidence-requirement', 'high-priority-unread-range']), 0)).toBe(FINISH_LOOP_ESCAPE_THRESHOLD);
        expect(finishLoopEscapeThreshold(reasons(['incomplete-checklist', 'executable-work-remaining']), 0)).toBe(FINISH_LOOP_ESCAPE_THRESHOLD);
        expect(finishLoopEscapeThreshold(reasons(['incomplete-checklist']), 0)).toBe(FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD);
    });
});

describe('Finish Gate — Fix D: actor+effect from finding text', () => {
    function completedInvestigation(): InvestigationState {
        const investigation = new InvestigationState();
        investigation.recordActualRead('src/orders.ts', 1, 150, 150, false);
        investigation.recordToolUse('check_policy');
        investigation.recordToolUse('search_code');
        investigation.recordToolUse('get_endpoints');
        investigation.recordToolUse('read_config');
        investigation.recordFlowVerification('src/orders.ts', 'trace_flow_cross_file', 'refuted', 0, 'no cross-file flows');
        investigation.markAllHandlersReviewed();
        investigation.markCandidatesVerified();
        return investigation;
    }

    it('(a) accepts a logic candidate when the finding why has actor+effect but the claim does not (06-fixed regression)', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        const id = candidates.register({
            rootCauseId: 'business_logic_price_manipulation:44',
            type: 'business_logic',
            severity: 'high',
            locations: [{ filePath: 'src/orders.ts', line: 44 }],
            claim: 'Any customer with a valid JWT sets item.price in the POST /orders body. The server never looks the price up.',
        });
        candidates.addEvidence(id, 'backfill:source:src/orders.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/orders.ts', 'guard', 'control');
        candidates.addEvidence(id, 'backfill:check_policy:src/orders.ts', 'policy');

        const finding = {
            line: 44, type: 'business_logic_price_manipulation', severity: 'high' as const,
            confidence: 85, evidence: 'POST body sets price directly',
            why: 'Actor: any authenticated customer. Effect: goods ship at a price the customer chose, including zero or negative.',
        };

        const transcript: any[] = [{
            action: { type: 'check_guard', filePath: 'src/orders.ts' },
            observation: 'Guard: NOT EFFECTIVE — no price validation guard found',
        }];

        const result = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            transcript,
            proposal: { type: 'finish', findings: [finding], summary: 'done', selfCritique: 'checked' },
        }));
        expect(result.reasons.filter(r => r.code === 'non-terminal-candidate')).toEqual([]);
    });

    it('(a) the claim itself without "customer" still fails without a matching finding', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        const id = candidates.register({
            rootCauseId: 'biz:44',
            type: 'business_logic',
            severity: 'high',
            locations: [{ filePath: 'src/orders.ts', line: 44 }],
            claim: 'Price is not validated before storage.',
        });
        candidates.addEvidence(id, 'backfill:source:src/orders.ts', 'source', 'source');

        const result = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' },
        }));
        expect(result.reasons.some(r => r.code === 'non-terminal-candidate')).toBe(true);
    });

    it('(a) widened actor terms: "customer", "owner", "buyer", "seller" are accepted in the claim', () => {
        const investigation = completedInvestigation();
        for (const actor of ['customer', 'owner', 'buyer', 'seller', 'merchant', 'operator']) {
            const candidates = new CandidateStore();
            const id = candidates.register({
                rootCauseId: `biz:${actor}:44`,
                type: 'business_logic',
                severity: 'high',
                locations: [{ filePath: 'src/orders.ts', line: 44 }],
                claim: `Any ${actor} can bypass the payment check and get free goods.`,
            });
            candidates.addEvidence(id, 'backfill:source:src/orders.ts', 'source', 'source');
            candidates.addEvidence(id, 'backfill:check_guard:src/orders.ts', 'guard', 'control');
            const result = evaluateFinishGate(makeInput({
                investigation,
                candidates,
                proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' },
            }));
            expect(result.reasons.filter(r => r.code === 'non-terminal-candidate')).toEqual([]);
        }
    });

    it('(b) injection candidate without flow: accepts run_tests runtime evidence', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        const id = candidates.register({
            rootCauseId: 'sql_injection:113',
            type: 'sql_injection',
            severity: 'critical',
            locations: [{ filePath: 'src/analytics.ts', line: 113 }],
            claim: 'SQL injection via tag parameter',
        });
        candidates.addEvidence(id, 'backfill:source:src/analytics.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/analytics.ts', 'guard', 'control');
        candidates.addEvidence(id, 'backfill:config:src/analytics.ts', undefined, 'threat-model');

        const transcript: any[] = [{
            action: { type: 'run_tests', mode: 'generated', rationale: 'test sqli' },
            observation: 'run_tests generated: passed\nBackend: docker\nExit code: 0\nDuration: 6575ms\n\nOutput:\nSELECT * FROM events WHERE account_id = \'acct_abc12345\' AND tags @> \'["x\'; DROP TABLE events;--"]\' ORDER BY timestamp DESC LIMIT 100\nPASS: DROP TABLE lies outside any SQL string literal',
        }];

        const result = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            transcript,
            proposal: { type: 'finish', findings: [{ line: 113, type: 'sql_injection', severity: 'critical', confidence: 90, evidence: 'x', why: 'SQL injection' }], summary: 'done', selfCritique: 'checked' },
        }));
        expect(result.reasons.filter(r => r.code === 'non-terminal-candidate')).toEqual([]);
    });

    it('(b) injection candidate without flow or run_tests: becomes a coverage gap, not a repeated blocker', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        candidates.register({
            rootCauseId: 'sql_injection:113',
            type: 'sql_injection',
            severity: 'critical',
            locations: [{ filePath: 'src/analytics.ts', line: 113 }],
            claim: 'SQL injection via tag parameter',
        });

        const result1 = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            transcript: [],
            proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' },
        }));
        expect(result1.coverageGaps?.some(g => g.title.includes('No traced flow'))).toBe(true);
        expect(result1.reasons.some(r => r.code === 'non-terminal-candidate')).toBe(false);

        const result2 = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            transcript: [],
            proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' },
        }));
        expect(result2.reasons.some(r => r.code === 'non-terminal-candidate')).toBe(false);
    });

    it('(c) logic candidate with missing control: filled by check_guard observation', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        const id = candidates.register({
            rootCauseId: 'broken_access_control:31',
            type: 'broken_access_control',
            severity: 'critical',
            locations: [{ filePath: 'src/admin.ts', line: 31 }],
            claim: 'Any attacker can bypass the admin guard on non-GET routes.',
        });
        candidates.addEvidence(id, 'backfill:source:src/admin.ts', 'source', 'source');

        const transcript: any[] = [{
            action: { type: 'check_guard', filePath: 'src/admin.ts' },
            observation: 'Guard "requireAdmin" vs broken_access_control: NOT EFFECTIVE\nReason: Guard detected as \'unknown\' but effectiveness against broken_access_control is unknown',
        }];

        const result = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            transcript,
            proposal: { type: 'finish', findings: [{ line: 31, type: 'broken_access_control', severity: 'critical', confidence: 90, evidence: 'x', why: 'Any attacker can bypass the admin guard.' }], summary: 'done', selfCritique: 'checked' },
        }));
        const candidateReasons = result.reasons.filter(r => r.code === 'non-terminal-candidate');
        const controlMissing = candidateReasons.some(r => r.description.includes('control'));
        expect(controlMissing).toBe(false);
    });

    it('forced_incomplete becomes complete when all blocking reasons are resolved by fixes', () => {
        const investigation = completedInvestigation();
        const candidates = new CandidateStore();
        for (const [line, type, claim] of [
            [44, 'business_logic', 'Any customer sets item.price in POST /orders body.'],
            [81, 'business_logic', 'Any customer marks order as paid without paying.'],
            [129, 'business_logic', 'Cancel blocks only shipped orders.'],
        ] as const) {
            const cid = candidates.register({
                rootCauseId: `${type}:${line}`, type, severity: 'high',
                locations: [{ filePath: 'src/orders.ts', line }],
                claim,
            });
            candidates.addEvidence(cid, `backfill:source:src/orders.ts`, 'source', 'source');
        }

        const findings = [
            { line: 44, type: 'business_logic', severity: 'high' as const, confidence: 85, evidence: 'x', why: 'Actor: any authenticated customer. Effect: goods ship at chosen price.' },
            { line: 81, type: 'business_logic', severity: 'high' as const, confidence: 85, evidence: 'x', why: 'Actor: any authenticated customer. Effect: order marked paid without payment.' },
            { line: 129, type: 'business_logic', severity: 'high' as const, confidence: 85, evidence: 'x', why: 'Actor: the customer who owns the order. Effect: cancels paid order with no refund.' },
        ];

        const transcript: any[] = [{
            action: { type: 'check_guard', filePath: 'src/orders.ts' },
            observation: 'Guard: NOT EFFECTIVE — no payment validation guard found',
        }];

        const result = evaluateFinishGate(makeInput({
            investigation,
            candidates,
            transcript,
            proposal: { type: 'finish', findings, summary: 'done', selfCritique: 'checked' },
        }));
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('complete');
    });
});

describe('Finish Gate — textHasActorAndEffect export', () => {
    it('recognizes classic actor+effect in finding why text', () => {
        expect(textHasActorAndEffect('Actor: any authenticated customer. Effect: goods ship at a price the customer chose.')).toBe(true);
    });

    it('rejects text without an actor', () => {
        expect(textHasActorAndEffect('The price field is not validated.')).toBe(false);
    });

    it('rejects text without an effect', () => {
        expect(textHasActorAndEffect('The attacker has a token.')).toBe(false);
    });
});
