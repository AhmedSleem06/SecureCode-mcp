import { describe, it, expect } from 'vitest';
import { hasStructureSupport, getCapability } from '../src/project-map/capabilityRegistry';
import { evaluateFinishGate, FLOW_REQUIRED_TYPES } from '../src/attack/finishGate';
import { createScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { InvestigationState } from '../src/attack/investigationState';

describe('hasStructureSupport', () => {
    it('returns true for supported languages', () => {
        expect(hasStructureSupport('javascript')).toBe(true);
        expect(hasStructureSupport('typescript')).toBe(true);
        expect(hasStructureSupport('tsx')).toBe(true);
        expect(hasStructureSupport('python')).toBe(true);
    });

    it('returns false for unsupported languages', () => {
        expect(hasStructureSupport('go')).toBe(false);
        expect(hasStructureSupport('ruby')).toBe(false);
        expect(hasStructureSupport('php')).toBe(false);
        expect(hasStructureSupport('java')).toBe(false);
        expect(hasStructureSupport('kotlin')).toBe(false);
        expect(hasStructureSupport('csharp')).toBe(false);
        expect(hasStructureSupport('rust')).toBe(false);
        expect(hasStructureSupport('c')).toBe(false);
        expect(hasStructureSupport('cpp')).toBe(false);
    });

    it('detects language from file path', () => {
        expect(hasStructureSupport('src/handler.ts')).toBe(true);
        expect(hasStructureSupport('server.js')).toBe(true);
        expect(hasStructureSupport('app.py')).toBe(true);
        expect(hasStructureSupport('main.go')).toBe(false);
        expect(hasStructureSupport('service.rb')).toBe(false);
        expect(hasStructureSupport('Controller.java')).toBe(false);
        expect(hasStructureSupport('handler.rs')).toBe(false);
        expect(hasStructureSupport('model.php')).toBe(false);
        expect(hasStructureSupport('app.kt')).toBe(false);
        expect(hasStructureSupport('service.cs')).toBe(false);
    });

    it('handles normalized language names', () => {
        expect(hasStructureSupport('ts')).toBe(true);
        expect(hasStructureSupport('js')).toBe(true);
        expect(hasStructureSupport('py')).toBe(true);
    });

    it('fallback tier has correct capabilities', () => {
        const cap = getCapability('go');
        expect(cap.tier).toBe('fallback');
        expect(cap.taint).toBe(false);
        expect(cap.ast).toBe(false);
        expect(cap.guardCheck).toBe(false);
        expect(cap.policyCheck).toBe(false);
    });
});

const goContent = `package main

import (
    "database/sql"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    db.Query("SELECT * FROM users WHERE id = " + id)
}`;

const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };

function makeGoTarget() {
    return { filePath: 'handlers/user.go', language: 'go', fileContent: goContent };
}

function makeGateInput(overrides?: Partial<any>) {
    const target = makeGoTarget();
    const state = createScanRunState('run-go-1', target, budget);
    return {
        proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' } as any,
        state,
        evidence: new EvidenceLedger(),
        workItems: new WorkItemQueue(),
        handlers: new HandlerInventory(),
        candidates: new CandidateStore(),
        investigation: new InvestigationState(),
        scheduler: { kind: 'finish-ready' as const, reason: 'no work' },
        target: { filePath: 'handlers/user.go', language: 'go' },
        gateMode: 'evidence' as const,
        evidenceGate: {
            currentLeads: [],
            deliveredRanges: [{ start: 1, end: 12 }],
            targetRange: { start: 1, end: 12 },
            openLeadsRejectedOnce: true,
        },
        ...overrides,
    };
}

describe('Finish gate — unsupported language (Go)', () => {
    it('SQL injection candidate with read coverage completes without trace_flow for Go target', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('handlers/user.go', 1, 12, 12);
        investigation.recordActualRead('handlers/user.go', 1, 12, 12, false);

        const id = candidates.register({
            rootCauseId: 'sqli-go-1',
            type: 'sql_injection',
            severity: 'high',
            locations: [{ filePath: 'handlers/user.go', line: 10 }],
            claim: 'Attacker injects SQL via user input concatenated into query at line 10',
        });
        candidates.addEvidence(id, 'backfill:source:handlers/user.go', 'source', 'source');

        const input = makeGateInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        const candidateReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(candidateReasons).toHaveLength(0);
        expect(result.mode).not.toBe('continue');
    });

    it('does not cause forced_incomplete or loop for Go injection candidate', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('handlers/user.go', 1, 12, 12);
        investigation.recordActualRead('handlers/user.go', 1, 12, 12, false);

        const id = candidates.register({
            rootCauseId: 'sqli-go-2',
            type: 'sql_injection',
            severity: 'high',
            locations: [{ filePath: 'handlers/user.go', line: 10 }],
            claim: 'Attacker injects SQL via id parameter concatenated into db.Query at line 10',
        });
        candidates.addEvidence(id, 'backfill:source:handlers/user.go', 'source', 'source');

        const input = makeGateInput({ candidates, investigation });
        const result = evaluateFinishGate(input);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('complete');
    });

    it('Go injection candidate WITHOUT read coverage is still rejected with read_file suggestion', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();

        const id = candidates.register({
            rootCauseId: 'sqli-go-3',
            type: 'sql_injection',
            severity: 'high',
            locations: [{ filePath: 'handlers/user.go', line: 10 }],
            claim: 'Attacker injects SQL via user input',
        });
        candidates.addEvidence(id, 'backfill:source:handlers/user.go', 'source', 'source');

        const input = makeGateInput({ candidates, investigation });
        input.evidenceGate = { ...input.evidenceGate, deliveredRanges: [] };
        const result = evaluateFinishGate(input);
        const candidateReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(candidateReasons.length).toBeGreaterThan(0);
        expect(candidateReasons[0].description).toContain('read the entry-point');
        expect(candidateReasons[0].description).not.toContain('trace_flow');
    });

    it('TypeScript injection candidate STILL requires trace_flow (structure supported)', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('src/users.ts', 1, 120, 120);
        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = candidates.register({
            rootCauseId: 'sqli-ts-1',
            type: 'sql_injection',
            severity: 'high',
            locations: [{ filePath: 'src/users.ts', line: 50 }],
            claim: 'Attacker injects SQL via user input into query at line 50',
        });
        candidates.addEvidence(id, 'backfill:source:src/users.ts', 'source', 'source');
        candidates.addEvidence(id, 'backfill:check_guard:src/users.ts', 'guard', 'control');

        const state = createScanRunState('run-ts-1', { filePath: 'src/users.ts', language: 'typescript', fileContent: '' }, budget);
        const input = {
            proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' } as any,
            state,
            evidence: new EvidenceLedger(),
            workItems: new WorkItemQueue(),
            handlers: new HandlerInventory(),
            candidates,
            investigation,
            scheduler: { kind: 'finish-ready' as const, reason: 'no work' },
            target: { filePath: 'src/users.ts', language: 'typescript' },
            gateMode: 'evidence' as const,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 120 }],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        };
        const result = evaluateFinishGate(input);
        const candidateReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(candidateReasons.length).toBeGreaterThan(0);
    });

    it('Go command_injection candidate passes with read coverage and claim', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordRead('handlers/exec.go', 1, 20, 20);
        investigation.recordActualRead('handlers/exec.go', 1, 20, 20, false);

        const id = candidates.register({
            rootCauseId: 'cmdi-go-1',
            type: 'command_injection',
            severity: 'critical',
            locations: [{ filePath: 'handlers/exec.go', line: 15 }],
            claim: 'Attacker injects OS commands via unsanitized user input passed to exec.Command',
        });
        candidates.addEvidence(id, 'backfill:source:handlers/exec.go', 'source', 'source');

        const input = makeGateInput({
            candidates,
            investigation,
            target: { filePath: 'handlers/exec.go', language: 'go' },
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 20 }],
                targetRange: { start: 1, end: 20 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        const candidateReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(candidateReasons).toHaveLength(0);
    });
});

describe('InvestigationState — recovery action language awareness', () => {
    it('recommends search_code instead of check_policy for unsupported language', () => {
        const state = new InvestigationState();
        state.markStepComplete('initial-read');
        state.markStepComplete('auth-symbol-search');
        state.markStepComplete('config-inspection');
        state.markStepComplete('all-handlers-reviewed');
        state.markStepComplete('candidates-verified');
        const action = state.getRecommendedRecoveryAction('go');
        expect(action).not.toBe('check_policy');
        expect(action).not.toBe('trace_flow_cross_file');
    });

    it('recommends search_code for cross-file-flow with unsupported language', () => {
        const state = new InvestigationState();
        state.markStepComplete('initial-read');
        state.markStepComplete('policy-check');
        state.markStepComplete('auth-symbol-search');
        state.markStepComplete('config-inspection');
        state.markStepComplete('all-handlers-reviewed');
        state.markStepComplete('candidates-verified');
        const action = state.getRecommendedRecoveryAction('go');
        expect(action).toBe('search_code');
    });

    it('still recommends trace_flow_cross_file for supported language', () => {
        const state = new InvestigationState();
        state.markStepComplete('initial-read');
        state.markStepComplete('policy-check');
        state.markStepComplete('auth-symbol-search');
        state.markStepComplete('config-inspection');
        state.markStepComplete('all-handlers-reviewed');
        state.markStepComplete('candidates-verified');
        const action = state.getRecommendedRecoveryAction('typescript');
        expect(action).toBe('trace_flow_cross_file');
    });

    it('legacy call with no language still returns check_policy', () => {
        const state = new InvestigationState();
        state.markStepComplete('initial-read');
        state.markStepComplete('auth-symbol-search');
        state.markStepComplete('config-inspection');
        state.markStepComplete('all-handlers-reviewed');
        state.markStepComplete('candidates-verified');
        state.markStepComplete('cross-file-flow');
        const action = state.getRecommendedRecoveryAction();
        expect(action).toBe('check_policy');
    });
});
