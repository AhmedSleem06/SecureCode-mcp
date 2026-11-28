import { describe, it, expect } from 'vitest';
import { evaluateFinishGate, candidateLinesDelivered } from '../src/attack/finishGate';
import { createScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { InvestigationState } from '../src/attack/investigationState';

const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
const target = { filePath: 'src/users.ts', language: 'typescript', fileContent: 'export function handler() {}' };
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
        target: { filePath: 'src/users.ts' },
        gateMode: 'evidence' as const,
        evidenceGate: {
            currentLeads: [],
            deliveredRanges: [{ start: 1, end: 120 }],
            targetRange: { start: 1, end: 120 },
            openLeadsRejectedOnce: true,
        },
        ...overrides,
    };
}

function registerCandidate(store: CandidateStore, line: number, file = 'src/users.ts') {
    return store.register({
        rootCauseId: `bac-L${line}`,
        type: 'broken_access_control',
        severity: 'high',
        locations: [{ filePath: file, line }],
        claim: 'Any authenticated user can escalate privileges by modifying the role field',
    });
}

describe('Source crediting — line-level accounting', () => {

    it('(a) finding L50, prompt delivered lines 1-120, no read_file → source credited, finish not rejected for source', () => {
        const candidates = new CandidateStore();
        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        const input = makeInput({ candidates });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).toContain('source');
        const sourceReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions' && r.description.includes('source'));
        expect(sourceReasons).toHaveLength(0);
    });

    it('(b) only lines 1-10 of the same file read/delivered → source not credited for L50', () => {
        const candidates = new CandidateStore();
        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        const input = makeInput({ candidates });
        input.evidenceGate = {
            ...input.evidenceGate,
            deliveredRanges: [{ start: 1, end: 10 }],
        };
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).not.toContain('source');
        const reasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(reasons.length).toBeGreaterThan(0);
        expect(reasons[0].description).toContain('source');
    });

    it('(c) read requested 1-80 but delivered only to line 30 (truncated) → source not credited for L50', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordActualRead('src/users.ts', 1, 30, 120, true);

        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        const input = makeInput({
            candidates,
            investigation,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 30 }],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).not.toContain('source');
        const reasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(reasons.length).toBeGreaterThan(0);
        expect(reasons[0].description).toContain('source');
    });

    it('(d) line 50 delivered from a different file → source not credited', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordActualRead('other/file.ts', 1, 100, 100, false);

        const id = registerCandidate(candidates, 50, 'src/users.ts');
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        const input = makeInput({
            candidates,
            investigation,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).not.toContain('source');
        const reasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(reasons.length).toBeGreaterThan(0);
    });

    it('(e-hit) candidate registered BEFORE the read, L50 is covered by investigation → source credited', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();

        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const input = makeInput({
            candidates,
            investigation,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 120 }],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).toContain('source');
        const sourceReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions' && r.description.includes('source'));
        expect(sourceReasons).toHaveLength(0);
    });

    it('(e-miss) candidate registered BEFORE the read, only lines 1-10 delivered → source not credited', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();

        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        investigation.recordActualRead('src/users.ts', 1, 10, 120, false);

        const input = makeInput({
            candidates,
            investigation,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 10 }],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).not.toContain('source');
        const reasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(reasons.length).toBeGreaterThan(0);
    });

    it('(e-after-hit) candidate registered AFTER a read that covers L50 → source credited at gate', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();

        investigation.recordActualRead('src/users.ts', 1, 120, 120, false);

        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        const input = makeInput({
            candidates,
            investigation,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 120 }],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).toContain('source');
        const sourceReasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions' && r.description.includes('source'));
        expect(sourceReasons).toHaveLength(0);
    });

    it('(e-after-miss) candidate registered AFTER a read that covers only 1-10 → source not credited', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();

        investigation.recordActualRead('src/users.ts', 1, 10, 120, false);

        const id = registerCandidate(candidates, 50);
        candidates.addEvidence(id, 'guard-control:x', 'guard', 'control');

        const input = makeInput({
            candidates,
            investigation,
            evidenceGate: {
                currentLeads: [],
                deliveredRanges: [{ start: 1, end: 10 }],
                targetRange: { start: 1, end: 120 },
                openLeadsRejectedOnce: true,
            },
        });
        const result = evaluateFinishGate(input);
        expect(candidates.get(id)!.satisfiedDimensions).not.toContain('source');
        const reasons = (result.advice ?? []).filter(r => r.code === 'candidate-open-questions');
        expect(reasons.length).toBeGreaterThan(0);
    });
});

describe('candidateLinesDelivered — shared helper unit tests', () => {

    it('returns vulnDelivered true when line is in deliveredRanges', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        const id = registerCandidate(candidates, 50);
        const cand = candidates.get(id)!;

        const result = candidateLinesDelivered(cand, investigation, 'src/users.ts', [{ start: 1, end: 120 }]);
        expect(result.vulnDelivered).toBe(true);
    });

    it('returns vulnDelivered true when line is in investigation coverage', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordActualRead('src/users.ts', 40, 60, 120, false);
        const id = registerCandidate(candidates, 50);
        const cand = candidates.get(id)!;

        const result = candidateLinesDelivered(cand, investigation);
        expect(result.vulnDelivered).toBe(true);
    });

    it('returns vulnDelivered false when line is not in any delivered range', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordActualRead('src/users.ts', 1, 10, 120, false);
        const id = registerCandidate(candidates, 50);
        const cand = candidates.get(id)!;

        const result = candidateLinesDelivered(cand, investigation, 'src/users.ts', [{ start: 1, end: 10 }]);
        expect(result.vulnDelivered).toBe(false);
    });

    it('returns false when line is covered in a different file', () => {
        const candidates = new CandidateStore();
        const investigation = new InvestigationState();
        investigation.recordActualRead('other/file.ts', 1, 100, 100, false);
        const id = registerCandidate(candidates, 50, 'src/users.ts');
        const cand = candidates.get(id)!;

        const result = candidateLinesDelivered(cand, investigation, 'other/file.ts', [{ start: 1, end: 100 }]);
        expect(result.vulnDelivered).toBe(false);
    });

    it('returns false for empty candidate locations', () => {
        const investigation = new InvestigationState();
        const cand = { locations: [] } as any;
        const result = candidateLinesDelivered(cand, investigation, 'src/users.ts', [{ start: 1, end: 120 }]);
        expect(result.vulnDelivered).toBe(false);
        expect(result.entryDelivered).toBe(false);
    });
});
