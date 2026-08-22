import { describe, it, expect } from 'vitest';
import { evaluateProofGate, buildProofEvidence } from '../src/attack/proofGate';
import type { ParsedProofMarker } from '../src/attack/proofTypes';

function validMarker(sourceMode: 'real-import' | 'real-server' = 'real-import'): ParsedProofMarker {
    return {
        found: true,
        baseline: 'pass',
        exploit: 'pass',
        impact: 'observed',
        targetReached: true,
        assertion: 'deterministic',
        mockedVulnerablePath: false,
        sourceMode,
    };
}

const validContext = {
    sandboxBackend: 'docker',
    targetFile: 'src/http.ts',
    targetLine: 100,
    repeatedRuns: 3,
    repeatPasses: 3,
    llmVerdict: 'PROVEN' as const,
};

describe('evaluateProofGate', () => {
    it('passes all gates for valid real-import proof', () => {
        const result = evaluateProofGate(validMarker('real-import'), validContext);
        expect(result.eligibleForProven).toBe(true);
        expect(result.failedGates).toHaveLength(0);
        expect(result.downgradedVerdict).toBe('PROVEN');
    });

    it('passes all gates for valid real-server proof', () => {
        const result = evaluateProofGate(validMarker('real-server'), validContext);
        expect(result.eligibleForProven).toBe(true);
        expect(result.downgradedVerdict).toBe('PROVEN');
    });

    it('rejects PROVEN when proof marker is missing', () => {
        const result = evaluateProofGate({ found: false }, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('proof-marker-missing');
        expect(result.downgradedVerdict).toBe('INCONCLUSIVE');
    });

    it('rejects PROVEN for synthetic source mode', () => {
        const result = evaluateProofGate(validMarker('synthetic'), validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('synthetic-source');
        expect(result.downgradedVerdict).toBe('INCONCLUSIVE');
    });

    it('rejects PROVEN for extracted-logic source mode', () => {
        const result = evaluateProofGate(validMarker('extracted-logic'), validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('extracted-logic-source');
        expect(result.downgradedVerdict).toBe('INCONCLUSIVE');
    });

    it('rejects PROVEN when vulnerable path is mocked', () => {
        const marker = { ...validMarker(), mockedVulnerablePath: true };
        const result = evaluateProofGate(marker, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('mock-vulnerable-path');
    });

    it('rejects PROVEN when target not reached', () => {
        const marker = { ...validMarker(), targetReached: false };
        const result = evaluateProofGate(marker, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('target-not-reached');
    });

    it('rejects PROVEN when baseline fails', () => {
        const marker = { ...validMarker(), baseline: 'fail' as const };
        const result = evaluateProofGate(marker, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('baseline-failed');
    });

    it('downgrades to UNPROVEN when exploit fails', () => {
        const marker = { ...validMarker(), exploit: 'fail' as const };
        const result = evaluateProofGate(marker, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('exploit-failed');
        expect(result.downgradedVerdict).toBe('UNPROVEN');
    });

    it('downgrades to UNPROVEN when impact not observed', () => {
        const marker = { ...validMarker(), impact: 'not-observed' as const };
        const result = evaluateProofGate(marker, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('impact-not-observed');
        expect(result.downgradedVerdict).toBe('UNPROVEN');
    });

    it('rejects PROVEN for non-deterministic assertion', () => {
        const marker = { ...validMarker(), assertion: 'llm-only' as const };
        const result = evaluateProofGate(marker, validContext);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('non-deterministic-assertion');
    });

    it('rejects PROVEN with insufficient repeats', () => {
        const ctx = { ...validContext, repeatedRuns: 1, repeatPasses: 1, minimumRepeatRuns: 3 };
        const result = evaluateProofGate(validMarker(), ctx);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('insufficient-repeats');
    });

    it('rejects PROVEN for flaky proof (2/3 passes)', () => {
        const ctx = { ...validContext, repeatedRuns: 3, repeatPasses: 2, minimumRepeatRuns: 3 };
        const result = evaluateProofGate(validMarker(), ctx);
        expect(result.eligibleForProven).toBe(false);
        expect(result.failedGates).toContain('flaky-proof');
    });

    it('warns when LLM said PROVEN but gates fail', () => {
        const marker = { ...validMarker(), impact: 'not-observed' as const };
        const result = evaluateProofGate(marker, validContext);
        expect(result.warnings).toContain('LLM said PROVEN but deterministic gates failed — downgrading');
    });

    it('warns when gates pass but LLM did not say PROVEN', () => {
        const ctx = { ...validContext, llmVerdict: 'INCONCLUSIVE' as const };
        const result = evaluateProofGate(validMarker(), ctx);
        expect(result.eligibleForProven).toBe(true);
        expect(result.warnings).toContain('LLM verdict was not PROVEN but proof marker passed — overriding to PROVEN');
    });
});

describe('buildProofEvidence', () => {
    it('builds evidence from valid marker', () => {
        const evidence = buildProofEvidence(validMarker(), {
            sandboxBackend: 'docker',
            targetFile: 'src/http.ts',
            targetLine: 100,
            repeatedRuns: 3,
            repeatPasses: 3,
        });
        expect(evidence.sourceMode).toBe('real-import');
        expect(evidence.reachedTarget).toBe(true);
        expect(evidence.baselinePassed).toBe(true);
        expect(evidence.exploitPassed).toBe(true);
        expect(evidence.impactObserved).toBe(true);
        expect(evidence.deterministicAssertion).toBe(true);
        expect(evidence.mocksVulnerablePath).toBe(false);
        expect(evidence.repeatedRuns).toBe(3);
        expect(evidence.repeatPasses).toBe(3);
        expect(evidence.proofId).toBeTruthy();
    });

    it('defaults to synthetic when sourceMode missing', () => {
        const marker: ParsedProofMarker = { ...validMarker(), sourceMode: undefined };
        const evidence = buildProofEvidence(marker, {
            sandboxBackend: 'docker',
            targetFile: 'src/http.ts',
            targetLine: 100,
            repeatedRuns: 3,
            repeatPasses: 3,
        });
        expect(evidence.sourceMode).toBe('synthetic');
    });
});
