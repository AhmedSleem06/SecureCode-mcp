import { describe, it, expect } from 'vitest';
import { validateProvenInvariant } from '../src/audit/scanAuditLog';

describe('validateProvenInvariant', () => {
    it('passes for a valid PROVEN finding', () => {
        const findings = [{
            proven: 'PROVEN',
            proofEvidence: {
                sourceMode: 'real-import',
                repeatedRuns: 3,
                repeatPasses: 3,
                assumptions: [],
            },
            proofGateResult: { eligibleForProven: true },
        }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(0);
    });

    it('fails for missing proofEvidence', () => {
        const findings = [{ proven: 'PROVEN' }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].violations).toContain('missing proofEvidence');
    });

    it('fails for ineligible proof gate', () => {
        const findings = [{
            proven: 'PROVEN',
            proofEvidence: { sourceMode: 'real-import', repeatedRuns: 3, repeatPasses: 3, assumptions: [] },
            proofGateResult: { eligibleForProven: false },
        }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].violations).toContain('proofGateResult.eligibleForProven is not true');
    });

    it('fails for synthetic source mode', () => {
        const findings = [{
            proven: 'PROVEN',
            proofEvidence: { sourceMode: 'synthetic', repeatedRuns: 3, repeatPasses: 3, assumptions: [] },
            proofGateResult: { eligibleForProven: true },
        }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].violations.some(v => v.includes('sourceMode'))).toBe(true);
    });

    it('fails for insufficient repeated runs', () => {
        const findings = [{
            proven: 'PROVEN',
            proofEvidence: { sourceMode: 'real-import', repeatedRuns: 2, repeatPasses: 2, assumptions: [] },
            proofGateResult: { eligibleForProven: true },
        }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].violations.some(v => v.includes('repeatedRuns'))).toBe(true);
    });

    it('fails for flaky proof (repeatPasses !== repeatedRuns)', () => {
        const findings = [{
            proven: 'PROVEN',
            proofEvidence: { sourceMode: 'real-import', repeatedRuns: 3, repeatPasses: 2, assumptions: [] },
            proofGateResult: { eligibleForProven: true },
        }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].violations.some(v => v.includes('flaky'))).toBe(true);
    });

    it('fails for failed mutation test', () => {
        const findings = [{
            proven: 'PROVEN',
            proofEvidence: {
                sourceMode: 'real-import',
                repeatedRuns: 3,
                repeatPasses: 3,
                assumptions: ['mutation-test: non-discriminating'],
            },
            proofGateResult: { eligibleForProven: true },
        }];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].violations.some(v => v.includes('mutation'))).toBe(true);
    });

    it('ignores non-PROVEN findings', () => {
        const findings = [
            { proven: 'UNPROVEN' },
            { proven: 'INCONCLUSIVE' },
            { verdict: 'NOT_REPRODUCIBLE' },
        ];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(0);
    });

    it('handles multiple findings with mixed violations', () => {
        const findings = [
            { proven: 'PROVEN', proofEvidence: { sourceMode: 'real-import', repeatedRuns: 3, repeatPasses: 3, assumptions: [] }, proofGateResult: { eligibleForProven: true } },
            { proven: 'PROVEN' },
            { proven: 'UNPROVEN' },
        ];
        const checks = validateProvenInvariant(findings);
        expect(checks).toHaveLength(1);
        expect(checks[0].findingIndex).toBe(1);
    });
});
