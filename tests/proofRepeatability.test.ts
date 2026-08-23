import { describe, it, expect } from 'vitest';
import type { ProofRunResult } from '../src/attack/proofTypes';

describe('ProofRunResult validation', () => {
    it('a run is only "passed" if all properties are valid', () => {
        const run: ProofRunResult = {
            runIndex: 1,
            verdict: 'pass',
            markerValid: true,
            targetReached: true,
            impactObserved: true,
        };
        expect(
            run.verdict === 'pass' &&
            run.markerValid &&
            run.targetReached &&
            run.impactObserved,
        ).toBe(true);
    });

    it('a run with verdict=pass but missing marker is NOT passed', () => {
        const run: ProofRunResult = {
            runIndex: 1,
            verdict: 'pass',
            markerValid: false,
            targetReached: true,
            impactObserved: true,
        };
        expect(
            run.verdict === 'pass' &&
            run.markerValid &&
            run.targetReached &&
            run.impactObserved,
        ).toBe(false);
    });

    it('a run with verdict=pass but no target reached is NOT passed', () => {
        const run: ProofRunResult = {
            runIndex: 1,
            verdict: 'pass',
            markerValid: true,
            targetReached: false,
            impactObserved: true,
        };
        expect(
            run.verdict === 'pass' &&
            run.markerValid &&
            run.targetReached &&
            run.impactObserved,
        ).toBe(false);
    });

    it('a run with verdict=pass but no impact is NOT passed', () => {
        const run: ProofRunResult = {
            runIndex: 1,
            verdict: 'pass',
            markerValid: true,
            targetReached: true,
            impactObserved: false,
        };
        expect(
            run.verdict === 'pass' &&
            run.markerValid &&
            run.targetReached &&
            run.impactObserved,
        ).toBe(false);
    });

    it('a run with verdict=fail is NOT passed regardless of other properties', () => {
        const run: ProofRunResult = {
            runIndex: 1,
            verdict: 'fail',
            markerValid: true,
            targetReached: true,
            impactObserved: true,
        };
        expect(
            run.verdict === 'pass' &&
            run.markerValid &&
            run.targetReached &&
            run.impactObserved,
        ).toBe(false);
    });

    it('3/3 complete proof runs are required for PROVEN', () => {
        const runs: ProofRunResult[] = [
            { runIndex: 1, verdict: 'pass', markerValid: true, targetReached: true, impactObserved: true },
            { runIndex: 2, verdict: 'pass', markerValid: true, targetReached: true, impactObserved: true },
            { runIndex: 3, verdict: 'pass', markerValid: true, targetReached: true, impactObserved: true },
        ];
        const totalPasses = runs.filter(r =>
            r.verdict === 'pass' &&
            r.markerValid &&
            r.targetReached &&
            r.impactObserved,
        ).length;
        expect(totalPasses).toBe(3);
        expect(totalPasses).toBe(runs.length);
    });

    it('2/3 complete proof runs is flaky (not PROVEN)', () => {
        const runs: ProofRunResult[] = [
            { runIndex: 1, verdict: 'pass', markerValid: true, targetReached: true, impactObserved: true },
            { runIndex: 2, verdict: 'pass', markerValid: true, targetReached: true, impactObserved: true },
            { runIndex: 3, verdict: 'pass', markerValid: false, targetReached: true, impactObserved: true },
        ];
        const totalPasses = runs.filter(r =>
            r.verdict === 'pass' &&
            r.markerValid &&
            r.targetReached &&
            r.impactObserved,
        ).length;
        expect(totalPasses).toBe(2);
        expect(totalPasses).toBeLessThan(runs.length);
    });
});
