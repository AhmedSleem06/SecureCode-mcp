import { describe, it, expect } from 'vitest';
import {
    QUALITY_THRESHOLDS,
    checkThreshold,
    checkAllThresholds,
} from './fixtures/qualityThresholds';

describe('Quality Thresholds', () => {
    it('defines strict proven precision = 1.0', () => {
        expect(QUALITY_THRESHOLDS.strictProvenPrecision).toBe(1.0);
    });

    it('defines candidate recall >= 0.90', () => {
        expect(QUALITY_THRESHOLDS.candidateRecall).toBeGreaterThanOrEqual(0.90);
    });

    it('defines critical range coverage >= 0.90', () => {
        expect(QUALITY_THRESHOLDS.criticalRangeCoverage).toBeGreaterThanOrEqual(0.90);
    });

    it('defines blocked action rate <= 0.10', () => {
        expect(QUALITY_THRESHOLDS.blockedActionRate).toBeLessThanOrEqual(0.10);
    });

    it('defines zero unhandled critical gaps', () => {
        expect(QUALITY_THRESHOLDS.unhandledCriticalGaps).toBe(0);
    });

    it('checkThreshold passes for a rate metric meeting the threshold', () => {
        const result = checkThreshold('candidateRecall', 0.95);
        expect(result.passed).toBe(true);
    });

    it('checkThreshold fails for a rate metric below the threshold', () => {
        const result = checkThreshold('candidateRecall', 0.80);
        expect(result.passed).toBe(false);
    });

    it('checkThreshold passes for a max metric at or below the threshold', () => {
        const result = checkThreshold('blockedActionRate', 0.05);
        expect(result.passed).toBe(true);
    });

    it('checkThreshold fails for a max metric above the threshold', () => {
        const result = checkThreshold('blockedActionRate', 0.15);
        expect(result.passed).toBe(false);
    });

    it('checkAllThresholds evaluates all metrics', () => {
        const metrics = {
            strictProvenPrecision: 1.0,
            candidateRecall: 0.90,
            criticalRangeCoverage: 0.90,
            classificationConsistency: 0.80,
            blockedActionRate: 0.10,
            repeatedSearchRate: 0.10,
            requiredCrossFileFlowRate: 0.90,
            requiredPolicyCheckRate: 0.90,
            unhandledCriticalGaps: 0,
        };
        const results = checkAllThresholds(metrics);
        expect(results).toHaveLength(Object.keys(QUALITY_THRESHOLDS).length);
        expect(results.every(r => r.passed)).toBe(true);
    });

    it('checkAllThresholds fails when any metric is below threshold', () => {
        const metrics = {
            strictProvenPrecision: 0.95,
            candidateRecall: 0.90,
            criticalRangeCoverage: 0.90,
            classificationConsistency: 0.80,
            blockedActionRate: 0.10,
            repeatedSearchRate: 0.10,
            requiredCrossFileFlowRate: 0.90,
            requiredPolicyCheckRate: 0.90,
            unhandledCriticalGaps: 0,
        };
        const results = checkAllThresholds(metrics);
        expect(results.some(r => !r.passed)).toBe(true);
    });
});
