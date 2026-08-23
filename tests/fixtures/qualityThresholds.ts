/**
 * Quality thresholds for the Synara regression harness.
 *
 * These thresholds gate whether a scan run passes the quality bar.
 * Adjust them as the agent improves — start strict and relax only
 * when the metric is consistently met.
 */

export const QUALITY_THRESHOLDS = {
    /** Every PROVEN finding must be a true positive (no false positives). */
    strictProvenPrecision: 1.0,
    /** The agent must find at least 90% of known vulnerabilities. */
    candidateRecall: 0.90,
    /** At least 90% of critical line ranges must be read. */
    criticalRangeCoverage: 0.90,
    /** The same file must produce the same verdict at least 80% of the time. */
    classificationConsistency: 0.80,
    /** At most 10% of steps may be blocked (duplicate/overlapping reads). */
    blockedActionRate: 0.10,
    /** At most 10% of searches may be equivalent duplicates. */
    repeatedSearchRate: 0.10,
    /** At least 90% of required cross-file flow traces must be performed. */
    requiredCrossFileFlowRate: 0.90,
    /** At least 90% of required policy checks must be performed. */
    requiredPolicyCheckRate: 0.90,
    /** Zero unhandled critical coverage gaps. */
    unhandledCriticalGaps: 0,
} as const;

export interface QualityMetricResult {
    name: string;
    value: number;
    threshold: number;
    passed: boolean;
}

export function checkThreshold(
    name: keyof typeof QUALITY_THRESHOLDS,
    value: number,
): QualityMetricResult {
    const threshold = QUALITY_THRESHOLDS[name];
    // For "rate" metrics (higher is better), pass when value >= threshold.
    // For "max" metrics (blockedActionRate, repeatedSearchRate, unhandledCriticalGaps),
    // pass when value <= threshold.
    const isMaxMetric = name === 'blockedActionRate' || name === 'repeatedSearchRate' || name === 'unhandledCriticalGaps';
    const passed = isMaxMetric ? value <= threshold : value >= threshold;
    return { name, value, threshold, passed };
}

export function checkAllThresholds(metrics: Record<string, number>): QualityMetricResult[] {
    return Object.keys(QUALITY_THRESHOLDS).map(name =>
        checkThreshold(name as keyof typeof QUALITY_THRESHOLDS, metrics[name] ?? 0),
    );
}
