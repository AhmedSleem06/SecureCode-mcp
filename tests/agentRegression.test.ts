import { describe, it, expect } from 'vitest';
import { checkRegression, formatRegressionResult, type AgentEvalReport } from '../src/tooling/agentRegression';
import type { AgentEvalMetrics } from '../src/tooling/agentEvalScoring';

function makeMetrics(overrides: Partial<AgentEvalMetrics> = {}): AgentEvalMetrics {
    return {
        tp: 8, fn: 2, fp: 1, tn: 9,
        recall: 0.8, precision: 0.8889, fpr: 0.1, f1: 0.8421,
        total: 20, totalRealVuln: 10, totalSafe: 10,
        infraFailures: 0,
        completionRate: 1.0,
        provenRate: 0.5, unprovenRate: 0.2, inconclusiveRate: 0.3,
        meanSteps: 15, meanCostUsd: 0.05, meanLatencyMs: 30000,
        ...overrides,
    };
}

function makeReport(metrics: AgentEvalMetrics, overrides: Partial<AgentEvalReport> = {}): AgentEvalReport {
    return {
        timestamp: '2026-08-19T00:00:00Z',
        manifest_version: 1,
        fixtureCount: 20,
        metrics,
        results: [],
        targets: { recall_min: 0.70, precision_min: 0.70, fpr_max: 0.30, completion_rate_min: 0.90 },
        pass: true,
        cacheVersion: 31,
        commitSha: 'abc12345def67890',
        ...overrides,
    };
}

describe('checkRegression', () => {
    const SHA = 'abc12345def67890';

    it('passes when candidate is equal or better than baseline', () => {
        const baseline = makeReport(makeMetrics());
        const candidate = makeReport(makeMetrics({ precision: 0.90, recall: 0.85 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(true);
        expect(result.reasons).toHaveLength(0);
    });

    it('fails when precision drops more than 0.02', () => {
        const baseline = makeReport(makeMetrics({ precision: 0.8889 }));
        const candidate = makeReport(makeMetrics({ precision: 0.85 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Precision dropped'))).toBe(true);
    });

    it('fails when recall drops more than 0.02', () => {
        const baseline = makeReport(makeMetrics({ recall: 0.80 }));
        const candidate = makeReport(makeMetrics({ recall: 0.77 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Recall dropped'))).toBe(true);
    });

    it('fails when completion rate drops more than 0.03', () => {
        const baseline = makeReport(makeMetrics({ completionRate: 1.0 }));
        const candidate = makeReport(makeMetrics({ completionRate: 0.95 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Completion rate dropped'))).toBe(true);
    });

    it('passes when precision drops within threshold (≤0.02)', () => {
        const baseline = makeReport(makeMetrics({ precision: 0.8889 }));
        const candidate = makeReport(makeMetrics({ precision: 0.88 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(true);
    });

    it('fails on fixture count mismatch', () => {
        const baseline = makeReport(makeMetrics(), { fixtureCount: 20 });
        const candidate = makeReport(makeMetrics(), { fixtureCount: 15 });
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Fixture count mismatch'))).toBe(true);
    });

    it('fails on manifest version mismatch', () => {
        const baseline = makeReport(makeMetrics(), { manifest_version: 1 });
        const candidate = makeReport(makeMetrics(), { manifest_version: 2 });
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Manifest version mismatch'))).toBe(true);
    });

    it('fails on cache version mismatch (stale result)', () => {
        const baseline = makeReport(makeMetrics());
        const candidate = makeReport(makeMetrics(), { cacheVersion: 20 });
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Cache version mismatch'))).toBe(true);
    });

    it('fails on multiple regressions simultaneously', () => {
        const baseline = makeReport(makeMetrics({ precision: 0.90, recall: 0.85, completionRate: 1.0 }));
        const candidate = makeReport(makeMetrics({ precision: 0.80, recall: 0.75, completionRate: 0.90 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.length).toBeGreaterThanOrEqual(3);
    });

    it('fails on commit SHA mismatch', () => {
        const baseline = makeReport(makeMetrics());
        const candidate = makeReport(makeMetrics(), { commitSha: 'different12345678' });
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        expect(result.passed).toBe(false);
        expect(result.reasons.some(r => r.includes('Commit SHA mismatch'))).toBe(true);
    });
});

describe('formatRegressionResult', () => {
    const SHA = 'abc12345def67890';

    it('produces a markdown table with PASS status', () => {
        const baseline = makeReport(makeMetrics());
        const candidate = makeReport(makeMetrics());
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        const md = formatRegressionResult(result);
        expect(md).toContain('PASS');
        expect(md).toContain('Precision');
        expect(md).toContain('Recall');
        expect(md).toContain('Completion Rate');
    });

    it('produces a markdown table with FAIL status and reasons', () => {
        const baseline = makeReport(makeMetrics({ precision: 0.90 }));
        const candidate = makeReport(makeMetrics({ precision: 0.80 }));
        const result = checkRegression(baseline, candidate, { currentSha: SHA });
        const md = formatRegressionResult(result);
        expect(md).toContain('FAIL');
        expect(md).toContain('Failure Reasons');
        expect(md).toContain('Precision dropped');
    });
});
