import { describe, it, expect } from 'vitest';
import {
    scoreCase,
    aggregateMetrics,
    formatMetricsMarkdown,
    type AgentEvalFixture,
    type AgentEvalFinding,
} from '../src/tooling/agentEvalScoring';

describe('scoreCase', () => {
    const vulnFixture: AgentEvalFixture = {
        id: 'v1', class: 'sqli', language: 'typescript', framework: 'express',
        verdict: 'vulnerable', expectLine: 10, expectType: 'sql_injection',
    };
    const safeFixture: AgentEvalFixture = {
        id: 's1', class: 'sqli', language: 'typescript', framework: 'express',
        verdict: 'safe',
    };

    it('scores a true positive (finding at expected line+type)', () => {
        const findings: AgentEvalFinding[] = [
            { line: 10, type: 'sql_injection', severity: 'critical', confidence: 85, proven: 'PROVEN' },
        ];
        const result = scoreCase(vulnFixture, findings);
        expect(result.found).toBe(true);
        expect(result.strictFound).toBe(true);
        expect(result.provenCount).toBe(1);
    });

    it('scores a false positive on a safe fixture', () => {
        const findings: AgentEvalFinding[] = [
            { line: 5, type: 'xss', severity: 'high', confidence: 70, proven: 'INCONCLUSIVE' },
        ];
        const result = scoreCase(safeFixture, findings);
        expect(result.found).toBe(true);
        expect(result.expected).toBe('safe');
    });

    it('scores a false negative (no findings on vulnerable fixture)', () => {
        const result = scoreCase(vulnFixture, []);
        expect(result.found).toBe(false);
        expect(result.strictFound).toBe(false);
    });

    it('scores strict miss (finding at wrong line or type)', () => {
        const findings: AgentEvalFinding[] = [
            { line: 20, type: 'sql_injection', severity: 'high', confidence: 80, proven: 'INCONCLUSIVE' },
        ];
        const result = scoreCase(vulnFixture, findings);
        expect(result.found).toBe(true);
        expect(result.strictFound).toBe(false);
    });

    it('tracks infrastructure failures separately', () => {
        const result = scoreCase(vulnFixture, [], true, 'API timeout');
        expect(result.infraFailure).toBe(true);
        expect(result.infraError).toBe('API timeout');
        expect(result.found).toBe(false);
    });

    it('normalizes vulnerability types (SQL_Injection → sql_injection)', () => {
        const findings: AgentEvalFinding[] = [
            { line: 10, type: 'SQL-Injection', severity: 'critical', confidence: 90, proven: 'PROVEN' },
        ];
        const result = scoreCase(vulnFixture, findings);
        expect(result.strictFound).toBe(true);
    });
});

describe('aggregateMetrics', () => {
    const vulnFixture: AgentEvalFixture = {
        id: 'v1', class: 'sqli', language: 'typescript', framework: 'express',
        verdict: 'vulnerable', expectLine: 10, expectType: 'sql_injection',
    };
    const safeFixture: AgentEvalFixture = {
        id: 's1', class: 'sqli', language: 'typescript', framework: 'express',
        verdict: 'safe',
    };

    it('computes precision, recall, FPR correctly', () => {
        const results = [
            scoreCase(vulnFixture, [{ line: 10, type: 'sql_injection', severity: 'high', confidence: 85, proven: 'PROVEN' }], false, undefined, 15, 0.03, 5000),
            scoreCase(vulnFixture, [], false, undefined, 20, 0.04, 6000), // FN
            scoreCase(safeFixture, [{ line: 3, type: 'xss', severity: 'medium', confidence: 60, proven: 'INCONCLUSIVE' }], false, undefined, 10, 0.02, 3000), // FP
            scoreCase(safeFixture, [], false, undefined, 8, 0.01, 2000), // TN
        ];
        const m = aggregateMetrics(results);
        expect(m.tp).toBe(1);
        expect(m.fn).toBe(1);
        expect(m.fp).toBe(1);
        expect(m.tn).toBe(1);
        expect(m.recall).toBe(0.5);
        expect(m.precision).toBe(0.5);
        expect(m.fpr).toBe(0.5);
        expect(m.infraFailures).toBe(0);
        expect(m.completionRate).toBe(1);
    });

    it('excludes infra failures from recall/precision but tracks them', () => {
        const results = [
            scoreCase(vulnFixture, [{ line: 10, type: 'sql_injection', severity: 'high', confidence: 85, proven: 'PROVEN' }]),
            scoreCase(vulnFixture, [], true, 'timeout'), // infra failure
        ];
        const m = aggregateMetrics(results);
        expect(m.tp).toBe(1);
        expect(m.fn).toBe(0); // infra failure excluded
        expect(m.infraFailures).toBe(1);
        expect(m.completionRate).toBe(1);
    });

    it('computes verify verdict rates', () => {
        const results = [
            scoreCase(vulnFixture, [
                { line: 10, type: 'sql_injection', severity: 'high', confidence: 85, proven: 'PROVEN' },
                { line: 20, type: 'xss', severity: 'medium', confidence: 60, proven: 'INCONCLUSIVE' },
            ]),
            scoreCase(vulnFixture, [
                { line: 10, type: 'sql_injection', severity: 'high', confidence: 85, proven: 'UNPROVEN' },
            ]),
        ];
        const m = aggregateMetrics(results);
        expect(m.provenRate).toBe(1/3);
        expect(m.unprovenRate).toBe(1/3);
        expect(m.inconclusiveRate).toBe(1/3);
    });

    it('computes mean cost/steps/latency', () => {
        const results = [
            scoreCase(vulnFixture, [{ line: 10, type: 'sql_injection', severity: 'high', confidence: 85, proven: 'PROVEN' }], false, undefined, 10, 0.05, 3000),
            scoreCase(safeFixture, [], false, undefined, 5, 0.02, 1500),
        ];
        const m = aggregateMetrics(results);
        expect(m.meanSteps).toBe(7.5);
        expect(m.meanCostUsd).toBe(0.035);
        expect(m.meanLatencyMs).toBe(2250);
    });

    it('handles empty results without dividing by zero', () => {
        const m = aggregateMetrics([]);
        expect(m.recall).toBe(0);
        expect(m.precision).toBe(1);
        expect(m.fpr).toBe(0);
    });
});

describe('formatMetricsMarkdown', () => {
    it('produces a markdown table with all metrics', () => {
        const m = aggregateMetrics([
            scoreCase(
                { id: 'v1', class: 'sqli', language: 'ts', framework: 'express', verdict: 'vulnerable', expectLine: 1, expectType: 'sql_injection' },
                [{ line: 1, type: 'sql_injection', severity: 'high', confidence: 85, proven: 'PROVEN' }],
            ),
        ]);
        const md = formatMetricsMarkdown(m);
        expect(md).toContain('Recall');
        expect(md).toContain('100.0%');
        expect(md).toContain('Precision');
        expect(md).toContain('Proven Rate');
    });
});
