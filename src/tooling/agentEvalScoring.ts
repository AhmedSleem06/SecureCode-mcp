/**
 * Agent eval scoring — pure functions for scoring Pipeline 2 scan results
 * against a golden testset.
 *
 * Scoring model:
 *   - Each fixture has an expected verdict (vulnerable | safe) and optionally
 *     an expected line + type.
 *   - A finding "matches" a vulnerable fixture if it's at the expected line
 *     with the expected type (strict) or any finding at all (loose).
 *   - A finding on a safe fixture is a false positive.
 *   - Infrastructure failures (crash, timeout, spawn_failed) are tracked
 *     separately and never count as false negatives.
 *   - Verify verdicts (PROVEN/UNPROVEN/INCONCLUSIVE) are tracked as
 *     distribution metrics, not pass/fail.
 */

export interface AgentEvalFixture {
    id: string;
    class: string;
    language: string;
    framework: string;
    verdict: 'vulnerable' | 'safe';
    expectLine?: number;
    expectType?: string;
}

export interface AgentEvalFinding {
    line: number;
    type: string;
    severity: string;
    confidence: number;
    proven: string;
    evidenceLevel?: string;
}

export interface AgentEvalCaseResult {
    fixtureId: string;
    class: string;
    language: string;
    framework: string;
    expected: 'vulnerable' | 'safe';
    found: boolean;
    strictFound: boolean;
    findingCount: number;
    reportedTypes: string[];
    reportedLines: number[];
    provenCount: number;
    unprovenCount: number;
    inconclusiveCount: number;
    skippedCount: number;
    infraFailure: boolean;
    infraError?: string;
    stepsUsed: number;
    costSpentUsd: number;
    latencyMs: number;
}

export interface AgentEvalMetrics {
    tp: number;
    fn: number;
    fp: number;
    tn: number;
    recall: number;
    precision: number;
    fpr: number;
    f1: number;
    total: number;
    totalRealVuln: number;
    totalSafe: number;
    infraFailures: number;
    completionRate: number;
    provenRate: number;
    unprovenRate: number;
    inconclusiveRate: number;
    meanSteps: number;
    meanCostUsd: number;
    meanLatencyMs: number;
}

function normalizeType(t: string): string {
    return (t || '').toLowerCase().replace(/[\s-]+/g, '_');
}

export function scoreCase(
    fixture: AgentEvalFixture,
    findings: AgentEvalFinding[],
    infraFailure: boolean = false,
    infraError?: string,
    stepsUsed: number = 0,
    costSpentUsd: number = 0,
    latencyMs: number = 0,
): AgentEvalCaseResult {
    const reportedTypes = findings.map(f => normalizeType(f.type));
    const reportedLines = findings.map(f => f.line);

    const found = findings.length > 0;
    let strictFound = false;

    if (fixture.verdict === 'vulnerable' && fixture.expectLine && fixture.expectType) {
        const expectedType = normalizeType(fixture.expectType);
        strictFound = findings.some(f =>
            f.line === fixture.expectLine && normalizeType(f.type) === expectedType
        );
    } else if (fixture.verdict === 'vulnerable') {
        strictFound = found;
    }

    const provenCount = findings.filter(f => f.proven === 'PROVEN').length;
    const unprovenCount = findings.filter(f => f.proven === 'UNPROVEN').length;
    const inconclusiveCount = findings.filter(f => f.proven === 'INCONCLUSIVE').length;
    const skippedCount = findings.filter(f => f.proven === 'SKIPPED').length;

    return {
        fixtureId: fixture.id,
        class: fixture.class,
        language: fixture.language,
        framework: fixture.framework,
        expected: fixture.verdict,
        found,
        strictFound,
        findingCount: findings.length,
        reportedTypes,
        reportedLines,
        provenCount,
        unprovenCount,
        inconclusiveCount,
        skippedCount,
        infraFailure,
        infraError,
        stepsUsed,
        costSpentUsd,
        latencyMs,
    };
}

export function aggregateMetrics(results: AgentEvalCaseResult[]): AgentEvalMetrics {
    let tp = 0, fn = 0, fp = 0, tn = 0;
    let infraFailures = 0;
    let totalSteps = 0;
    let totalCost = 0;
    let totalLatency = 0;
    let totalProven = 0;
    let totalUnproven = 0;
    let totalInconclusive = 0;
    let completedRuns = 0;

    for (const r of results) {
        if (r.infraFailure) {
            infraFailures++;
            continue;
        }

        totalSteps += r.stepsUsed;
        totalCost += r.costSpentUsd;
        totalLatency += r.latencyMs;
        completedRuns++;

        totalProven += r.provenCount;
        totalUnproven += r.unprovenCount;
        totalInconclusive += r.inconclusiveCount;

        if (r.expected === 'vulnerable' && r.found) tp++;
        else if (r.expected === 'vulnerable' && !r.found) fn++;
        else if (r.expected === 'safe' && r.found) fp++;
        else tn++;
    }

    const totalRealVuln = tp + fn;
    const totalSafe = fp + tn;
    const totalFindings = tp + fp;
    const nonInfraTotal = results.length - infraFailures;

    const recall = totalRealVuln ? tp / totalRealVuln : 0;
    const precision = totalFindings ? tp / totalFindings : 1;
    const fpr = totalSafe ? fp / totalSafe : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

    const totalVerdicts = totalProven + totalUnproven + totalInconclusive;
    const verifyableRuns = results.filter(r => !r.infraFailure && r.expected === 'vulnerable' && r.found).length;

    return {
        tp, fn, fp, tn,
        recall, precision, fpr, f1,
        total: results.length,
        totalRealVuln, totalSafe,
        infraFailures,
        completionRate: nonInfraTotal ? completedRuns / nonInfraTotal : 0,
        provenRate: totalVerdicts ? totalProven / totalVerdicts : 0,
        unprovenRate: totalVerdicts ? totalUnproven / totalVerdicts : 0,
        inconclusiveRate: totalVerdicts ? totalInconclusive / totalVerdicts : 0,
        meanSteps: completedRuns ? totalSteps / completedRuns : 0,
        meanCostUsd: completedRuns ? totalCost / completedRuns : 0,
        meanLatencyMs: completedRuns ? totalLatency / completedRuns : 0,
    };
}

export function formatMetricsMarkdown(metrics: AgentEvalMetrics): string {
    const pct = (n: number) => (n * 100).toFixed(1) + '%';
    const usd = (n: number) => '$' + n.toFixed(4);
    const ms = (n: number) => n.toFixed(0) + 'ms';

    return `## Agent Scan Golden Eval Results

| Metric | Value |
|--------|-------|
| **Recall** | ${pct(metrics.recall)} (${metrics.tp}/${metrics.totalRealVuln}) |
| **Precision** | ${pct(metrics.precision)} (${metrics.tp}/${metrics.tp + metrics.fp}) |
| **FPR** | ${pct(metrics.fpr)} (${metrics.fp}/${metrics.totalSafe}) |
| **F1** | ${metrics.f1.toFixed(3)} |
| **Completion Rate** | ${pct(metrics.completionRate)} |
| **Infra Failures** | ${metrics.infraFailures}/${metrics.total} |
| **Proven Rate** | ${pct(metrics.provenRate)} |
| **Unproven Rate** | ${pct(metrics.unprovenRate)} |
| **Inconclusive Rate** | ${pct(metrics.inconclusiveRate)} |
| **Mean Steps** | metrics.meanSteps.toFixed(1) |
| **Mean Cost** | ${usd(metrics.meanCostUsd)} |
| **Mean Latency** | ${ms(metrics.meanLatencyMs)} |
`;
}
