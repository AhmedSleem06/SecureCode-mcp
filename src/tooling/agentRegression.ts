/**
 * Agent regression gate — compares a new eval result against a stored
 * baseline and fails when precision, recall, or completion rate regresses
 * beyond strict thresholds.
 *
 * Gate rules (per the user's decision: "Strict regression gate"):
 *   - precision drop > 0.02  → FAIL
 *   - recall drop > 0.02     → FAIL
 *   - completion-rate drop > 0.03 → FAIL
 *   - fixture/schema mismatch → FAIL
 *   - cache version mismatch → FAIL (result was produced by an old prompt)
 *   - commit SHA mismatch → FAIL (result was produced on a different commit)
 *
 * Usage:
 *   npx tsx tooling/checkAgentRegression.ts --baseline <path> --result <path>
 *
 * The baseline is stored in tooling/agent-testset/baseline.json. It's
 * regenerated when a deliberate quality change is made (run the eval,
 * inspect the new metrics, if they're better or equal, update the baseline).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { AGENT_SCAN_CACHE_VERSION } from '../project-map/scanCache';
import type { AgentEvalMetrics } from './agentEvalScoring';

export interface AgentEvalReport {
    timestamp: string;
    manifest_version: number;
    fixtureCount: number;
    metrics: AgentEvalMetrics;
    results: any[];
    targets: { recall_min: number; precision_min: number; fpr_max: number; completion_rate_min: number };
    pass: boolean;
    cacheVersion?: number;
    commitSha?: string;
}

export interface RegressionResult {
    passed: boolean;
    reasons: string[];
    deltas: {
        precisionDelta: number;
        recallDelta: number;
        completionRateDelta: number;
        fprDelta: number;
    };
    baseline: AgentEvalMetrics;
    candidate: AgentEvalMetrics;
}

const THRESHOLDS = {
    maxPrecisionDrop: 0.02,
    maxRecallDrop: 0.02,
    maxCompletionRateDrop: 0.03,
} as const;

function getCommitSha(): string {
    try {
        return execSync('git rev-parse HEAD', { encoding: 'utf8', windowsHide: true }).trim();
    } catch {
        return 'unknown';
    }
}

export function checkRegression(
    baseline: AgentEvalReport,
    candidate: AgentEvalReport,
    options: { currentSha?: string } = {},
): RegressionResult {
    const reasons: string[] = [];
    const b = baseline.metrics;
    const c = candidate.metrics;

    const precisionDelta = c.precision - b.precision;
    const recallDelta = c.recall - b.recall;
    const completionRateDelta = c.completionRate - b.completionRate;
    const fprDelta = c.fpr - b.fpr;

    if (precisionDelta < -THRESHOLDS.maxPrecisionDrop) {
        reasons.push(`Precision dropped by ${Math.abs(precisionDelta).toFixed(4)} (max allowed: ${THRESHOLDS.maxPrecisionDrop}). ${b.precision.toFixed(4)} → ${c.precision.toFixed(4)}`);
    }

    if (recallDelta < -THRESHOLDS.maxRecallDrop) {
        reasons.push(`Recall dropped by ${Math.abs(recallDelta).toFixed(4)} (max allowed: ${THRESHOLDS.maxRecallDrop}). ${b.recall.toFixed(4)} → ${c.recall.toFixed(4)}`);
    }

    if (completionRateDelta < -THRESHOLDS.maxCompletionRateDrop) {
        reasons.push(`Completion rate dropped by ${Math.abs(completionRateDelta).toFixed(4)} (max allowed: ${THRESHOLDS.maxCompletionRateDrop}). ${b.completionRate.toFixed(4)} → ${c.completionRate.toFixed(4)}`);
    }

    if (baseline.fixtureCount !== candidate.fixtureCount) {
        reasons.push(`Fixture count mismatch: baseline has ${baseline.fixtureCount}, candidate has ${candidate.fixtureCount}. Run the eval with the same testset.`);
    }

    if (baseline.manifest_version !== candidate.manifest_version) {
        reasons.push(`Manifest version mismatch: baseline is v${baseline.manifest_version}, candidate is v${candidate.manifest_version}. Update the baseline.`);
    }

    if (candidate.cacheVersion !== undefined && candidate.cacheVersion !== AGENT_SCAN_CACHE_VERSION) {
        reasons.push(`Cache version mismatch: candidate result was produced with cache version ${candidate.cacheVersion}, but current AGENT_SCAN_CACHE_VERSION is ${AGENT_SCAN_CACHE_VERSION}. The result is stale — re-run the eval.`);
    }

    const candidateSha = candidate.commitSha;
    const expectedSha = options.currentSha ?? getCommitSha();
    if (candidateSha && candidateSha !== 'unknown' && candidateSha !== expectedSha) {
        reasons.push(`Commit SHA mismatch: candidate result was produced on ${candidateSha.slice(0, 8)}, but current HEAD is ${expectedSha.slice(0, 8)}. Re-run the eval on the current commit.`);
    }

    return {
        passed: reasons.length === 0,
        reasons,
        deltas: { precisionDelta, recallDelta, completionRateDelta, fprDelta },
        baseline: b,
        candidate: c,
    };
}

export function formatRegressionResult(result: RegressionResult): string {
    const lines: string[] = [];
    const status = result.passed ? 'PASS' : 'FAIL';
    lines.push(`## Regression Gate: ${status}`);
    lines.push('');
    lines.push('| Metric | Baseline | Candidate | Delta | Threshold |');
    lines.push('|--------|----------|-----------|-------|-----------|');
    lines.push(`| Precision | ${result.baseline.precision.toFixed(4)} | ${result.candidate.precision.toFixed(4)} | ${result.deltas.precisionDelta >= 0 ? '+' : ''}${result.deltas.precisionDelta.toFixed(4)} | ≥ -${THRESHOLDS.maxPrecisionDrop} |`);
    lines.push(`| Recall | ${result.baseline.recall.toFixed(4)} | ${result.candidate.recall.toFixed(4)} | ${result.deltas.recallDelta >= 0 ? '+' : ''}${result.deltas.recallDelta.toFixed(4)} | ≥ -${THRESHOLDS.maxRecallDrop} |`);
    lines.push(`| Completion Rate | ${result.baseline.completionRate.toFixed(4)} | ${result.candidate.completionRate.toFixed(4)} | ${result.deltas.completionRateDelta >= 0 ? '+' : ''}${result.deltas.completionRateDelta.toFixed(4)} | ≥ -${THRESHOLDS.maxCompletionRateDrop} |`);
    lines.push(`| FPR | ${result.baseline.fpr.toFixed(4)} | ${result.candidate.fpr.toFixed(4)} | ${result.deltas.fprDelta >= 0 ? '+' : ''}${result.deltas.fprDelta.toFixed(4)} | (info) |`);

    if (result.reasons.length > 0) {
        lines.push('');
        lines.push('### Failure Reasons:');
        for (const r of result.reasons) {
            lines.push(`- ${r}`);
        }
    }

    return lines.join('\n');
}
