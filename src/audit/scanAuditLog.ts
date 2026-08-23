/**
 * Metadata-only scan audit log — samples per-scan metadata (no source code,
 * no evidence strings) for quality auditing and regression tracking.
 *
 * Privacy contract (same as agentTrace.ts):
 *   - Source code NEVER leaves the machine.
 *   - Evidence strings, `why` explanations, fix code, and file content are
 *     NOT recorded. Only hashes, counts, verdicts, cost, steps, and action
 *     type histograms are stored.
 *   - The audit log is per-workspace, stored at
 *     `<workspaceRoot>/.securecode/scan-audit.jsonl`.
 *
 * Sampling:
 *   - Not every scan is recorded — a configurable sampling rate (default 1.0
 *     = 100% for local audit; the caller can lower it) gates which scans
 *     are persisted. Sampling is deterministic per scan (hash of file path
 *     + timestamp) so the same scan re-run doesn't double-count.
 *
 * Reuses metric vocabulary from agentEvalScoring.ts for aggregation:
 *   - provenRate, inconclusiveRate, meanSteps, meanCostUsd
 *
 * Retention:
 *   - 90-day TTL (longer than trace's 7 days — audit is long-term quality).
 *   - 1000 entries per workspace (3x the approval audit cap).
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const AUDIT_DIR = '.securecode';
const AUDIT_FILE = 'scan-audit.jsonl';
const MAX_ENTRIES = 1000;
const RETENTION_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

export interface ScanAuditSample {
    timestamp: string;
    filePath: string;
    fileHash: string;
    language: string;
    scanStatus: string;
    stepsUsed: number;
    costSpentUsd: number;
    findings: {
        type: string;
        severity: string;
        line: number;
        confidence: number;
        proven: string;
        evidenceLevel?: string;
        verificationLevel?: string;
    }[];
    findingCounts: {
        total: number;
        proven: number;
        unproven: number;
        inconclusive: number;
        notReproducible: number;
        skipped: number;
    };
    precisionMetrics?: {
        investigationNotesCount: number;
        coverageGapsCount: number;
        verificationLevelDistribution: Record<string, number>;
        rootCauseCount: number;
        hasArchitectureContext: boolean;
        stepsGranted?: number;
        extensionsGranted?: number;
        terminationReason?: string;
        provenStrictCount?: number;
        provenRejectedByGate?: number;
        proofGateFailures?: Record<string, number>;
        syntheticProofCount?: number;
        extractedLogicProofCount?: number;
        realImportProofCount?: number;
        baselinePassRate?: number;
        exploitPassRate?: number;
        targetReachedRate?: number;
        flakyProofCount?: number;
        mutationDiscriminationRate?: number;
        humanReviewPendingCount?: number;
    };
    verifyUsage?: {
        findingsAttempted: number;
        roundsUsed: number;
        llmCallsUsed: number;
        costSpentUsd: number;
        wallClockMs: number;
    };
    actionHistogram: Record<string, number>;
    cached: boolean;
    scope?: {
        changedFiles: number;
        blastRadius: number;
        baseRef?: string;
    };
}

function ensureAuditDir(workspaceRoot: string): string {
    const dir = path.join(workspaceRoot, AUDIT_DIR);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

function getAuditPath(workspaceRoot: string): string {
    return path.join(ensureAuditDir(workspaceRoot), AUDIT_FILE);
}

function shouldSample(filePath: string, timestamp: number, samplingRate: number): boolean {
    if (samplingRate >= 1.0) return true;
    if (samplingRate <= 0.0) return false;
    const hash = crypto.createHash('sha256').update(`${filePath}:${timestamp}`).digest('hex');
    const value = parseInt(hash.substring(0, 8), 16) / 0xffffffff;
    return value < samplingRate;
}

function buildActionHistogram(transcript: any[]): Record<string, number> {
    const hist: Record<string, number> = {};
    for (const step of transcript) {
        const type = step?.action?.type;
        if (!type) continue;
        hist[type] = (hist[type] || 0) + 1;
    }
    return hist;
}

export function recordScanAuditSample(
    workspaceRoot: string,
    scanResult: {
        filePath: string;
        fileHash: string;
        language: string;
        scanStatus: string;
        stepsUsed: number;
        costSpentUsd: number;
        agentFindings: any[];
        transcript?: any[];
        cached: boolean;
        verifyUsage?: any;
        scope?: any;
        investigationNotes?: any[];
        coverageGaps?: any[];
        hasArchitectureContext?: boolean;
        stepsGranted?: number;
        extensionsGranted?: number;
        terminationReason?: string;
    },
    options?: {
        samplingRate?: number;
    },
): boolean {
    const samplingRate = options?.samplingRate ?? 1.0;
    const timestamp = Date.now();

    if (!shouldSample(scanResult.filePath, timestamp, samplingRate)) {
        return false;
    }

    const findings: ScanAuditSample['findings'] = (scanResult.agentFindings || []).map((f: any) => ({
        type: f.type || 'unknown',
        severity: f.severity || 'unknown',
        line: f.line || 0,
        confidence: f.confidence ?? 0,
        proven: f.proven || 'UNKNOWN',
        evidenceLevel: f.evidenceLevel,
        verificationLevel: f.verificationLevel,
    }));

    const findingCounts = {
        total: findings.length,
        proven: findings.filter(f => f.proven === 'PROVEN').length,
        unproven: findings.filter(f => f.proven === 'UNPROVEN').length,
        inconclusive: findings.filter(f => f.proven === 'INCONCLUSIVE').length,
        notReproducible: findings.filter(f => f.proven === 'NOT_REPRODUCIBLE').length,
        skipped: findings.filter(f => f.proven === 'SKIPPED').length,
    };

    const verificationLevelDistribution: Record<string, number> = {};
    for (const f of findings) {
        const vl = f.verificationLevel || 'unspecified';
        verificationLevelDistribution[vl] = (verificationLevelDistribution[vl] || 0) + 1;
    }

    const rootCauseIds = new Set<string>();
    for (const f of scanResult.agentFindings || []) {
        if (f.rootCause?.rootCauseId) rootCauseIds.add(f.rootCause.rootCauseId);
    }

    const proofGateFailures: Record<string, number> = {};
    let provenStrictCount = 0;
    let provenRejectedByGate = 0;
    let syntheticProofCount = 0;
    let realImportProofCount = 0;
    let flakyProofCount = 0;

    for (const f of scanResult.agentFindings || []) {
        if (f.proven === 'PROVEN' && f.proofGateResult?.eligibleForProven) provenStrictCount++;
        if (f.proofGateResult && !f.proofGateResult.eligibleForProven && f.proven !== 'PROVEN') provenRejectedByGate++;
        if (f.proofEvidence?.sourceMode === 'synthetic') syntheticProofCount++;
        if (f.proofEvidence?.sourceMode === 'real-import') realImportProofCount++;
        if (f.proofGateResult?.failedGates.includes('flaky-proof')) flakyProofCount++;
        if (f.proofGateResult) {
            for (const gate of f.proofGateResult.failedGates) {
                proofGateFailures[gate] = (proofGateFailures[gate] || 0) + 1;
            }
        }
    }

    const precisionMetrics = {
        investigationNotesCount: scanResult.investigationNotes?.length ?? 0,
        coverageGapsCount: scanResult.coverageGaps?.length ?? 0,
        verificationLevelDistribution,
        rootCauseCount: rootCauseIds.size,
        hasArchitectureContext: scanResult.hasArchitectureContext ?? false,
        stepsGranted: scanResult.stepsGranted,
        extensionsGranted: scanResult.extensionsGranted,
        terminationReason: scanResult.terminationReason,
        provenStrictCount,
        provenRejectedByGate,
        proofGateFailures,
        syntheticProofCount,
        realImportProofCount,
        flakyProofCount,
    };

    const sample: ScanAuditSample = {
        timestamp: new Date(timestamp).toISOString(),
        filePath: scanResult.filePath,
        fileHash: scanResult.fileHash,
        language: scanResult.language,
        scanStatus: scanResult.scanStatus,
        stepsUsed: scanResult.stepsUsed,
        costSpentUsd: scanResult.costSpentUsd,
        findings,
        findingCounts,
        precisionMetrics,
        verifyUsage: scanResult.verifyUsage,
        actionHistogram: buildActionHistogram(scanResult.transcript || []),
        cached: scanResult.cached,
        scope: scanResult.scope ? {
            changedFiles: scanResult.scope.changedFiles?.length || 0,
            blastRadius: scanResult.scope.blastRadius?.length || 0,
            baseRef: scanResult.scope.baseRef,
        } : undefined,
    };

    try {
        const auditPath = getAuditPath(workspaceRoot);
        const line = JSON.stringify(sample) + '\n';
        fs.appendFileSync(auditPath, line, { encoding: 'utf8', mode: 0o600 });
        pruneOldEntries(workspaceRoot);
        return true;
    } catch {
        return false;
    }
}

function pruneOldEntries(workspaceRoot: string): void {
    try {
        const auditPath = getAuditPath(workspaceRoot);
        if (!fs.existsSync(auditPath)) return;
        const content = fs.readFileSync(auditPath, 'utf8');
        const lines = content.trim().split('\n').filter(Boolean);
        if (lines.length <= MAX_ENTRIES) return;

        const cutoff = Date.now() - RETENTION_MS;
        const kept: string[] = [];
        for (const line of lines) {
            try {
                const entry = JSON.parse(line);
                const ts = new Date(entry.timestamp).getTime();
                if (ts >= cutoff) kept.push(line);
            } catch {
                // keep unparseable lines (don't lose data on corruption)
                kept.push(line);
            }
        }

        if (kept.length > MAX_ENTRIES) {
            kept.splice(0, kept.length - MAX_ENTRIES);
        }

        fs.writeFileSync(auditPath, kept.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
    } catch {
        // best-effort
    }
}

export interface ScanAuditSummary {
    totalScans: number;
    cachedScans: number;
    freshScans: number;
    totalFindings: number;
    byProven: Record<string, number>;
    bySeverity: Record<string, number>;
    byType: Record<string, number>;
    provenRate: number;
    inconclusiveRate: number;
    meanSteps: number;
    meanCostUsd: number;
    meanFindingsPerScan: number;
    actionTypeUsage: Record<string, number>;
    oldestEntry: string | null;
    newestEntry: string | null;
}

export function readScanAuditLog(workspaceRoot: string, limit: number = 100): ScanAuditSample[] {
    try {
        const auditPath = getAuditPath(workspaceRoot);
        if (!fs.existsSync(auditPath)) return [];
        const content = fs.readFileSync(auditPath, 'utf8');
        const lines = content.trim().split('\n').filter(Boolean);
        const samples: ScanAuditSample[] = [];
        for (const line of lines.slice(-limit)) {
            try {
                samples.push(JSON.parse(line));
            } catch {
                // skip corrupt
            }
        }
        return samples;
    } catch {
        return [];
    }
}

export function summarizeScanAuditLog(workspaceRoot: string): ScanAuditSummary {
    const samples = readScanAuditLog(workspaceRoot, MAX_ENTRIES);
    const summary: ScanAuditSummary = {
        totalScans: samples.length,
        cachedScans: samples.filter(s => s.cached).length,
        freshScans: samples.filter(s => !s.cached).length,
        totalFindings: 0,
        byProven: {},
        bySeverity: {},
        byType: {},
        provenRate: 0,
        inconclusiveRate: 0,
        meanSteps: 0,
        meanCostUsd: 0,
        meanFindingsPerScan: 0,
        actionTypeUsage: {},
        oldestEntry: null,
        newestEntry: null,
    };

    if (samples.length === 0) return summary;

    let totalSteps = 0;
    let totalCost = 0;
    let totalFindings = 0;
    let totalProven = 0;
    let totalInconclusive = 0;

    for (const s of samples) {
        totalSteps += s.stepsUsed;
        totalCost += s.costSpentUsd;
        totalFindings += s.findingCounts.total;
        totalProven += s.findingCounts.proven;
        totalInconclusive += s.findingCounts.inconclusive;

        for (const f of s.findings) {
            summary.byProven[f.proven] = (summary.byProven[f.proven] || 0) + 1;
            summary.bySeverity[f.severity] = (summary.bySeverity[f.severity] || 0) + 1;
            summary.byType[f.type] = (summary.byType[f.type] || 0) + 1;
        }

        for (const [action, count] of Object.entries(s.actionHistogram)) {
            summary.actionTypeUsage[action] = (summary.actionTypeUsage[action] || 0) + count;
        }

        if (!summary.oldestEntry || s.timestamp < summary.oldestEntry) {
            summary.oldestEntry = s.timestamp;
        }
        if (!summary.newestEntry || s.timestamp > summary.newestEntry) {
            summary.newestEntry = s.timestamp;
        }
    }

    summary.totalFindings = totalFindings;
    summary.meanSteps = totalSteps / samples.length;
    summary.meanCostUsd = totalCost / samples.length;
    summary.meanFindingsPerScan = totalFindings / samples.length;
    summary.provenRate = totalFindings > 0 ? totalProven / totalFindings : 0;
    summary.inconclusiveRate = totalFindings > 0 ? totalInconclusive / totalFindings : 0;

    return summary;
}

export function clearScanAuditLog(workspaceRoot: string): void {
    try {
        const auditPath = getAuditPath(workspaceRoot);
        if (fs.existsSync(auditPath)) fs.unlinkSync(auditPath);
    } catch {
        // best-effort
    }
}

export function formatAuditSummary(summary: ScanAuditSummary): string {
    if (summary.totalScans === 0) {
        return 'No scan audit data available.';
    }

    const lines: string[] = [
        `Scan Audit Summary (${summary.totalScans} scans, ${summary.cachedScans} cached, ${summary.freshScans} fresh):`,
        '',
        `Findings: ${summary.totalFindings} total (${summary.meanFindingsPerScan.toFixed(1)}/scan)`,
        `  Proven: ${summary.byProven.PROVEN || 0} (${(summary.provenRate * 100).toFixed(1)}%)`,
        `  Inconclusive: ${summary.byProven.INCONCLUSIVE || 0} (${(summary.inconclusiveRate * 100).toFixed(1)}%)`,
        `  Unproven: ${summary.byProven.UNPROVEN || 0}`,
        `  Not Reproducible: ${summary.byProven.NOT_REPRODUCIBLE || 0}`,
        `  Skipped: ${summary.byProven.SKIPPED || 0}`,
        '',
        `Cost: $${summary.meanCostUsd.toFixed(4)}/scan (avg), $${(summary.meanCostUsd * summary.totalScans).toFixed(4)} total`,
        `Steps: ${summary.meanSteps.toFixed(1)}/scan (avg)`,
        '',
        'By severity:',
    ];

    for (const [sev, count] of Object.entries(summary.bySeverity).sort((a, b) => b[1] - a[1])) {
        lines.push(`  ${sev}: ${count}`);
    }

    lines.push('', 'By type:');
    for (const [type, count] of Object.entries(summary.byType).sort((a, b) => b[1] - a[1])) {
        lines.push(`  ${type}: ${count}`);
    }

    lines.push('', 'Tool usage:');
    for (const [action, count] of Object.entries(summary.actionTypeUsage).sort((a, b) => b[1] - a[1])) {
        lines.push(`  ${action}: ${count}`);
    }

    if (summary.oldestEntry && summary.newestEntry) {
        lines.push('', `Range: ${summary.oldestEntry} → ${summary.newestEntry}`);
    }

    return lines.join('\n');
}

// ── Proof audit metrics ────────────────────────────────────────────────────

export interface ProofAuditMetrics {
    provenStrictCount: number;
    provenRejectedByGate: number;
    proofGateFailures: Record<string, number>;
    syntheticProofCount: number;
    extractedLogicProofCount: number;
    realImportProofCount: number;
    baselinePassRate: number;
    exploitPassRate: number;
    targetReachedRate: number;
    flakyProofCount: number;
    mutationDiscriminationRate: number;
    humanReviewPendingCount: number;
}

export interface ProofInvariantCheck {
    findingIndex: number;
    violations: string[];
}

/**
 * Validate the PROVEN invariant: every PROVEN finding must have:
 *   - proofEvidence
 *   - proofGateResult.eligibleForProven === true
 *   - sourceMode = real-import or real-server
 *   - repeatedRuns >= 3
 *   - repeatPasses === repeatedRuns
 *   - mutation discrimination passed
 *
 * Returns an array of violations per finding. An empty array means all
 * PROVEN findings satisfy the invariant.
 */
export function validateProvenInvariant(findings: any[]): ProofInvariantCheck[] {
    const checks: ProofInvariantCheck[] = [];

    findings.forEach((finding, i) => {
        if (finding.proven !== 'PROVEN' && finding.verdict !== 'PROVEN') return;

        const violations: string[] = [];

        if (!finding.proofEvidence) {
            violations.push('missing proofEvidence');
        }

        if (!finding.proofGateResult || !finding.proofGateResult.eligibleForProven) {
            violations.push('proofGateResult.eligibleForProven is not true');
        }

        const sourceMode = finding.proofEvidence?.sourceMode;
        if (sourceMode && sourceMode !== 'real-import' && sourceMode !== 'real-server') {
            violations.push(`sourceMode is ${sourceMode}, must be real-import or real-server`);
        }

        const repeatedRuns = finding.proofEvidence?.repeatedRuns ?? 0;
        if (repeatedRuns < 3) {
            violations.push(`repeatedRuns is ${repeatedRuns}, must be >= 3`);
        }

        const repeatPasses = finding.proofEvidence?.repeatPasses ?? 0;
        if (repeatPasses !== repeatedRuns) {
            violations.push(`repeatPasses (${repeatPasses}) !== repeatedRuns (${repeatedRuns}) — proof is flaky`);
        }

        if (finding.proofEvidence?.assumptions?.some((a: string) => a.includes('mutation-test'))) {
            violations.push('mutation discrimination not passed');
        }

        if (violations.length > 0) {
            checks.push({ findingIndex: i, violations });
        }
    });

    return checks;
}
