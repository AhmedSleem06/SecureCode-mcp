import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
    recordScanAuditSample,
    readScanAuditLog,
    summarizeScanAuditLog,
    clearScanAuditLog,
    formatAuditSummary,
    type ScanAuditSample,
} from '../src/audit/scanAuditLog';

let workspaceRoot: string;

beforeEach(() => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-audit-'));
});

afterEach(() => {
    try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
});

function makeScanResult(overrides?: Partial<any>): any {
    return {
        filePath: 'src/auth.ts',
        fileHash: 'abcdef0123456789',
        language: 'typescript',
        scanStatus: 'completed',
        stepsUsed: 12,
        costSpentUsd: 0.05,
        agentFindings: [
            { type: 'sql_injection', severity: 'high', line: 42, confidence: 85, proven: 'PROVEN', evidenceLevel: 'high' },
            { type: 'xss', severity: 'medium', line: 15, confidence: 60, proven: 'INCONCLUSIVE' },
            { type: 'missing_rate_limiting', severity: 'low', line: 1, confidence: 30, proven: 'SKIPPED' },
        ],
        transcript: [
            { action: { type: 'read_file' } },
            { action: { type: 'read_file' } },
            { action: { type: 'search_code' } },
            { action: { type: 'check_guard' } },
            { action: { type: 'finish' } },
        ],
        cached: false,
        verifyUsage: {
            findingsAttempted: 2,
            roundsUsed: 3,
            llmCallsUsed: 6,
            costSpentUsd: 0.03,
            wallClockMs: 45000,
        },
        ...overrides,
    };
}

describe('recordScanAuditSample', () => {
    it('writes a sample to scan-audit.jsonl', () => {
        const recorded = recordScanAuditSample(workspaceRoot, makeScanResult());
        expect(recorded).toBe(true);

        const entries = readScanAuditLog(workspaceRoot);
        expect(entries.length).toBe(1);
        expect(entries[0].filePath).toBe('src/auth.ts');
        expect(entries[0].scanStatus).toBe('completed');
    });

    it('records metadata only — no evidence strings or code', () => {
        const result = makeScanResult({
            agentFindings: [
                { type: 'sql_injection', severity: 'high', line: 42, confidence: 85, proven: 'PROVEN', evidence: 'db.query("SELECT * FROM users WHERE id=" + req.body.id)', why: 'user input flows to query' },
            ],
        });
        recordScanAuditSample(workspaceRoot, result);

        const entries = readScanAuditLog(workspaceRoot);
        const entry = entries[0];
        expect(entry.findings[0].type).toBe('sql_injection');
        expect(entry.findings[0].severity).toBe('high');
        expect(entry.findings[0].line).toBe(42);
        expect(entry.findings[0].confidence).toBe(85);
        expect(entry.findings[0].proven).toBe('PROVEN');
        // CRITICAL: no evidence string stored
        expect((entry.findings[0] as any).evidence).toBeUndefined();
        expect((entry.findings[0] as any).why).toBeUndefined();
    });

    it('builds action histogram from transcript', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const entries = readScanAuditLog(workspaceRoot);
        expect(entries[0].actionHistogram).toEqual({
            read_file: 2,
            search_code: 1,
            check_guard: 1,
            finish: 1,
        });
    });

    it('counts findings by proven status', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const entries = readScanAuditLog(workspaceRoot);
        expect(entries[0].findingCounts.total).toBe(3);
        expect(entries[0].findingCounts.proven).toBe(1);
        expect(entries[0].findingCounts.inconclusive).toBe(1);
        expect(entries[0].findingCounts.skipped).toBe(1);
    });

    it('records scope metadata when present', () => {
        const result = makeScanResult({
            scope: {
                changedFiles: ['src/auth.ts', 'src/utils.ts'],
                blastRadius: ['src/auth.ts', 'src/utils.ts', 'src/handler.ts'],
                baseRef: 'main',
            },
        });
        recordScanAuditSample(workspaceRoot, result);
        const entries = readScanAuditLog(workspaceRoot);
        expect(entries[0].scope).toEqual({
            changedFiles: 2,
            blastRadius: 3,
            baseRef: 'main',
        });
    });

    it('records verify usage when present', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const entries = readScanAuditLog(workspaceRoot);
        expect(entries[0].verifyUsage).toEqual({
            findingsAttempted: 2,
            roundsUsed: 3,
            llmCallsUsed: 6,
            costSpentUsd: 0.03,
            wallClockMs: 45000,
        });
    });

    it('skips recording when sampling rate is 0', () => {
        const recorded = recordScanAuditSample(workspaceRoot, makeScanResult(), { samplingRate: 0 });
        expect(recorded).toBe(false);
        expect(readScanAuditLog(workspaceRoot).length).toBe(0);
    });

    it('always records when sampling rate is 1 (default)', () => {
        const recorded = recordScanAuditSample(workspaceRoot, makeScanResult());
        expect(recorded).toBe(true);
    });

    it('handles multiple recordings (append-only)', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult({ filePath: 'a.ts' }));
        recordScanAuditSample(workspaceRoot, makeScanResult({ filePath: 'b.ts' }));
        recordScanAuditSample(workspaceRoot, makeScanResult({ filePath: 'c.ts' }));
        const entries = readScanAuditLog(workspaceRoot);
        expect(entries.length).toBe(3);
        expect(entries[0].filePath).toBe('a.ts');
        expect(entries[2].filePath).toBe('c.ts');
    });

    it('does not throw on write failure', () => {
        const readonly = path.join(workspaceRoot, 'readonly');
        fs.mkdirSync(readonly, { recursive: true });
        fs.chmodSync(readonly, 0o444);
        const recorded = recordScanAuditSample(readonly, makeScanResult());
        // Should not throw, may or may not record depending on OS
        expect(typeof recorded).toBe('boolean');
    });
});

describe('summarizeScanAuditLog', () => {
    it('returns empty summary for no data', () => {
        const summary = summarizeScanAuditLog(workspaceRoot);
        expect(summary.totalScans).toBe(0);
        expect(summary.totalFindings).toBe(0);
    });

    it('aggregates metrics across multiple scans', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult({ filePath: 'a.ts', stepsUsed: 10, costSpentUsd: 0.04 }));
        recordScanAuditSample(workspaceRoot, makeScanResult({ filePath: 'b.ts', stepsUsed: 20, costSpentUsd: 0.06 }));
        const summary = summarizeScanAuditLog(workspaceRoot);
        expect(summary.totalScans).toBe(2);
        expect(summary.freshScans).toBe(2);
        expect(summary.cachedScans).toBe(0);
        expect(summary.meanSteps).toBe(15);
        expect(summary.meanCostUsd).toBeCloseTo(0.05, 5);
        expect(summary.totalFindings).toBe(6);
        expect(summary.meanFindingsPerScan).toBe(3);
    });

    it('computes proven rate', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const summary = summarizeScanAuditLog(workspaceRoot);
        expect(summary.provenRate).toBeCloseTo(1/3, 2);
        expect(summary.byProven.PROVEN).toBe(1);
        expect(summary.byProven.INCONCLUSIVE).toBe(1);
        expect(summary.byProven.SKIPPED).toBe(1);
    });

    it('aggregates by severity and type', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const summary = summarizeScanAuditLog(workspaceRoot);
        expect(summary.bySeverity.high).toBe(1);
        expect(summary.bySeverity.medium).toBe(1);
        expect(summary.bySeverity.low).toBe(1);
        expect(summary.byType.sql_injection).toBe(1);
        expect(summary.byType.xss).toBe(1);
    });

    it('aggregates action type usage', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        recordScanAuditSample(workspaceRoot, makeScanResult({ filePath: 'b.ts' }));
        const summary = summarizeScanAuditLog(workspaceRoot);
        expect(summary.actionTypeUsage.read_file).toBe(4);
        expect(summary.actionTypeUsage.search_code).toBe(2);
        expect(summary.actionTypeUsage.check_guard).toBe(2);
    });

    it('tracks oldest and newest entries', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const summary = summarizeScanAuditLog(workspaceRoot);
        expect(summary.oldestEntry).not.toBeNull();
        expect(summary.newestEntry).not.toBeNull();
    });
});

describe('formatAuditSummary', () => {
    it('formats empty summary', () => {
        const summary = summarizeScanAuditLog(workspaceRoot);
        const formatted = formatAuditSummary(summary);
        expect(formatted).toContain('No scan audit data');
    });

    it('formats non-empty summary with metrics', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        const summary = summarizeScanAuditLog(workspaceRoot);
        const formatted = formatAuditSummary(summary);
        expect(formatted).toContain('Scan Audit Summary');
        expect(formatted).toContain('Proven:');
        expect(formatted).toContain('By severity:');
        expect(formatted).toContain('By type:');
        expect(formatted).toContain('Tool usage:');
    });
});

describe('clearScanAuditLog', () => {
    it('removes the audit file', () => {
        recordScanAuditSample(workspaceRoot, makeScanResult());
        expect(readScanAuditLog(workspaceRoot).length).toBe(1);
        clearScanAuditLog(workspaceRoot);
        expect(readScanAuditLog(workspaceRoot).length).toBe(0);
    });

    it('does not throw when no file exists', () => {
        expect(() => clearScanAuditLog(workspaceRoot)).not.toThrow();
    });
});
