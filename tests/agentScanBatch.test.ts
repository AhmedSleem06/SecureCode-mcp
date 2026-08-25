import { describe, it, expect } from 'vitest';
import {
    classifyAgentScanResult,
    buildBatchFileResult,
    buildNotStartedFileResult,
    aggregateBatchResult,
    type AgentScanBatchFileResult,
    type AgentScanBatchStopReason,
} from '../src/attack/agentScanBatchProtocol';
import type { AgentScanResult } from '../src/attack/agentScanProtocol';

function makeScanResult(status: AgentScanResult['status'], overrides?: Partial<AgentScanResult>): AgentScanResult {
    return {
        status,
        findings: [],
        investigationNotes: [],
        coverageGaps: [],
        transcript: [],
        stepsUsed: 10,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.05,
        ...overrides,
    };
}

describe('classifyAgentScanResult', () => {
    it('maps completed → completed', () => {
        expect(classifyAgentScanResult(makeScanResult('completed'))).toBe('completed');
    });

    it('maps incomplete → incomplete', () => {
        expect(classifyAgentScanResult(makeScanResult('incomplete'))).toBe('incomplete');
    });

    it('maps failed → failed', () => {
        expect(classifyAgentScanResult(makeScanResult('failed'))).toBe('failed');
    });

    it('maps cancelled → incomplete', () => {
        expect(classifyAgentScanResult(makeScanResult('cancelled'))).toBe('incomplete');
    });
});

describe('buildBatchFileResult', () => {
    it('builds a completed file result with findings', () => {
        const result = makeScanResult('completed', {
            findings: [{ line: 5, type: 'sql_injection', severity: 'high', confidence: 90, evidence: 'e', why: 'w' }],
            terminationReason: 'agent_finish',
        });
        const file = buildBatchFileResult('src/api.ts', 1, 'route_handler', 95, result, false);
        expect(file.filePath).toBe('src/api.ts');
        expect(file.rank).toBe(1);
        expect(file.role).toBe('route_handler');
        expect(file.importance).toBe(95);
        expect(file.status).toBe('completed');
        expect(file.scanStatus).toBe('completed');
        expect(file.terminationReason).toBe('agent_finish');
        expect(file.cached).toBe(false);
        expect(file.findings).toHaveLength(1);
    });

    it('preserves findings on incomplete scans', () => {
        const result = makeScanResult('incomplete', {
            findings: [{ line: 10, type: 'xss', severity: 'medium', confidence: 60, evidence: 'e', why: 'w' }],
            terminationReason: 'blocked_read_recovery',
            coverageGaps: [{ title: 'gap', detail: 'd', requiredEvidence: [], suggestedNextAction: 'read', priority: 'high' }],
        });
        const file = buildBatchFileResult('src/http.ts', 2, undefined, undefined, result);
        expect(file.status).toBe('incomplete');
        expect(file.findings).toHaveLength(1);
        expect(file.coverageGaps).toHaveLength(1);
    });

    it('includes error from failed scan', () => {
        const result = makeScanResult('failed', { error: 'API server restarted' });
        const file = buildBatchFileResult('src/auth.ts', 3, 'authentication', 80, result);
        expect(file.status).toBe('failed');
        expect(file.error).toBeDefined();
        expect(file.error!.message).toBe('API server restarted');
    });
});

describe('buildNotStartedFileResult', () => {
    it('builds a not-started placeholder', () => {
        const file = buildNotStartedFileResult('src/utils.ts', 4, 'shared_helper', 40);
        expect(file.filePath).toBe('src/utils.ts');
        expect(file.rank).toBe(4);
        expect(file.status).toBe('not-started');
        expect(file.findings).toEqual([]);
        expect(file.stepsUsed).toBe(0);
        expect(file.costSpentUsd).toBe(0);
    });
});

describe('aggregateBatchResult', () => {
    it('reports completed when all files completed', () => {
        const files: AgentScanBatchFileResult[] = [
            buildBatchFileResult('a.ts', 1, undefined, undefined, makeScanResult('completed')),
            buildBatchFileResult('b.ts', 2, undefined, undefined, makeScanResult('completed')),
        ];
        const batch = aggregateBatchResult('completed', 2, ['a.ts', 'b.ts'], files);
        expect(batch.status).toBe('completed');
        expect(batch.totals.completed).toBe(2);
        expect(batch.totals.incomplete).toBe(0);
        expect(batch.totals.failed).toBe(0);
        expect(batch.totals.notStarted).toBe(0);
    });

    it('reports incomplete when a scan is incomplete and stops', () => {
        const files: AgentScanBatchFileResult[] = [
            buildBatchFileResult('a.ts', 1, undefined, undefined, makeScanResult('completed')),
            buildBatchFileResult('b.ts', 2, undefined, undefined, makeScanResult('incomplete')),
            buildNotStartedFileResult('c.ts', 3, undefined, undefined),
        ];
        const batch = aggregateBatchResult('scan-incomplete', 3, ['a.ts', 'b.ts', 'c.ts'], files);
        expect(batch.status).toBe('incomplete');
        expect(batch.totals.completed).toBe(1);
        expect(batch.totals.incomplete).toBe(1);
        expect(batch.totals.notStarted).toBe(1);
    });

    it('reports failed when a scan fails', () => {
        const files: AgentScanBatchFileResult[] = [
            buildBatchFileResult('a.ts', 1, undefined, undefined, makeScanResult('failed')),
            buildNotStartedFileResult('b.ts', 2, undefined, undefined),
        ];
        const batch = aggregateBatchResult('scan-failed', 2, ['a.ts', 'b.ts'], files);
        expect(batch.status).toBe('failed');
        expect(batch.totals.failed).toBe(1);
        expect(batch.totals.notStarted).toBe(1);
    });

    it('reports cancelled when batch is cancelled', () => {
        const files: AgentScanBatchFileResult[] = [
            buildBatchFileResult('a.ts', 1, undefined, undefined, makeScanResult('incomplete')),
        ];
        const batch = aggregateBatchResult('cancelled', 3, ['a.ts', 'b.ts', 'c.ts'], files);
        expect(batch.status).toBe('cancelled');
    });

    it('reports preflight-failed on insufficient credits', () => {
        const batch = aggregateBatchResult('insufficient-credits', 3, ['a.ts', 'b.ts', 'c.ts'], []);
        expect(batch.status).toBe('preflight-failed');
        expect(batch.totals.notStarted).toBe(0);
    });

    it('sums findings across all files', () => {
        const files: AgentScanBatchFileResult[] = [
            buildBatchFileResult('a.ts', 1, undefined, undefined, makeScanResult('completed', {
                findings: [
                    { line: 1, type: 'xss', severity: 'low', confidence: 50, evidence: 'e', why: 'w' },
                    { line: 5, type: 'sqli', severity: 'high', confidence: 80, evidence: 'e', why: 'w' },
                ],
            })),
            buildBatchFileResult('b.ts', 2, undefined, undefined, makeScanResult('incomplete', {
                findings: [{ line: 10, type: 'ssrf', severity: 'medium', confidence: 70, evidence: 'e', why: 'w' }],
            })),
        ];
        const batch = aggregateBatchResult('scan-incomplete', 2, ['a.ts', 'b.ts'], files);
        expect(batch.totals.findings).toBe(3);
    });

    it('sums steps and cost across all files', () => {
        const files: AgentScanBatchFileResult[] = [
            buildBatchFileResult('a.ts', 1, undefined, undefined, makeScanResult('completed', { stepsUsed: 30, costSpentUsd: 0.04 })),
            buildBatchFileResult('b.ts', 2, undefined, undefined, makeScanResult('completed', { stepsUsed: 25, costSpentUsd: 0.03 })),
        ];
        const batch = aggregateBatchResult('completed', 2, ['a.ts', 'b.ts'], files);
        expect(batch.totals.stepsUsed).toBe(55);
        expect(batch.totals.costSpentUsd).toBeCloseTo(0.07, 5);
    });

    it('preserves selectedFiles order', () => {
        const batch = aggregateBatchResult('completed', 3, ['c.ts', 'a.ts', 'b.ts'], []);
        expect(batch.selectedFiles).toEqual(['c.ts', 'a.ts', 'b.ts']);
    });
});
