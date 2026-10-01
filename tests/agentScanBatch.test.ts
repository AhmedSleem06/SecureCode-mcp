import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/tools/map', () => ({
    toolMap: vi.fn(),
}));

vi.mock('../src/tools/agentScan', () => ({
    toolAgentScan: vi.fn(),
}));

vi.mock('../src/attack/agentScanBatchSelection', () => ({
    selectAgentScanBatchFiles: vi.fn(),
}));

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        getJson: vi.fn().mockResolvedValue({ scanCredits: 1000, attackerCredits: 100 }),
    })),
}));

import {
    classifyAgentScanResult,
    buildBatchFileResult,
    buildNotStartedFileResult,
    aggregateBatchResult,
    type AgentScanBatchFileResult,
    type AgentScanBatchStopReason,
} from '../src/attack/agentScanBatchProtocol';
import type { AgentScanResult } from '../src/attack/agentScanProtocol';
import { toolAgentScanBatch } from '../src/tools/agentScanBatch';
import { toolMap } from '../src/tools/map';
import { writeCachedScan } from '../src/project-map/scanCache';

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

    it('passes stopDetail and cachedScans extras into the result', () => {
        const cachedScans = [{ filePath: 'src/a.ts', findings: 2, scannedAt: new Date().toISOString() }];
        const batch = aggregateBatchResult('architecture-failed', 3, [], [], {
            stopDetail: 'Scout failed to start',
            cachedScans,
        });
        expect(batch.stopDetail).toBe('Scout failed to start');
        expect(batch.cachedScans).toEqual(cachedScans);
    });

    it('omits stopDetail and cachedScans when no extras are given', () => {
        const batch = aggregateBatchResult('completed', 3, [], []);
        expect(batch.stopDetail).toBeUndefined();
        expect(batch.cachedScans).toBeUndefined();
    });

    it('maps architecture-in-progress to preflight-failed status', () => {
        const batch = aggregateBatchResult('architecture-in-progress', 3, [], []);
        expect(batch.status).toBe('preflight-failed');
    });

    it('maps daily-limit-reached to preflight-failed status', () => {
        const batch = aggregateBatchResult('daily-limit-reached', 3, [], []);
        expect(batch.status).toBe('preflight-failed');
    });
});

describe('toolAgentScanBatch — preflight error taxonomy', () => {
    let workspaceRoot: string;
    let ctx: { workspaceRoot: string; apiUrl: string; apiToken: string };

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'batch-preflight-'));
        ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test' };
        vi.clearAllMocks();
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    function mockArchThrow(err: any) {
        (toolMap as any).mockRejectedValue(err);
    }

    it('classifies 409/AGENT_SCAN_ALREADY_RUNNING as architecture-in-progress', async () => {
        const err: any = new Error('Agent scan already running — a previous run is still executing server-side. Wait ~60-120 seconds and retry.');
        err.apiCode = 'AGENT_SCAN_ALREADY_RUNNING';
        err.statusCode = 409;
        mockArchThrow(err);

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.stopReason).toBe('architecture-in-progress');
        expect(result.status).toBe('preflight-failed');
        expect(result.stopDetail).toContain('already running');
        expect(result.stopDetail).toContain('retry individual agent-scan calls');
        expect(result.totals.selected).toBe(0);
    });

    it('classifies AGENT_SCAN_DAILY_LIMIT as daily-limit-reached with cache guidance', async () => {
        const err: any = new Error('Agent scan daily limit reached (10/10 runs today)');
        err.apiCode = 'AGENT_SCAN_DAILY_LIMIT';
        err.statusCode = 429;
        mockArchThrow(err);

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.stopReason).toBe('daily-limit-reached');
        expect(result.status).toBe('preflight-failed');
        expect(result.stopDetail).toContain('daily limit reached (10/10 runs today)');
        expect(/without noCache/i.test(result.stopDetail || '')).toBe(true);
    });

    it('classifies a generic error as architecture-failed with the real message', async () => {
        mockArchThrow(new Error('Scout brain connection refused'));

        const result = await toolAgentScanBatch(ctx, { topN: 2 });

        expect(result.stopReason).toBe('architecture-failed');
        expect(result.status).toBe('preflight-failed');
        expect(result.stopDetail).toContain('Scout brain connection refused');
    });

    it('includes cachedScans of completed cache entries in the preflight response', async () => {
        writeCachedScan(workspaceRoot, 'src/a.ts', 'const a = 1;', {
            findings: [{ type: 'xss' }, { type: 'sql_injection' }],
            status: 'completed',
            terminationReason: 'agent_finish',
            stepsUsed: 3,
            costSpentUsd: 0,
        });
        writeCachedScan(workspaceRoot, 'src/b.ts', 'const b = 2;', {
            findings: [],
            status: 'incomplete',
            terminationReason: 'wall_clock',
            stepsUsed: 1,
            costSpentUsd: 0,
        });

        const err: any = new Error('Agent scan daily limit reached (10/10 runs today)');
        err.apiCode = 'AGENT_SCAN_DAILY_LIMIT';
        mockArchThrow(err);

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.stopReason).toBe('daily-limit-reached');
        expect(result.cachedScans).toHaveLength(1);
        expect(result.cachedScans![0].filePath).toBe('src/a.ts');
        expect(result.cachedScans![0].findings).toBe(2);
        expect(typeof result.cachedScans![0].scannedAt).toBe('string');
    });

    it('reports empty cachedScans when the workspace has no cache', async () => {
        mockArchThrow(new Error('Scout brain connection refused'));

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.stopReason).toBe('architecture-failed');
        expect(result.cachedScans).toEqual([]);
    });
});
