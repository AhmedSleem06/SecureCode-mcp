import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/tools/map', () => ({
    toolMap: vi.fn(),
}));

vi.mock('../src/tools/agentScan', () => ({
    toolAgentScan: vi.fn(),
}));

vi.mock('../src/attack/agentScanBatchSelection', () => ({
    selectAgentScanBatchFiles: vi.fn(),
}));

import { toolAgentScanBatch } from '../src/tools/agentScanBatch';
import { toolMap } from '../src/tools/map';
import { toolAgentScan } from '../src/tools/agentScan';
import { selectAgentScanBatchFiles } from '../src/attack/agentScanBatchSelection';
import type { ArchitectureContext } from '../src/project-map/architectureContext';

const ctx = { workspaceRoot: '/tmp/test', apiUrl: 'http://localhost:3000', apiToken: 'test' };

function makeArch(overrides?: Partial<ArchitectureContext>): ArchitectureContext {
    return {
        version: 1,
        depth: 'standard',
        derivedAt: Date.now(),
        projectMapBuiltAt: Date.now(),
        projectMapVersion: 1,
        project: { type: 'web', frameworks: ['express'], runtimes: ['node'], packageManager: 'npm', languages: ['typescript'] },
        importantFiles: [],
        trustBoundaries: [],
        dataFlows: [],
        securityControls: [],
        architectureRisks: [],
        recommendedScanOrder: ['src/a.ts', 'src/b.ts', 'src/c.ts'],
        summary: 'test',
        completeness: 'full',
        ...overrides,
    };
}

function mockSelection(files: string[]) {
    (selectAgentScanBatchFiles as any).mockImplementation((_root: any, _arch: any, opts: any) => {
        const topN = opts.topN ?? 3;
        const limited = files.slice(0, topN);
        return {
            selected: limited.map((f, i) => ({ filePath: f, rank: i + 1, role: undefined, importance: undefined })),
            skipped: [],
        };
    });
}

function mockArchResult(arch: ArchitectureContext | null, cached = false) {
    (toolMap as any).mockResolvedValue({ architecture: arch, cached, depth: 'standard' });
}

function mockScanResult(status: string, overrides?: Record<string, any>) {
    return {
        status,
        agentFindings: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 10,
        costSpentUsd: 0.05,
        terminationReason: status === 'completed' ? 'agent_finish' : 'budget_exhausted',
        cached: false,
        ...overrides,
    };
}

describe('toolAgentScanBatch — sequential orchestration', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockSelection(['src/a.ts', 'src/b.ts', 'src/c.ts']);
    });

    it('scans files one at a time in exact order', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        const callOrder: string[] = [];
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            callOrder.push(args.filePath);
            return Promise.resolve(mockScanResult('completed'));
        });

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(callOrder).toEqual(['src/a.ts', 'src/b.ts', 'src/c.ts']);
        expect(result.status).toBe('completed');
        expect(result.totals.completed).toBe(3);
    });

    it('file 2 starts only after file 1 resolves', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        const resolveOrder: string[] = [];
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            return new Promise(resolve => {
                setTimeout(() => {
                    resolveOrder.push(args.filePath);
                    resolve(mockScanResult('completed'));
                }, 10);
            });
        });

        const result = await toolAgentScanBatch(ctx, { topN: 2 });

        expect(resolveOrder).toEqual(['src/a.ts', 'src/b.ts']);
        expect(result.totals.completed).toBe(2);
    });

    it('file 3 is not invoked after file 2 is incomplete', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        const scanned: string[] = [];
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            scanned.push(args.filePath);
            if (args.filePath === 'src/b.ts') {
                return Promise.resolve(mockScanResult('incomplete', { terminationReason: 'blocked_read_recovery' }));
            }
            return Promise.resolve(mockScanResult('completed'));
        });

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(scanned).toEqual(['src/a.ts', 'src/b.ts']);
        expect(result.totals.completed).toBe(1);
        expect(result.totals.incomplete).toBe(1);
        expect(result.totals.notStarted).toBe(1);
        expect(result.notStarted[0].filePath).toBe('src/c.ts');
    });

    it('thrown error classifies current file as failed', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            if (args.filePath === 'src/b.ts') {
                return Promise.reject(new Error('API server error'));
            }
            return Promise.resolve(mockScanResult('completed'));
        });

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.totals.completed).toBe(1);
        expect(result.totals.failed).toBe(1);
        expect(result.totals.notStarted).toBe(1);
        expect(result.failed[0].filePath).toBe('src/b.ts');
        expect(result.failed[0].error?.message).toBe('API server error');
    });

    it('all remaining files become not-started after failure', async () => {
        mockArchResult(makeArch());
        mockSelection(['src/a.ts', 'src/b.ts', 'src/c.ts', 'src/d.ts']);
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            if (args.filePath === 'src/a.ts') {
                return Promise.reject(new Error('fail'));
            }
            return Promise.resolve(mockScanResult('completed'));
        });

        const result = await toolAgentScanBatch(ctx, { topN: 4 });

        expect(result.totals.failed).toBe(1);
        expect(result.totals.notStarted).toBe(3);
        expect(result.notStarted.map(f => f.filePath)).toEqual(['src/b.ts', 'src/c.ts', 'src/d.ts']);
    });

    it('always passes _skipFix: true', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed'));

        await toolAgentScanBatch(ctx, { topN: 2 });

        const calls = (toolAgentScan as any).mock.calls;
        for (const call of calls) {
            expect(call[1]._skipFix).toBe(true);
        }
    });

    it('passes _noCache from batch argument', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed'));

        await toolAgentScanBatch(ctx, { topN: 2, noCache: true });

        const calls = (toolAgentScan as any).mock.calls;
        for (const call of calls) {
            expect(call[1]._noCache).toBe(true);
        }
    });

    it('does not stop when a completed scan has findings', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            return Promise.resolve(mockScanResult('completed', {
                agentFindings: [{ line: 5, type: 'sql_injection', severity: 'high', confidence: 90, evidence: 'e', why: 'w' }],
            }));
        });

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.totals.completed).toBe(3);
        expect(result.totals.findings).toBe(3);
    });

    it('returns preflight-failed when architecture is null', async () => {
        mockArchResult(null);
        const result = await toolAgentScanBatch(ctx, { topN: 3 });
        expect(result.status).toBe('preflight-failed');
        expect(result.stopReason).toBe('architecture-failed');
    });

    it('returns architecture-incomplete when scout completeness is failed', async () => {
        mockArchResult(makeArch({ completeness: 'failed' }));
        const result = await toolAgentScanBatch(ctx, { topN: 3 });
        expect(result.stopReason).toBe('architecture-incomplete');
    });

    it('returns completed with empty selection when no valid files', async () => {
        mockArchResult(makeArch());
        mockSelection([]);
        const result = await toolAgentScanBatch(ctx, { topN: 3 });
        expect(result.status).toBe('completed');
        expect(result.totals.selected).toBe(0);
    });

    it('emits progress events for architecture and each file', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed'));
        const events: string[] = [];
        await toolAgentScanBatch(ctx, {
            topN: 2,
            _progress: (_c: number, _t: number, m: string) => events.push(m),
        });
        expect(events.some(e => e.toLowerCase().includes('architect'))).toBe(true);
        expect(events.some(e => e.includes('src/a.ts'))).toBe(true);
        expect(events.some(e => e.includes('src/b.ts'))).toBe(true);
    });

    it('handles stopOnIncomplete=false to continue after incomplete', async () => {
        const arch = makeArch();
        mockArchResult(arch);
        (toolAgentScan as any).mockImplementation((_ctx: any, args: any) => {
            if (args.filePath === 'src/b.ts') {
                return Promise.resolve(mockScanResult('incomplete'));
            }
            return Promise.resolve(mockScanResult('completed'));
        });

        const result = await toolAgentScanBatch(ctx, { topN: 3, stopOnIncomplete: false });

        expect(result.totals.completed).toBe(2);
        expect(result.totals.incomplete).toBe(1);
        expect(result.totals.notStarted).toBe(0);
    });
});
