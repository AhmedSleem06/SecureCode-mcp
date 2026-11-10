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

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
    ApiClient: vi.fn().mockImplementation(() => ({
        getJson: vi.fn().mockResolvedValue({ scanCredits: 1000, attackerCredits: 100 }),
    })),
    };
});

import { toolAgentScanBatch } from '../src/tools/agentScanBatch';
import { toolMap } from '../src/tools/map';
import { toolAgentScan } from '../src/tools/agentScan';
import { selectAgentScanBatchFiles } from '../src/attack/agentScanBatchSelection';
import { ApiClient } from '../src/api/client';
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

    it('returns preflight-failed on insufficient credits', async () => {
        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 5, attackerCredits: 0 }),
        })) as any);
        mockArchResult(makeArch());
        mockSelection(['src/a.ts', 'src/b.ts', 'src/c.ts']);
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed'));

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.status).toBe('preflight-failed');
        expect(result.stopReason).toBe('insufficient-credits');
        expect(result.totals.notStarted).toBe(3);
        expect((toolAgentScan as any).mock.calls).toHaveLength(0);

        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 1000, attackerCredits: 100 }),
        })) as any);
    });

    it('preflight plans 5 credits per file (architecture cached) and warns about the 15-credit ceiling', async () => {
        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 15, attackerCredits: 0 }),
        })) as any);
        mockArchResult(makeArch(), true);
        mockSelection(['src/a.ts', 'src/b.ts', 'src/c.ts']);
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed', { creditsUsed: 5 }));

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.status).toBe('completed');
        expect((toolAgentScan as any).mock.calls).toHaveLength(3);
        expect(result.creditNote).toContain('Large files can use up to 15 credits each');
        expect(result.totals.creditsUsed).toBe(15);

        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 1000, attackerCredits: 100 }),
        })) as any);
    });

    it('insufficient-credits preflight explains the shortfall', async () => {
        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 14, attackerCredits: 0 }),
        })) as any);
        mockArchResult(makeArch(), true);
        mockSelection(['src/a.ts', 'src/b.ts', 'src/c.ts']);

        const result = await toolAgentScanBatch(ctx, { topN: 3 });

        expect(result.stopReason).toBe('insufficient-credits');
        expect(result.stopDetail).toContain('Insufficient credits: have 14, need 15.');
        expect(result.stopDetail).toContain('Top up at https://usesecurecode.tech');
        expect(result.creditNote).toContain('up to 45 total');

        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 1000, attackerCredits: 100 }),
        })) as any);
    });
});

function bigFile(lines: number): string {
    const out: string[] = [];
    for (let i = 0; out.length < lines; i++) {
        out.push(`export function handler${i}(req: any) {`);
        for (let j = 0; j < 48; j++) out.push(`    const v${j} = req.body.f${j};`);
        out.push('}');
        out.push('');
    }
    return out.slice(0, lines).join('\n');
}

describe('toolAgentScanBatch — file parts and replaced files', () => {
    let ws: string;
    const fsMod = require('fs') as typeof import('fs');
    const osMod = require('os') as typeof import('os');
    const pathMod = require('path') as typeof import('path');

    beforeEach(() => {
        vi.clearAllMocks();
        ws = fsMod.mkdtempSync(pathMod.join(osMod.tmpdir(), 'sc-batch-parts-'));
        fsMod.mkdirSync(pathMod.join(ws, 'src'), { recursive: true });
        fsMod.writeFileSync(pathMod.join(ws, 'src/big.ts'), bigFile(4700));
        fsMod.writeFileSync(pathMod.join(ws, 'src/small.ts'), 'export const x = 1;\n');
        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 1000, attackerCredits: 100 }),
        })) as any);
    });

    it('plans 5 credits per file part and lists the part counts', async () => {
        mockArchResult(makeArch(), true);
        mockSelection(['src/big.ts', 'src/small.ts']);
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed', { creditsUsed: 5 }));
        const events: string[] = [];

        const result = await toolAgentScanBatch({ ...ctx, workspaceRoot: ws }, {
            topN: 2,
            _progress: (_c: number, _t: number, m: string) => events.push(m),
        });

        expect(result.creditNote).toContain('Planned 5 credits per file part (5 parts across 2 files, 25 total)');
        expect(result.creditNote).toContain('src/big.ts 4 parts');
        expect(result.creditNote).toContain('up to 75 total');
        expect(events.some(e => e.includes('Scanning src/big.ts (1/2, 4 parts)'))).toBe(true);
        expect(result.completed[0].parts).toBe(4);
        expect(result.completed[1].parts).toBe(1);
    });

    it('stops before starting when the balance cannot cover the base credits of every part', async () => {
        vi.mocked(ApiClient).mockImplementation((() => ({
            getJson: vi.fn().mockResolvedValue({ scanCredits: 15, attackerCredits: 0 }),
        })) as any);
        mockArchResult(makeArch(), true);
        mockSelection(['src/big.ts', 'src/small.ts']);

        const result = await toolAgentScanBatch({ ...ctx, workspaceRoot: ws }, { topN: 2 });

        expect(result.status).toBe('preflight-failed');
        expect(result.stopReason).toBe('insufficient-credits');
        expect(result.stopDetail).toContain('have 15, need 25 (5 file parts × 5).');
        expect(result.stopDetail).toContain('Top up at https://usesecurecode.tech');
        expect((toolAgentScan as any).mock.calls).toHaveLength(0);
        expect(result.notStarted[0].parts).toBe(4);
    });

    it('passes merged part segments through to the file result', async () => {
        mockArchResult(makeArch(), true);
        mockSelection(['src/big.ts']);
        const segments = [
            { index: 1, startLine: 1, endLine: 1500, status: 'completed', creditsUsed: 5 },
            { index: 2, startLine: 1501, endLine: 4700, status: 'completed', creditsUsed: 7 },
        ];
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed', { creditsUsed: 12, segments }));

        const result = await toolAgentScanBatch({ ...ctx, workspaceRoot: ws }, { topN: 1 });

        expect(result.completed[0].segments).toEqual(segments);
        expect(result.completed[0].parts).toBe(2);
        expect(result.totals.creditsUsed).toBe(12);
    });

    it('renders replaced and types-only skipped files', async () => {
        mockArchResult(makeArch(), true);
        (selectAgentScanBatchFiles as any).mockImplementation(() => ({
            selected: [{
                filePath: 'src/small.ts', rank: 1,
                replaced: { from: 'src/Services/ServerAuth.ts', to: 'src/small.ts', reason: 'types only' },
            }],
            skipped: [
                { filePath: 'src/Services/Types.ts', reason: 'types only (no implementation found)' },
                { filePath: 'src/missing.ts', reason: 'file does not exist' },
            ],
        }));
        (toolAgentScan as any).mockResolvedValue(mockScanResult('completed'));

        const result = await toolAgentScanBatch({ ...ctx, workspaceRoot: ws }, { topN: 1 });

        expect(result.replaced).toEqual([{ from: 'src/Services/ServerAuth.ts', to: 'src/small.ts', reason: 'types only' }]);
        expect(result.completed[0].replaced?.from).toBe('src/Services/ServerAuth.ts');
        expect(result.selectionNote).toBe('Replaced src/Services/ServerAuth.ts (types only) with src/small.ts. Skipped src/Services/Types.ts (types only (no implementation found)).');
        expect(result.skipped).toHaveLength(2);
    });
});
