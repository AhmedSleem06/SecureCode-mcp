import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('../src/attack/verifyLoop', () => ({
    runVerifyLoop: vi.fn(),
}));

vi.mock('../src/attack/agentScanLoop', () => ({
    runAgentScan: vi.fn(),
}));

vi.mock('../src/attack/fixVerifyLoop', () => ({
    runFixVerifyLoop: vi.fn(),
}));

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
    };
});

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'fix-approval', duration: 0 }),
    })),
}));

vi.mock('../src/project-map/mapContext', () => ({
    getEndpointContextForFile: vi.fn().mockResolvedValue([]),
    getRelatedFilesForFile: vi.fn().mockResolvedValue([]),
    getMap: vi.fn().mockResolvedValue(null),
}));

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { toolAgentScan, mergeSegmentFindings } from '../src/tools/agentScan';
import { estimateJobMinutes } from '../src/jobs/jobRunner';
import { countFileLines } from '../src/attack/fileSegments';

function bigFile(functions: number, size = 100): string {
    const lines: string[] = [];
    for (let i = 0; i < functions; i++) {
        lines.push(`export function handler${i}(req: any, res: any) {`);
        for (let j = 0; j < size - 2; j++) lines.push(`    const v${j} = req.body.f${j};`);
        lines.push('}');
        lines.push('');
    }
    return lines.join('\n');
}

const BIG = bigFile(47);

function finding(line: number, type = 'sql_injection', evidence = 'db.query("SELECT " + req.body.id)') {
    return {
        type,
        line,
        lineEnd: line,
        evidence,
        why: 'user input concatenated into SQL',
        severity: 'high',
        confidence: 90,
    };
}

function agentResult(overrides: Record<string, unknown> = {}) {
    return {
        status: 'completed',
        terminationReason: 'agent_finish',
        findings: [],
        transcript: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 5,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.1,
        summary: 'done',
        creditsUsed: 5,
        baseCredits: 5,
        maxCredits: 15,
        creditExtensionsGranted: 0,
        ...overrides,
    } as any;
}

let workspaceRoot: string;
let order: string[];

function mockApi(credits: Record<string, number> = {}) {
    const postJson = vi.fn(async (p: string, body: any) => {
        order.push(p === '/agent/scan/close' ? `close:${body.runId}` : p);
        if (p === '/agent/scan/close') {
            return { settlement: { creditsRefunded: 0, creditsUsed: credits[body.runId] ?? 5 } };
        }
        return {};
    });
    vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);
    return postJson;
}

function closeCalls(postJson: any) {
    return (postJson.mock.calls as any[]).filter(c => c[0] === '/agent/scan/close').map(c => c[1].runId);
}

async function runScan(args: Record<string, unknown> = {}) {
    const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
    return toolAgentScan(ctx, { filePath: 'big.ts', language: 'typescript', _skipFix: true, _noCache: true, ...args }) as Promise<any>;
}

describe('toolAgentScan — large files scanned in parts', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-segments-'));
        fs.writeFileSync(path.join(workspaceRoot, 'big.ts'), BIG);
        fs.writeFileSync(path.join(workspaceRoot, 'small.ts'), 'export const a = 1;\n');
        order = [];
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(ApiClient).mockReset();
        vi.clearAllMocks();
        vi.mocked(runVerifyLoop).mockImplementation(async (input: any) => {
            order.push(`verify:${input.runId}`);
            return { verdict: 'UNPROVEN', reason: 'guard held', roundsUsed: 1, testScript: '', testOutput: '' } as any;
        });
        vi.mocked(runAgentScan).mockImplementation(async (_ctx: any, target: any, opts: any) => {
            const seg = opts.segment;
            order.push(`scan:${seg.index}`);
            opts.onProgress?.(1, 40, 'Step 1: read_file');
            const findings = seg.index === 1
                ? [finding(seg.endLine)]
                : seg.index === 2
                    ? [finding(seg.startLine)]
                    : seg.index === 3
                        ? [finding(seg.startLine + 10, 'path_traversal', 'fs.readFile(req.query.p)')]
                        : [];
            return agentResult({
                runId: `run-${seg.index}`,
                findings,
                summary: `part ${seg.index} done`,
                investigationNotes: [{ title: `note ${seg.index}`, detail: 'd', file: 'big.ts', verificationLevel: 'logic-confirmed', requiredEvidence: [], priority: 'low' }],
                creditsUsed: seg.index === 2 ? 7 : 5,
                creditExtensionsGranted: seg.index === 2 ? 1 : 0,
            });
        });
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    it('runs parts sequentially with the segment, closing each run once before the next part starts', async () => {
        const postJson = mockApi({ 'run-2': 7 });
        const messages: string[] = [];

        const result = await runScan({ _progress: (_c: number, _t: number, m: string) => messages.push(m) });

        const calls = vi.mocked(runAgentScan).mock.calls;
        expect(calls).toHaveLength(4);
        const segments = calls.map(c => (c[2] as any).segment);
        expect(segments.map(s => s.index)).toEqual([1, 2, 3, 4]);
        expect(segments.every(s => s.total === 4 && /^seg-[0-9a-f]{8}$/.test(s.groupId))).toBe(true);
        expect(new Set(segments.map(s => s.groupId)).size).toBe(1);
        expect(segments[0].startLine).toBe(1);
        for (let i = 1; i < 4; i++) expect(segments[i].startLine).toBe(segments[i - 1].endLine + 1);
        expect(segments[3].endLine).toBe(countFileLines(BIG));
        expect((calls[1][1] as any).segment).toEqual(segments[1]);
        expect(calls.every(c => (c[2] as any).deferClose === true)).toBe(true);

        expect(closeCalls(postJson)).toEqual(['run-1', 'run-2', 'run-3', 'run-4']);
        expect(order.indexOf('verify:run-1')).toBeLessThan(order.indexOf('close:run-1'));
        expect(order.indexOf('close:run-1')).toBeLessThan(order.indexOf('scan:2'));
        expect(order.indexOf('close:run-3')).toBeLessThan(order.indexOf('scan:4'));

        expect(messages[0]).toContain('lines → 4 parts, 20–60 credits');
        expect(messages).toContain('file part 2/4: Step 1: read_file');
        expect(messages.some(m => m.startsWith('file part 1/4: Scanning lines 1–'))).toBe(true);

        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.agentFindings).toHaveLength(2);
        expect(result.agentFindings.map((f: any) => f.type).sort()).toEqual(['path_traversal', 'sql_injection']);
        expect(result.creditsUsed).toBe(22);
        expect(result.creditsRefunded).toBe(0);
        expect(result.stepsUsed).toBe(20);
        expect(result.costSpentUsd).toBeCloseTo(0.4);
        expect(result.investigationNotes.map((n: any) => n.part.index)).toEqual([1, 2, 3, 4]);
        expect(result.segments).toHaveLength(4);
        expect(result.segments[1]).toMatchObject({ index: 2, status: 'completed', creditsUsed: 7 });
        expect(result.summary).toMatch(/^Scanned in 4 parts \(lines 1–[\d,]+, [\d,]+–[\d,]+, [\d,]+–[\d,]+, [\d,]+–4,746\)\. This file used 22 credits \(4 parts × 5 \+ 2 extension credits\)\./);
        expect(result.summary).toContain('part 3 done');
    });

    it('caches the merged result and serves it with its segments', async () => {
        mockApi();
        await runScan({ _noCache: false });
        vi.mocked(runAgentScan).mockClear();

        const cached = await runScan({ _noCache: false });

        expect(vi.mocked(runAgentScan)).not.toHaveBeenCalled();
        expect(cached.cached).toBe(true);
        expect(cached.segments).toHaveLength(4);
        expect(cached.agentFindings).toHaveLength(2);
    });

    it('keeps scanning after a failed part and reports the result as incomplete', async () => {
        const base = vi.mocked(runAgentScan).getMockImplementation()!;
        vi.mocked(runAgentScan).mockImplementation(async (ctx: any, target: any, opts: any) => {
            if (opts.segment.index === 2) {
                order.push('scan:2');
                return agentResult({ runId: 'run-2', status: 'failed', terminationReason: 'api_error', error: 'boom', findings: [] });
            }
            return base(ctx, target, opts);
        });
        const postJson = mockApi({ 'run-2': 5 });

        const result = await runScan({ _noCache: false });

        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(4);
        expect(closeCalls(postJson)).toEqual(['run-1', 'run-2', 'run-3', 'run-4']);
        expect(result.status).toBe('incomplete');
        expect(result.segments[1]).toMatchObject({ index: 2, status: 'failed', error: 'boom', creditsUsed: 5 });
        expect(result.summary).toMatch(/Part 2 \(lines [\d,]+–[\d,]+\) failed: boom\./);
        expect(result.creditsUsed).toBe(20);

        vi.mocked(runAgentScan).mockClear();
        await runScan({ _noCache: false });
        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(4);
    });

    it('stops cleanly when credits run out mid-file and returns the parts done', async () => {
        const base = vi.mocked(runAgentScan).getMockImplementation()!;
        vi.mocked(runAgentScan).mockImplementation(async (ctx: any, target: any, opts: any) => {
            if (opts.segment.index === 2) {
                order.push('scan:2');
                return agentResult({
                    status: 'failed',
                    terminationReason: 'api_error',
                    error: 'Insufficient credits — Top up at https://usesecurecode.tech and retry.',
                    findings: [],
                    runId: undefined,
                    creditsUsed: undefined,
                });
            }
            return base(ctx, target, opts);
        });
        const postJson = mockApi();

        const result = await runScan();

        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(2);
        expect(closeCalls(postJson)).toEqual(['run-1']);
        expect(result.status).toBe('incomplete');
        expect(result.capReason).toBe('insufficient_credits');
        expect(result.segments.map((s: any) => s.status)).toEqual(['completed', 'failed', 'not-started', 'not-started']);
        expect(result.agentFindings).toHaveLength(1);
        expect(result.creditsUsed).toBe(5);
        expect(result.summary).toContain('Out of credits after part 2 of 4');
        expect(result.summary).toContain('Top up at https://usesecurecode.tech');
        expect(result.coverageGaps.filter((g: any) => /not scanned/.test(g.title))).toHaveLength(2);
    });

    it('stops after a part whose extension failed for lack of credits', async () => {
        const base = vi.mocked(runAgentScan).getMockImplementation()!;
        vi.mocked(runAgentScan).mockImplementation(async (ctx: any, target: any, opts: any) => {
            const r = await base(ctx, target, opts);
            if (opts.segment.index === 1) r.capReason = 'insufficient_credits';
            return r;
        });
        mockApi();

        const result = await runScan();

        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(1);
        expect(result.segments.map((s: any) => s.status)).toEqual(['completed', 'not-started', 'not-started', 'not-started']);
        expect(result.summary).toContain('Out of credits after part 1 of 4');
    });

    it('stops starting parts once cancelled', async () => {
        const controller = new AbortController();
        const base = vi.mocked(runAgentScan).getMockImplementation()!;
        vi.mocked(runAgentScan).mockImplementation(async (ctx: any, target: any, opts: any) => {
            const r = await base(ctx, target, opts);
            controller.abort();
            return r;
        });
        const postJson = mockApi();

        const result = await runScan({ _signal: controller.signal });

        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(1);
        expect(closeCalls(postJson)).toEqual(['run-1']);
        expect(result.status).toBe('cancelled');
        expect(result.segments.slice(1).every((s: any) => s.status === 'not-started')).toBe(true);
    });

    it('throws when every part failed', async () => {
        vi.mocked(runAgentScan).mockImplementation(async (_c: any, _t: any, opts: any) =>
            agentResult({ runId: `run-${opts.segment.index}`, status: 'failed', error: 'server down', findings: [] }));
        const postJson = mockApi();

        await expect(runScan()).rejects.toThrow('server down');
        expect(closeCalls(postJson)).toEqual(['run-1', 'run-2', 'run-3', 'run-4']);
    });

    it('does not split files of 2,000 lines or less', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ runId: 'run-s' }));
        const postJson = mockApi();

        const result = await runScan({ filePath: 'small.ts' });

        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(1);
        expect((vi.mocked(runAgentScan).mock.calls[0][2] as any).segment).toBeUndefined();
        expect(closeCalls(postJson)).toEqual(['run-s']);
        expect(result).not.toHaveProperty('segments');
    });
});

describe('mergeSegmentFindings', () => {
    it('dedups by type, line ±2 and sink/evidence, keeping the stronger verdict', () => {
        const a = { ...finding(100), proven: 'UNPROVEN' } as any;
        const b = { ...finding(102), proven: 'PROVEN' } as any;
        const c = { ...finding(105), proven: 'INCONCLUSIVE' } as any;
        const d = { ...finding(101, 'sql_injection', 'other.query(x)'), proven: 'INCONCLUSIVE' } as any;
        const e = { ...finding(101, 'xss'), proven: 'INCONCLUSIVE' } as any;
        const s1 = { ...finding(200), proven: 'INCONCLUSIVE', evidenceChain: { flow: [], sink: { file: 'big.ts', line: 210, description: '' } } } as any;
        const s2 = { ...finding(201), proven: 'INCONCLUSIVE', evidenceChain: { flow: [], sink: { file: 'big.ts', line: 300, description: '' } } } as any;

        const merged = mergeSegmentFindings([a, b, c, d, e, s1, s2]);

        expect(merged).toHaveLength(6);
        expect(merged[0]).toBe(b);
        expect(merged).toContain(c);
        expect(merged).toContain(d);
        expect(merged).toContain(e);
        expect(merged).toContain(s1);
        expect(merged).toContain(s2);
    });
});

describe('estimateJobMinutes — file parts', () => {
    it('counts parts for a large single-file scan', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-estimate-'));
        try {
            fs.writeFileSync(path.join(ws, 'big.ts'), BIG);
            fs.writeFileSync(path.join(ws, 'small.ts'), 'const a = 1;\n');
            expect(estimateJobMinutes('agent-scan', { filePath: 'big.ts' }, ws)).toBe(32);
            expect(estimateJobMinutes('agent-scan', { filePath: 'small.ts' }, ws)).toBe(8);
            expect(estimateJobMinutes('agent-scan', { filePath: 'missing.ts' }, ws)).toBe(8);
            expect(estimateJobMinutes('agent-scan', { filePath: 'big.ts' })).toBe(8);
        } finally {
            fs.rmSync(ws, { recursive: true, force: true });
        }
    });
});
