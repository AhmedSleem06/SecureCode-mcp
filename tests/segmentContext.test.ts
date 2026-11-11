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
import { toolAgentScan, buildPriorPartsContext, type PartRecord } from '../src/tools/agentScan';

function part(index: number, startLine: number, endLine: number, result?: Record<string, any>): PartRecord {
    return { segment: { index, startLine, endLine } as any, ...(result ? { result } : {}) };
}

function finding(line: number, type: string, why: string, proven?: string) {
    return { type, line, why, evidence: 'e', severity: 'high', confidence: 80, ...(proven ? { proven } : {}) };
}

describe('buildPriorPartsContext', () => {
    it('summarises findings with their verdict and notes per finished part', () => {
        const text = buildPriorPartsContext([
            part(1, 1, 1500, {
                status: 'completed',
                agentFindings: [
                    finding(1402, 'sql_injection', 'req.query.id reaches db.query unescaped', 'INCONCLUSIVE'),
                    finding(1290, 'missing_authorization', 'deleteWorkspace skips requireWsOwnerSession', 'PROVEN'),
                ],
                investigationNotes: [{ title: 'Owner check reads the session cookie only', line: 1288 }],
            }),
            part(2, 1501, 3000, { status: 'completed', agentFindings: [], investigationNotes: [] }),
            part(3, 3001, 4500),
        ]);

        expect(text).toBe([
            'Earlier parts of this file (already scanned):',
            'Part 1 (lines 1–1,500):',
            '  finding: missing_authorization@1290 [PROVEN] — deleteWorkspace skips requireWsOwnerSession',
            '  finding: sql_injection@1402 [INCONCLUSIVE] — req.query.id reaches db.query unescaped',
            '  note: Owner check reads the session cookie only (line 1288)',
            'Part 2 (lines 1,501–3,000): no findings or notes.',
        ].join('\n'));
    });

    it('returns an empty string when no earlier part has a result', () => {
        expect(buildPriorPartsContext([])).toBe('');
        expect(buildPriorPartsContext([part(1, 1, 1500), part(2, 1501, 3000)])).toBe('');
    });

    it('marks failed parts as unscanned', () => {
        expect(buildPriorPartsContext([part(1, 1, 1500, { status: 'failed', agentFindings: [] })]))
            .toBe('Earlier parts of this file (already scanned):\nPart 1 (lines 1–1,500): scan failed; treat these lines as unscanned.');
    });

    it('clips long reasons and titles', () => {
        const text = buildPriorPartsContext([part(1, 1, 1500, {
            status: 'completed',
            agentFindings: [finding(10, 'xss', 'w'.repeat(300))],
            investigationNotes: [{ title: 't'.repeat(300), line: 20 }],
        })]);
        const [, , findingLine, noteLine] = text.split('\n');
        expect(findingLine).toBe(`  finding: xss@10 — ${'w'.repeat(139)}…`);
        expect(noteLine).toBe(`  note: ${'t'.repeat(99)}… (line 20)`);
    });

    it('truncates to maxChars with a trailing marker', () => {
        const findings = Array.from({ length: 60 }, (_, i) => finding(i + 1, 'idor', `reason number ${i + 1} `.repeat(5)));
        const text = buildPriorPartsContext([part(1, 1, 1500, { status: 'completed', agentFindings: findings })], 800);
        expect(text.length).toBeLessThanOrEqual(800);
        expect(text.endsWith('\n…')).toBe(true);
        expect(text).toContain('idor@1 — reason number 1');
        expect(text).not.toContain('idor@60');
    });
});

function guardedFile(functions = 47, size = 100): string {
    const lines: string[] = ["import { requireWsOwnerSession } from './auth';"];
    for (let i = 0; i < functions; i++) {
        lines.push(`export function handler${i}(req: any, res: any) {`);
        lines.push('    requireWsOwnerSession(req);');
        for (let j = 0; j < size - 3; j++) lines.push(`    const v${j} = req.body.f${j};`);
        lines.push('}');
        lines.push('');
    }
    return lines.join('\n');
}

describe('toolAgentScan — segment context', () => {
    let workspaceRoot: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-segctx-'));
        vi.clearAllMocks();
        vi.mocked(ApiClient).mockImplementation(() => ({
            postJson: vi.fn(async (p: string) => (p === '/agent/scan/close' ? { settlement: { creditsRefunded: 0, creditsUsed: 5 } } : {})),
        }) as any);
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'UNPROVEN', reason: 'guard held', roundsUsed: 1, testScript: '', testOutput: '' } as any);
        vi.mocked(runAgentScan).mockImplementation(async (_ctx: any, _target: any, opts: any) => {
            const seg = opts.segment;
            return {
                status: 'completed',
                terminationReason: 'agent_finish',
                findings: seg.index === 1
                    ? [{ type: 'missing_authorization', line: seg.startLine + 50, lineEnd: seg.startLine + 50, evidence: 'x', why: 'handler skips the owner check', severity: 'high', confidence: 80 }]
                    : [],
                transcript: [],
                investigationNotes: [{ title: `note from part ${seg.index}`, detail: 'd', file: 'big.ts', line: seg.startLine + 5, verificationLevel: 'logic-confirmed', requiredEvidence: [], priority: 'low' }],
                coverageGaps: [],
                stepsUsed: 5,
                stepsGranted: 40,
                extensionsGranted: 0,
                costSpentUsd: 0.1,
                summary: 'done',
                runId: `run-${seg.index}`,
                creditsUsed: 5,
                baseCredits: 5,
                maxCredits: 15,
                creditExtensionsGranted: 0,
            } as any;
        });
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    it('sends the guard map to every part and earlier conclusions to later parts', async () => {
        fs.writeFileSync(path.join(workspaceRoot, 'big.ts'), guardedFile());
        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        await toolAgentScan(ctx, { filePath: 'big.ts', language: 'typescript', _skipFix: true, _noCache: true });

        const calls = vi.mocked(runAgentScan).mock.calls;
        expect(calls.length).toBeGreaterThan(2);
        const contexts = calls.map(c => (c[2] as any).segment.context as string);
        for (const [i, c] of calls.entries()) expect((c[1] as any).segment.context).toBe(contexts[i]);

        expect(contexts[0]).toMatch(/^Authorization checks used in this file:\nrequireWsOwnerSession: used at 3, \d+, .*, … \(47 uses\)$/);
        expect(contexts[0]).not.toContain('Earlier parts');

        const first = calls[0][2] as any;
        expect(contexts[1]).toContain('\n\nEarlier parts of this file (already scanned):\nPart 1 (lines ');
        expect(contexts[1]).toContain(`  finding: missing_authorization@${first.segment.startLine + 50} [UNPROVEN] — handler skips the owner check`);
        expect(contexts[1]).toContain(`  note: note from part 1 (line ${first.segment.startLine + 5})`);
        expect(contexts[1]).not.toContain('note from part 2');
        expect(contexts[2]).toContain('note from part 2');
        expect(contexts.every(c => c.length <= 4000)).toBe(true);
    });

    it('omits context when the file has no guards and no part has finished', async () => {
        const plain = Array.from({ length: 4000 }, (_, i) => `const v${i} = ${i};`).join('\n');
        fs.writeFileSync(path.join(workspaceRoot, 'big.ts'), plain);
        const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
        await toolAgentScan(ctx, { filePath: 'big.ts', language: 'typescript', _skipFix: true, _noCache: true });

        const calls = vi.mocked(runAgentScan).mock.calls;
        expect(calls.length).toBeGreaterThan(1);
        expect('context' in (calls[0][2] as any).segment).toBe(false);
        expect((calls[1][2] as any).segment.context).toMatch(/^Earlier parts of this file \(already scanned\):\nPart 1 /);
    });
});
