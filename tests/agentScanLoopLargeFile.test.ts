// Vitest suite for the scan agent loop — large-file read recovery.
//
// Regression coverage for the production blocked_read_recovery death
// spiral on a >300-line file:
//   - Initial no-range read returns a function map; an identical repeat is
//     blocked with a ranged-read hint (fnmap key).
//   - Ranged reads that exceed the 16k observation cap record coverage ONLY
//     for the delivered lines, so the lost remainder is re-readable.
//   - Deterministic recovery actions record evidence, so the scheduler
//     advances requirement-by-requirement instead of re-proposing the same
//     action until triple-rejection terminates the scan.
//   - Scheduler recovery read_file actions carry line ranges.
//
// The read executor is the REAL one (delegated through the mock) so the
// truncation-aware delivered-range reporting is exercised end-to-end; the
// API client and the analysis tools follow the loop-test mocking pattern.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

vi.mock('../src/attack/agentScanExecutor', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../src/attack/agentScanExecutor')>();
    return {
        executeAction: vi.fn(async () => 'ok'),
        executeReadFileAction: vi.fn(async (action: any, ctx: any) => actual.executeReadFileAction(action, ctx)),
        executeFlowAction: vi.fn(async (action: any) => ({
            observation: `No taint flows found starting from ${action.filePath}.`,
            flowResult: { status: 'refuted', hops: [], truncated: false },
        })),
        extractFunctionBoundaries: actual.extractFunctionBoundaries,
    };
});

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';

let workspaceRoot: string;

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) {
        mockFn.mockResolvedValueOnce(resp);
    }
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

function startResponse() {
    return { runId: 'run-large-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' };
}

function stepResponse(next: any, stepsRemaining: number) {
    return { next, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining };
}

// ~1100 lines, uniformly dense (~110 chars/line average), and free of the
// finish gate's high-priority keywords so unread tail ranges don't block
// finish acceptance. Padded to exactly 1100 lines with parse-safe comments.
function makeLargeFileContent(): string {
    const lines: string[] = ["import express from 'express';"];
    let fn = 0;
    while (lines.length + 14 <= 1100) {
        fn++;
        lines.push(`export async function handler${fn}(req: express.Request, res: express.Response) {`);
        for (let j = 0; j < 11; j++) {
            lines.push(`    const record${fn}_${j} = JSON.stringify({ name: req.body.name${j}, route: req.params.route${j}, section: ${fn}, depth: ${j}, checksum: ${(fn * 13 + j * 7) % 997} });`);
        }
        lines.push('    res.status(200).json({ ok: true, received: true });');
        lines.push('}');
        lines.push('');
    }
    while (lines.length < 1100) {
        lines.push(`// padding line ${lines.length}`);
    }
    return lines.join('\n');
}

function makeSmallFileContent(): string {
    return Array.from({ length: 100 }, (_, i) => `export function step${i + 1}(input: string): string { return input + '-${i + 1}'; }`).join('\n');
}

beforeEach(() => {
    vi.clearAllMocks();
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'scanlarge-'));
    vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
    vi.restoreAllMocks();
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
});

describe('runAgentScan — large-file read recovery', () => {
    it('records delivered-only coverage for truncated reads and lets the agent re-read the lost remainder', async () => {
        const content = makeLargeFileContent();
        fs.writeFileSync(path.join(workspaceRoot, 'big.ts'), content);
        const target = { filePath: 'big.ts', language: 'typescript', fileContent: content };
        const ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test' };

        const noRangeRead = { type: 'read_file', path: 'big.ts', rationale: 'read the target' };
        const mockFn = mockPostJson([
            startResponse(),
            // T[0]: first no-range read → real executor returns the function map
            stepResponse({ type: 'read_file', path: 'big.ts', rationale: 'read the target' }, 39),
            // T[1], T[2], T[3]: identical whole-file repeats → blocked (fnmap key)
            stepResponse({ type: 'read_file', path: 'big.ts', rationale: 'read the target' }, 38),
            stepResponse({ type: 'read_file', path: 'big.ts', rationale: 'read the target' }, 37),
            stepResponse({ type: 'read_file', path: 'big.ts', rationale: 'read the target' }, 36),
            // T[5]: wide ranged read — exceeds the 16k cap, comes back truncated
            stepResponse({ type: 'read_file', path: 'big.ts', startLine: 200, endLine: 500, rationale: 'wide read' }, 35),
            // T[6]: re-read of the lost remainder — must NOT be blocked
            stepResponse({ type: 'read_file', path: 'big.ts', startLine: 400, endLine: 450, rationale: 're-read remainder' }, 34),
            stepResponse({ type: 'trace_flow_cross_file', filePath: 'big.ts', rationale: 'trace' }, 33),
            stepResponse({ type: 'read_config', configKind: 'all', rationale: 'config' }, 32),
            stepResponse({ type: 'find_tests', filePath: 'big.ts', rationale: 'tests' }, 31),
            stepResponse({ type: 'finish', findings: [], summary: 'done', selfCritique: 'done' }, 30),
        ]);

        const result = await runAgentScan(ctx, target, {});

        // (d) The scan completes — no blocked_read_recovery termination.
        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.terminationReason).not.toBe('blocked_read_recovery');

        const t = result.transcript;

        // Step 1 delivered a function map (large file, no range).
        expect(t[0].observation).toContain('Function map');
        expect(t[0].observation).toContain('LARGE FILE');

        // Step 2: the identical whole-file repeat is blocked with a hint to
        // use ranged reads instead of re-fetching the same map.
        expect(t[1].observation).toContain('BLOCKED');
        expect(t[1].observation).toContain('function map');
        expect(t[1].observation).toContain('startLine');

        // Deterministic recovery fired with a RANGED read_file — the
        // scheduler populates startLine/endLine from the next unread range.
        const recoverySteps = t.filter(s => s.observation?.startsWith('[DETERMINISTIC RECOVERY]'));
        expect(recoverySteps.length).toBe(1);
        const recoveryRead = recoverySteps[0];
        expect(recoveryRead.action.type).toBe('read_file');
        expect(typeof (recoveryRead.action as any).startLine).toBe('number');
        expect((recoveryRead.action as any).startLine).toBeGreaterThanOrEqual(1);
        expect(typeof (recoveryRead.action as any).endLine).toBe('number');

        // The wide ranged read came back truncated with an explicit re-read note.
        const wideRead = t.find(s => s.action.type === 'read_file' && (s.action as any).startLine === 200);
        expect(wideRead).toBeDefined();
        expect(wideRead!.observation).not.toContain('BLOCKED');
        expect(wideRead!.observation).toContain('[truncated at line ');
        expect(wideRead!.observation).toContain('re-read lines ');

        // (a)+(b) Coverage was recorded ONLY for the delivered lines — the
        // re-read of the lost remainder executes cleanly instead of being
        // blocked as duplicate/high-overlap of the requested 200..500 range.
        const remainderRead = t.find(s => s.action.type === 'read_file' && (s.action as any).startLine === 400);
        expect(remainderRead).toBeDefined();
        expect(remainderRead!.observation).not.toContain('BLOCKED');
        expect(remainderRead!.observation).toContain('lines 400-450 of 1100');

        // (c) No duplicate-recovery rejection was ever issued.
        // 11 step-path calls + the final /agent/scan/close (the loop now
        // confirms every exit — accepted finishes included).
        expect(mockFn.mock.calls.length).toBe(12);
        const warned = (console.warn as any).mock.calls.some((c: any[]) => String(c[0]).includes('Duplicate recovery action'));
        expect(warned).toBe(false);
    });

    it('recovery actions record evidence so the scheduler advances requirements without triple-rejection', async () => {
        const content = makeSmallFileContent();
        fs.writeFileSync(path.join(workspaceRoot, 'small.ts'), content);
        const target = { filePath: 'small.ts', language: 'typescript', fileContent: content };
        const ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test' };

        const dupRead = { type: 'read_file', path: 'small.ts', startLine: 1, endLine: 100, rationale: 'r' };
        const dup = (n: number) => stepResponse({ ...dupRead }, n);
        const mockFn = mockPostJson([
            startResponse(),
            stepResponse({ ...dupRead }, 39),   // T[0]: full read, coverage 1..100
            dup(38), dup(37), dup(36),          // blocked 1,2,3 → recovery A (cross-file-flow)
            dup(35), dup(34), dup(33),          // blocked 1,2,3 → recovery B (tests-found)
            dup(32), dup(31), dup(30),          // blocked 1,2,3 → recovery C (threat-model → read_config)
            stepResponse({ type: 'trace_flow_cross_file', filePath: 'small.ts', rationale: 'trace' }, 29),
            stepResponse({ type: 'finish', findings: [], summary: 'done', selfCritique: 'done' }, 28),
        ]);

        const result = await runAgentScan(ctx, target, {});

        // (d) The scan completes — no blocked_read_recovery termination.
        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.terminationReason).not.toBe('blocked_read_recovery');

        // (c) The scheduler ADVANCED one requirement per recovery cycle
        // (cross-file flow → tests → config) instead of re-proposing the
        // same action until triple-rejection terminated the run.
        const recoverySteps = result.transcript.filter(s => s.observation?.startsWith('[DETERMINISTIC RECOVERY]'));
        expect(recoverySteps.length).toBe(3);
        expect(recoverySteps.map(s => s.action.type)).toEqual([
            'trace_flow_cross_file', 'find_tests', 'read_config',
        ]);
        expect(recoverySteps[0].action).toMatchObject({ filePath: 'small.ts', requirementId: 'util-cross-file-flow' });
        expect(recoverySteps[1].action).toMatchObject({ filePath: 'small.ts', requirementId: 'util-tests-found' });
        expect(recoverySteps[2].action).toMatchObject({ configKind: 'all', requirementId: 'util-threat-model' });

        // No duplicate-recovery rejection was ever issued.
        const warned = (console.warn as any).mock.calls.some((c: any[]) => String(c[0]).includes('Duplicate recovery action'));
        expect(warned).toBe(false);

        // Recovery constraint is sent from 2 blocked reads onward and is
        // cleared again once a recovery makes progress.
        const constraintAfter2 = (mockFn.mock.calls[4][1] as any).actionConstraint;
        expect(constraintAfter2).toBeDefined();
        expect(constraintAfter2.mode).toBe('recovery');
        expect(constraintAfter2.requiredAction).toBe('trace_flow_cross_file');
        expect((mockFn.mock.calls[5][1] as any).actionConstraint).toBeUndefined();
        const constraintSecondCycle = (mockFn.mock.calls[7][1] as any).actionConstraint;
        expect(constraintSecondCycle).toBeDefined();
        expect(constraintSecondCycle.mode).toBe('recovery');
    });
});
