import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({
            postJson: vi.fn(),
        })),
    };
});

vi.mock('../src/attack/agentScanExecutor', () => ({
    executeAction: vi.fn(),
    executeReadFileAction: vi.fn(),
    executeFlowAction: vi.fn(),
    extractFunctionBoundaries: vi.fn(),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';
import {
    clampHarnessSettings,
    DEFAULT_AGENT_HARNESS,
    FULL_READ_WINDOW,
} from '../src/attack/agentScanProtocol';
import { InvestigationState } from '../src/attack/investigationState';

const ctx = { workspaceRoot: '/tmp/securecode-harness-test-missing', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const baseStart = { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' };

function step(next: any, remaining: number, extra: Record<string, unknown> = {}) {
    return { next, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: remaining, ...extra };
}

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) mockFn.mockResolvedValueOnce(resp);
    mockFn.mockResolvedValue({ settlement: { creditsRefunded: 0, creditsUsed: 5 } });
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

function setupExecutors(totalLines: number) {
    (executeReadFileAction as any).mockImplementation(async (action: any) => ({
        observation: `lines ${action.startLine}-${action.endLine}`,
        actualStart: action.startLine ?? 1,
        actualEnd: action.endLine ?? totalLines,
        totalLines,
        truncated: false,
    }));
    (executeAction as any).mockResolvedValue('ok');
    (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [], truncated: false } });
    (extractFunctionBoundaries as any).mockResolvedValue(null);
}

const target = { filePath: 'small.ts', language: 'typescript', fileContent: Array.from({ length: 100 }, (_, i) => `const v${i + 1} = ${i + 1};`).join('\n') };
const read = (start: number, end: number) => ({ type: 'read_file', path: 'lib.ts', startLine: start, endLine: end, rationale: 'read' });

function readSequence() {
    return [
        step(read(1, 20), 39),
        step(read(21, 40), 38),
        step(read(41, 60), 37),
        step(read(1, 20), 36),
        step(null, 35, { costCapped: true, capReason: 'max_credits' }),
    ];
}

const stepBodies = (mockFn: any) => (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step').map(c => c[1]);

describe('clampHarnessSettings (MCP mirror)', () => {
    it('defaults to checklist / 2 / window', () => {
        expect(DEFAULT_AGENT_HARNESS).toEqual({ gateMode: 'checklist', fullReadWindow: 2, reReadPolicy: 'window' });
        expect(DEFAULT_AGENT_HARNESS.fullReadWindow).toBe(FULL_READ_WINDOW);
        expect(clampHarnessSettings(undefined)).toEqual(DEFAULT_AGENT_HARNESS);
        expect(clampHarnessSettings('evidence')).toEqual(DEFAULT_AGENT_HARNESS);
    });

    it('clamps the window and replaces unknown enums', () => {
        expect(clampHarnessSettings({ fullReadWindow: 1 }).fullReadWindow).toBe(2);
        expect(clampHarnessSettings({ fullReadWindow: 9 }).fullReadWindow).toBe(4);
        expect(clampHarnessSettings({ fullReadWindow: 3.5 }).fullReadWindow).toBe(2);
        expect(clampHarnessSettings({ gateMode: 'yolo', reReadPolicy: 'x', fullReadWindow: 3 }))
            .toEqual({ gateMode: 'checklist', fullReadWindow: 3, reReadPolicy: 'window' });
        expect(clampHarnessSettings({ gateMode: 'evidence', fullReadWindow: 4, reReadPolicy: 'coverage' }))
            .toEqual({ gateMode: 'evidence', fullReadWindow: 4, reReadPolicy: 'coverage' });
    });
});

describe('InvestigationState full-read window', () => {
    it('keeps the last FULL_READ_WINDOW reads visible by default and honours a larger window', () => {
        const record = (s: InvestigationState) => {
            for (const [a, b] of [[1, 20], [21, 40], [41, 60]]) s.recordRead('lib.ts', a, b, 100);
        };
        const def = new InvestigationState();
        record(def);
        expect(def.getVisibleRanges('lib.ts')).toEqual([{ start: 21, end: 40 }, { start: 41, end: 60 }]);
        const three = new InvestigationState(3);
        record(three);
        expect(three.getVisibleRanges('lib.ts')).toHaveLength(3);
    });
});

describe('runAgentScan — harness settings', () => {
    beforeEach(() => vi.clearAllMocks());

    it('uses the default harness when the start response has none', async () => {
        setupExecutors(100);
        const mockFn = mockPostJson([baseStart, ...readSequence()]);

        const result = await runAgentScan(ctx, target, {});

        const bodies = stepBodies(mockFn);
        expect(bodies.length).toBeGreaterThan(1);
        for (const b of bodies) expect(b.harness).toEqual(DEFAULT_AGENT_HARNESS);
        const reRead = result.transcript.filter(t => t.action.type === 'read_file')[3];
        expect(reRead.observation).not.toContain('BLOCKED');
    });

    it('echoes the start-response harness in every step request and blocks re-reads inside the larger window', async () => {
        setupExecutors(100);
        const harness = { gateMode: 'evidence', fullReadWindow: 3, reReadPolicy: 'window' };
        const mockFn = mockPostJson([{ ...baseStart, harness }, ...readSequence()]);

        const result = await runAgentScan(ctx, target, {});

        const bodies = stepBodies(mockFn);
        expect(bodies.length).toBeGreaterThan(1);
        for (const b of bodies) expect(b.harness).toEqual(harness);
        const reRead = result.transcript.filter(t => t.action.type === 'read_file')[3];
        expect(reRead.observation).toContain('BLOCKED');
        expect(reRead.observation).toContain('one of your last 3 reads');
    });

    it('clamps a malformed start-response harness', async () => {
        setupExecutors(100);
        const mockFn = mockPostJson([{ ...baseStart, harness: { gateMode: 'nope', fullReadWindow: 50 } }, ...readSequence()]);

        await runAgentScan(ctx, target, {});

        for (const b of stepBodies(mockFn)) expect(b.harness).toEqual({ gateMode: 'checklist', fullReadWindow: 4, reReadPolicy: 'window' });
    });
});
