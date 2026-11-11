// Vitest suite: handlers covered by reads delivered before or after
// get_endpoints are credited as reviewed, so the finish gate does not
// reject a fully read small route file for unreviewed handlers.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

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

vi.mock('../src/project-map/endpointDiscovery', () => ({
    discoverEndpoints: vi.fn(),
    formatEndpoints: vi.fn(() => 'endpoints'),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';
import { discoverEndpoints } from '../src/project-map/endpointDiscovery';

const FILE = 'routes/app.js';
const TOTAL_LINES = 43;
const HANDLER_LINES = [10, 16, 22, 28, 34];

const startResp = { runId: 'run-1', budget: { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 }, scanCredits: 95, refundId: 'r1' };

function step(next: any, remaining: number) {
    return { next, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: remaining };
}

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) mockFn.mockResolvedValueOnce(resp);
    mockFn.mockResolvedValue({ settlement: { creditsRefunded: 0, creditsUsed: 5 } });
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

function fileContent(): string {
    const lines = Array.from({ length: TOTAL_LINES }, (_, i) => `// line ${i + 1}`);
    lines[0] = "const express = require('express');";
    lines[1] = 'const app = express();';
    const verbs = ['get', 'post', 'put', 'delete', 'get'];
    HANDLER_LINES.forEach((line, i) => {
        lines[line - 1] = `app.${verbs[i]}('/r${i}', (req, res) => res.send(req.query.q));`;
    });
    return lines.join('\n');
}

function handlerRejections(result: any): string[] {
    return result.transcript
        .filter((t: any) => t.action.type === 'system_event' && t.action.eventType === 'finish_rejected')
        .map((t: any) => String(t.action.message))
        .filter((m: string) => /Review all discovered handlers|handler\(s\) unreviewed/.test(m));
}

const analysisSteps = (from: number) => [
    step({ type: 'check_policy', filePath: FILE, rationale: 'r' }, from),
    step({ type: 'search_code', pattern: 'authenticate', rationale: 'r' }, from - 1),
    step({ type: 'trace_flow_cross_file', filePath: FILE, rationale: 'r' }, from - 2),
    step({ type: 'read_config', configKind: 'all', rationale: 'r' }, from - 3),
    step({ type: 'check_guard', filePath: FILE, guardName: 'none', attackType: 'xss', rationale: 'r' }, from - 4),
    step({ type: 'finish', findings: [], summary: 'done', selfCritique: 'done' }, from - 5),
];

describe('runAgentScan — handler review coverage', () => {
    let workspaceRoot: string;
    let ctx: any;

    beforeEach(() => {
        vi.clearAllMocks();
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-handlers-'));
        fs.mkdirSync(path.join(workspaceRoot, 'routes'));
        fs.writeFileSync(path.join(workspaceRoot, FILE), fileContent());
        ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test' };
        (executeReadFileAction as any).mockImplementation(async (action: any) => ({
            observation: `lines ${action.startLine ?? 1}-${action.endLine ?? TOTAL_LINES}`,
            actualStart: action.startLine ?? 1,
            actualEnd: Math.min(action.endLine ?? TOTAL_LINES, TOTAL_LINES),
            totalLines: TOTAL_LINES,
            truncated: false,
        }));
        (executeAction as any).mockResolvedValue('ok');
        (executeFlowAction as any).mockResolvedValue({ observation: 'flow result', flowResult: { status: 'confirmed', hops: [{ filePath: FILE, line: 10 }], truncated: false } });
        (extractFunctionBoundaries as any).mockResolvedValue(null);
        (discoverEndpoints as any).mockResolvedValue(HANDLER_LINES.map((line, i) => ({
            method: ['GET', 'POST', 'PUT', 'DELETE', 'GET'][i], path: `/r${i}`, file: FILE, line, framework: 'express',
        })));
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    it('credits a whole-file read made before get_endpoints', async () => {
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: FILE, rationale: 'read whole file' }, 39),
            step({ type: 'get_endpoints', rationale: 'r' }, 38),
            ...analysisSteps(37),
        ]);

        const result = await runAgentScan(ctx, { filePath: FILE, language: 'javascript', fileContent: fileContent() }, {});

        expect(discoverEndpoints).toHaveBeenCalled();
        expect(handlerRejections(result)).toEqual([]);
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.coverageGaps.some((g: any) => /Review all discovered handlers/.test(g.title))).toBe(false);
    });

    it('combines a partial read before discovery with a later read', async () => {
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: FILE, startLine: 1, endLine: 20, rationale: 'r' }, 39),
            step({ type: 'get_endpoints', rationale: 'r' }, 38),
            step({ type: 'read_file', path: FILE, startLine: 21, endLine: 43, rationale: 'r' }, 37),
            ...analysisSteps(36),
        ]);

        const result = await runAgentScan(ctx, { filePath: FILE, language: 'javascript', fileContent: fileContent() }, {});

        expect(handlerRejections(result)).toEqual([]);
        expect(result.terminationReason).toBe('agent_finish');
    });

    it('still rejects finish while a handler range was never read', async () => {
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: FILE, startLine: 1, endLine: 20, rationale: 'r' }, 39),
            step({ type: 'get_endpoints', rationale: 'r' }, 38),
            ...analysisSteps(37),
            step(null, 30),
        ]);
        (executeReadFileAction as any).mockImplementation(async (action: any) => ({
            observation: 'partial',
            actualStart: action.startLine ?? 1,
            actualEnd: Math.min(action.endLine ?? 20, 20),
            totalLines: TOTAL_LINES,
            truncated: false,
        }));

        const result = await runAgentScan(ctx, { filePath: FILE, language: 'javascript', fileContent: fileContent() }, {});

        expect(handlerRejections(result).length).toBeGreaterThan(0);
    });

    it('credits handlers covered by a finish-gate recovery read', async () => {
        mockPostJson([
            startResp,
            step({ type: 'read_file', path: FILE, startLine: 1, endLine: 20, rationale: 'r' }, 39),
            step({ type: 'get_endpoints', rationale: 'r' }, 38),
            ...analysisSteps(37),
            step({ type: 'finish', findings: [], summary: 'done again', selfCritique: 'done' }, 30),
        ]);

        const result = await runAgentScan(ctx, { filePath: FILE, language: 'javascript', fileContent: fileContent() }, {});

        const recoveries = result.transcript.filter((t: any) => String(t.observation).startsWith('[FINISH GATE RECOVERY]'));
        expect(recoveries.length).toBe(1);
        expect((recoveries[0].action as any).type).toBe('read_file');
        expect(handlerRejections(result)).toHaveLength(1);
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.summary).toContain('done again');
    });
});
