// Cache-guard tests for the agent-scan tool:
//  - only fully-successful scans (status 'completed' + terminationReason
//    'agent_finish') are written to the scan cache
//  - incomplete/failed scans never write to cache
//  - the documented `noCache` arg (and the internal `_noCache` alias)
//    bypasses the cache read so a fresh scan always runs
// Mocking structure modeled on tests/agentScanFixRegen.test.ts.

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
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'approval', duration: 0 }),
    })),
}));

vi.mock('../src/project-map/mapContext', () => ({
    getEndpointContextForFile: vi.fn().mockResolvedValue([]),
    getRelatedFilesForFile: vi.fn().mockResolvedValue([]),
    getMap: vi.fn().mockResolvedValue(null),
}));

vi.mock('../src/project-map/fixTester', () => ({
    testFix: vi.fn().mockResolvedValue({
        passes: true,
        syntaxValid: true,
        fixEffective: true,
        newVulnerabilities: [],
        regressions: [],
        tests: [],
    }),
}));

vi.mock('../src/project-map/scanCache', () => ({
    getCachedScan: vi.fn(),
    writeCachedScan: vi.fn(),
    computeMemoryFingerprint: vi.fn(() => 'test-fingerprint'),
    filterCachedFindingsAgainstMemory: vi.fn((findings: unknown[]) => findings),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { runVerifyLoop } from '../src/attack/verifyLoop';
import { getCachedScan, writeCachedScan } from '../src/project-map/scanCache';
import { toolAgentScan } from '../src/tools/agentScan';

const CODE = [
    'import express from "express";',
    'const app = express();',
    'app.post("/users", (req, res) => {',
    '  const q = "SELECT * FROM users WHERE id=" + req.body.id;',
    '  db.query(q);',
    '  res.send("ok");',
    '});',
].join('\n');

function makeFinding() {
    return {
        type: 'sql_injection',
        line: 4,
        lineEnd: 5,
        evidence: 'const q = "SELECT * FROM users WHERE id=" + req.body.id;',
        why: 'user input concatenated into SQL',
        severity: 'high',
        confidence: 95,
    };
}

function setupScan(overrides: Record<string, unknown> = {}) {
    vi.mocked(runAgentScan).mockResolvedValue({
        status: 'completed',
        terminationReason: 'agent_finish',
        findings: [makeFinding()],
        transcript: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 5,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.05,
        summary: 'scan finished',
        ...overrides,
    } as any);
}

function setupVerifyProven() {
    vi.mocked(runVerifyLoop).mockResolvedValue({
        verdict: 'PROVEN',
        reason: 'exploit reproduced',
        roundsUsed: 2,
        testScript: '',
        testOutput: '',
        subVerdict: 'analyzed',
    } as any);
}

let workspaceRoot: string;

describe('toolAgentScan — scan cache guard', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-cacheguard-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), CODE);
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(runVerifyLoop).mockReset();
        vi.clearAllMocks();
        setupScan();
        setupVerifyProven();
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    async function runScan(args: Record<string, unknown> = {}) {
        const ctx: any = {
            workspaceRoot,
            apiUrl: 'https://api.usesecurecode.tech',
            apiToken: 'test-token',
        };
        return toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript', _skipFix: true, ...args });
    }

    it('caches a fully-successful scan (completed + agent_finish)', async () => {
        const result: any = await runScan();

        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');

        // Cache read was attempted before the fresh scan ran.
        expect(getCachedScan).toHaveBeenCalledTimes(1);

        // Successful fresh scan is written back to cache.
        expect(writeCachedScan).toHaveBeenCalledTimes(1);
        const call = vi.mocked(writeCachedScan).mock.calls[0];
        expect(call[0]).toBe(workspaceRoot);
        expect(call[1]).toBe('routes.ts');
        expect(call[4]).toBe('test-fingerprint');
        expect(call[3]).toMatchObject({
            status: 'completed',
            terminationReason: 'agent_finish',
        });
        expect(call[3].findings).toHaveLength(1);
    });

    it('does not cache an incomplete scan (blocked_read_recovery)', async () => {
        setupScan({ status: 'incomplete', terminationReason: 'blocked_read_recovery', findings: [], summary: 'read blocked' });

        const result: any = await runScan();

        expect(result.status).toBe('incomplete');
        expect(result.terminationReason).toBe('blocked_read_recovery');
        expect(writeCachedScan).not.toHaveBeenCalled();
    });

    it('does not cache a completed scan that stopped for a non-finish reason (llm_degraded)', async () => {
        setupScan({ status: 'completed', terminationReason: 'llm_degraded', findings: [] });

        await runScan();

        expect(writeCachedScan).not.toHaveBeenCalled();
    });

    it('noCache: true bypasses the cache read and runs a fresh scan', async () => {
        const result: any = await runScan({ noCache: true });

        expect(getCachedScan).not.toHaveBeenCalled();
        expect(runAgentScan).toHaveBeenCalledTimes(1);
        expect(result.status).toBe('completed');
        // Fresh results are still written back.
        expect(writeCachedScan).toHaveBeenCalledTimes(1);
    });

    it('_noCache internal alias still bypasses the cache read', async () => {
        await runScan({ _noCache: true });

        expect(getCachedScan).not.toHaveBeenCalled();
        expect(runAgentScan).toHaveBeenCalledTimes(1);
    });

    it('reads the cache when noCache is not requested', async () => {
        await runScan();

        expect(getCachedScan).toHaveBeenCalledTimes(1);
        expect(getCachedScan).toHaveBeenCalledWith(workspaceRoot, 'routes.ts', CODE);
    });
});
