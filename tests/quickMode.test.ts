import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../src/attack/verifyLoop', () => ({
    runVerifyLoop: vi.fn(),
}));

vi.mock('../src/attack/agentScanLoop', () => ({
    runAgentScan: vi.fn(),
}));

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
    };
});

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'r', duration: 0 }),
        requestSessionApproval: vi.fn().mockResolvedValue({
            granted: true, state: 'granted', reason: 'ok', detail: '', requestId: 'sess-1',
            runId: 'r', maxTests: 100, remaining: 100, expiresAt: Date.now() + 600_000,
        }),
    })),
    consumeSessionApproval: vi.fn().mockReturnValue(true),
    revokeSessionApproval: vi.fn().mockReturnValue(true),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { runVerifyLoop } from '../src/attack/verifyLoop';
import { ApiClient } from '../src/api/client';
import { toolAgentScan } from '../src/tools/agentScan';

function agentResult(overrides: any = {}) {
    return {
        status: 'completed',
        findings: [],
        investigationNotes: [],
        coverageGaps: [],
        transcript: [],
        stepsUsed: 5,
        stepsGranted: 40,
        extensionsGranted: 0,
        costSpentUsd: 0.30,
        terminationReason: 'agent_finish',
        runId: 'run-1',
        ...overrides,
    };
}

const FINDING_HIGH = { type: 'sql_injection', line: 10, severity: 'high', confidence: 90, evidence: 'e', why: 'w' };
const FINDING_MED = { type: 'xss', line: 20, severity: 'medium', confidence: 75, evidence: 'e', why: 'w' };
const FINDING_LOW = { type: 'info_disclosure', line: 30, severity: 'low', confidence: 60, evidence: 'e', why: 'w' };

describe('agent-scan mode mapping', () => {
    const ctx: any = { workspaceRoot: '/tmp/ws', apiUrl: 'http://localhost:3000', apiToken: 'test' };

    beforeEach(() => {
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(runVerifyLoop).mockReset();
    });

    it('maps mode=standard to requestedMode=standard', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ scanMode: 'standard' }));
        vi.mocked(ApiClient).mockReturnValue({ postJson: vi.fn() } as any);

        await toolAgentScan(ctx, { code: 'x', language: 'javascript', mode: 'standard' });

        const opts = vi.mocked(runAgentScan).mock.calls[0][2];
        expect(opts.requestedMode).toBe('standard');
    });

    it('maps mode=deep to requestedMode=assurance', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ scanMode: 'assurance' }));
        vi.mocked(ApiClient).mockReturnValue({ postJson: vi.fn() } as any);

        await toolAgentScan(ctx, { code: 'x', language: 'javascript', mode: 'deep' });

        const opts = vi.mocked(runAgentScan).mock.calls[0][2];
        expect(opts.requestedMode).toBe('assurance');
    });

    it('omits requestedMode when mode is not specified', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ scanMode: 'standard' }));
        vi.mocked(ApiClient).mockReturnValue({ postJson: vi.fn() } as any);

        await toolAgentScan(ctx, { code: 'x', language: 'javascript' });

        const opts = vi.mocked(runAgentScan).mock.calls[0][2];
        expect(opts.requestedMode).toBeUndefined();
    });

    it('rejects mode=quick with a clear error', async () => {
        await expect(
            toolAgentScan(ctx, { code: 'x', language: 'javascript', mode: 'quick' }),
        ).rejects.toThrow("mode 'quick' was removed");
    });
});

describe('agent-scan result scanMode', () => {
    const ctx: any = { workspaceRoot: '/tmp/ws', apiUrl: 'http://localhost:3000', apiToken: 'test' };

    beforeEach(() => {
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(runVerifyLoop).mockReset();
    });

    it('maps server assurance to deep in the result', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ scanMode: 'assurance' }));
        vi.mocked(ApiClient).mockReturnValue({ postJson: vi.fn() } as any);

        const result = await toolAgentScan(ctx, { code: 'x', language: 'javascript', mode: 'deep' });

        expect(result.scanMode).toBe('deep');
        expect(result.summary).toContain('[deep mode]');
    });

    it('maps server standard to standard in the result', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ scanMode: 'standard' }));
        vi.mocked(ApiClient).mockReturnValue({ postJson: vi.fn() } as any);

        const result = await toolAgentScan(ctx, { code: 'x', language: 'javascript' });

        expect(result.scanMode).toBe('standard');
        expect(result.summary).toContain('[standard mode]');
    });

    it('standard mode proves high + medium findings', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({
            scanMode: 'standard',
            findings: [FINDING_HIGH, FINDING_MED, FINDING_LOW],
        }));
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'PROVEN', reason: 'exploited', roundsUsed: 2,
            testScript: '', testOutput: '', subVerdict: 'proven',
        });
        vi.mocked(ApiClient).mockReturnValue({ postJson: vi.fn() } as any);

        const result = await toolAgentScan(ctx, { code: 'x', language: 'javascript' });

        expect(vi.mocked(runVerifyLoop)).toHaveBeenCalledTimes(2);
        expect(result.agentFindings.find((f: any) => f.type === 'sql_injection').proven).toBe('PROVEN');
        expect(result.agentFindings.find((f: any) => f.type === 'xss').proven).toBe('PROVEN');
        expect(result.agentFindings.find((f: any) => f.type === 'info_disclosure').proven).toBe('SKIPPED');
    });
});
