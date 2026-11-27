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
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'test auto-approve', requestId: 'test-approval', duration: 0 }),
        requestSessionApproval: vi.fn().mockResolvedValue({
            granted: true, state: 'granted', reason: 'ok', detail: '', requestId: 'sess-1',
            runId: 'r', maxTests: 100, remaining: 100, expiresAt: Date.now() + 600_000,
        }),
    })),
    consumeSessionApproval: vi.fn().mockReturnValue(true),
    revokeSessionApproval: vi.fn().mockReturnValue(true),
}));

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { toolAgentScan } from '../src/tools/agentScan';

const FINDING = {
    type: 'command_injection',
    line: 10,
    lineEnd: undefined,
    evidence: 'exec(input)',
    why: 'user input reaches exec',
    severity: 'high',
    confidence: 0.85,
    file: 'src/foo.ts',
    snippet: 'exec(userInput)',
    category: 'server-side',
};

describe('toolAgentScan — sandbox-unavailable (no local Docker/Deno)', () => {
    beforeEach(() => {
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
    });

    it('returns INCONCLUSIVE with sandbox-unavailable when runVerifyLoop returns sandbox-unavailable', async () => {
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE',
            reason: 'No verification sandbox backend was detected.',
            roundsUsed: 0,
            testScript: '',
            testOutput: '',
            subVerdict: 'sandbox-unavailable',
        });

        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [FINDING],
            transcript: [],
            stepsTaken: 1,
            costUsd: 0.05,
        } as any);

        const mockPostJson = vi.fn();
        vi.mocked(ApiClient).mockReturnValue({
            postJson: mockPostJson,
        } as any);

        const ctx: any = {
            workspaceRoot: '/tmp/workspace',
            apiUrl: 'https://api.usesecurecode.tech',
            apiToken: 'test-token',
        };

        const result = await toolAgentScan(ctx, {
            code: 'const x = 1;',
            language: 'javascript',
        });

        expect(mockPostJson).not.toHaveBeenCalledWith('/sandbox/prove', expect.any(Object));

        const provenFinding = result.agentFindings[0];
        expect(provenFinding.proven).toBe('INCONCLUSIVE');
        expect(provenFinding.verifySubVerdict).toBe('sandbox-unavailable');
    });
});
