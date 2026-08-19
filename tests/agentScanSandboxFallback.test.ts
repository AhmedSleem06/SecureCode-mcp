import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock runVerifyLoop to return sandbox-unavailable — simulates a user
// without Docker/Deno. Then verify that toolAgentScan falls back to
// the API-side /sandbox/prove endpoint.

vi.mock('../src/attack/verifyLoop', () => ({
    runVerifyLoop: vi.fn(),
}));

vi.mock('../src/attack/agentScanLoop', () => ({
    runAgentScan: vi.fn(),
}));

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
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

describe('toolAgentScan — API sandbox fallback (no local Docker/Deno)', () => {
    beforeEach(() => {
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
    });

    it('falls back to /sandbox/prove when runVerifyLoop returns sandbox-unavailable', async () => {
        // runVerifyLoop returns sandbox-unavailable (no Docker/Deno on the machine)
        vi.mocked(runVerifyLoop).mockResolvedValue({
            verdict: 'INCONCLUSIVE',
            reason: 'No verification sandbox backend was detected.',
            roundsUsed: 0,
            testScript: '',
            testOutput: '',
            subVerdict: 'sandbox-unavailable',
        });

        // runAgentScan returns one finding to verify
        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [FINDING],
            transcript: [],
            stepsTaken: 1,
            costUsd: 0.05,
        } as any);

        // Mock the ApiClient.postJson to return a sandbox prove response
        const mockPostJson = vi.fn().mockResolvedValue({
            proven: 'PROVEN',
            canReproduce: true,
            rationale: 'exploit succeeded via API sandbox',
            degraded: false,
        });

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

        // The API sandbox fallback should have been called
        expect(mockPostJson).toHaveBeenCalledWith(
            '/sandbox/prove',
            expect.objectContaining({
                vulnerabilityType: 'command_injection',
                language: 'javascript',
            }),
        );

        // The finding should be PROVEN (from the API sandbox), not INCONCLUSIVE
        const provenFinding = result.agentFindings[0];
        expect(provenFinding.proven).toBe('PROVEN');
        expect(provenFinding.provenReason).toContain('exploit succeeded');
    });

    it('returns INCONCLUSIVE when both local sandbox and API sandbox fail', async () => {
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

        // API sandbox also fails
        const mockPostJson = vi.fn().mockRejectedValue(new Error('API sandbox down'));
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

        expect(mockPostJson).toHaveBeenCalledWith('/sandbox/prove', expect.any(Object));

        const provenFinding = result.agentFindings[0];
        expect(provenFinding.proven).toBe('INCONCLUSIVE');
    });
});
