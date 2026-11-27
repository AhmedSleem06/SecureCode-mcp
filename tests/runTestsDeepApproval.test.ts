import { describe, it, expect, vi, beforeEach } from 'vitest';

const brokerMocks = vi.hoisted(() => ({
    consumeSessionApproval: vi.fn(),
    getSessionApproval: vi.fn(),
}));

vi.mock('../src/approval/broker', () => ({
    consumeSessionApproval: brokerMocks.consumeSessionApproval,
    getSessionApproval: brokerMocks.getSessionApproval,
}));

const runTestsMock = vi.hoisted(() => vi.fn());

vi.mock('../src/utils/testRunner', async (importOriginal) => {
    const real: any = await importOriginal();
    return {
        ...real,
        runTests: runTestsMock,
    };
});

import { executeAction, type ExecuteActionOptions } from '../src/attack/agentScanExecutor';
import type { ServerContext } from '../src/mcp/types';

const ctx: ServerContext = { apiUrl: 'http://test', apiToken: 'tok', workspaceRoot: '/tmp/ws' };
const target = { filePath: 'src/app.js', language: 'javascript', fileContent: 'x', endpointContext: [] };

beforeEach(() => {
    for (const m of Object.values(brokerMocks)) m.mockReset();
    runTestsMock.mockReset();
    runTestsMock.mockResolvedValue({
        approved: true,
        mode: 'generated',
        status: 'passed',
        exitCode: 0,
        output: 'PASS: ok',
        durationMs: 100,
    });
});

describe('run_tests executor deep-scan approval fallback', () => {
    const runTestsAction = {
        type: 'run_tests' as const,
        mode: 'generated',
        script: 'console.log("PASS: ok")',
        runner: 'node',
    };

    it('falls back to per-run approval when deep-scan approval is still pending (state none)', async () => {
        brokerMocks.getSessionApproval.mockReturnValue({ granted: false, state: 'none', reason: 'no approval' });

        const opts: ExecuteActionOptions = { deepScanRunId: 'deep-pending' };
        const result = await executeAction(runTestsAction as any, ctx, 'run-1', {} as any, target as any, opts);

        expect(brokerMocks.getSessionApproval).toHaveBeenCalledWith('deep-pending');
        expect(brokerMocks.consumeSessionApproval).not.toHaveBeenCalled();
        expect(runTestsMock).toHaveBeenCalledTimes(1);
        const callArgs = runTestsMock.mock.calls[0];
        expect(callArgs[2]?.skipApproval).toBeUndefined();
        expect(result).toContain('passed');
    });

    it('skips per-run prompt when deep-scan approval is granted', async () => {
        brokerMocks.getSessionApproval.mockReturnValue({ granted: true, state: 'granted', reason: 'User approved' });
        brokerMocks.consumeSessionApproval.mockReturnValue(true);

        const opts: ExecuteActionOptions = { deepScanRunId: 'deep-granted' };
        const result = await executeAction(runTestsAction as any, ctx, 'run-1', {} as any, target as any, opts);

        expect(brokerMocks.getSessionApproval).toHaveBeenCalledWith('deep-granted');
        expect(brokerMocks.consumeSessionApproval).toHaveBeenCalledWith('deep-granted');
        expect(runTestsMock).toHaveBeenCalledTimes(1);
        const callArgs = runTestsMock.mock.calls[0];
        expect(callArgs[2]?.skipApproval).toBe(true);
    });

    it('returns exhausted message when deep-scan approval units ran out', async () => {
        brokerMocks.getSessionApproval.mockReturnValue({ granted: false, state: 'exhausted', reason: 'all used' });
        brokerMocks.consumeSessionApproval.mockReturnValue(false);

        const opts: ExecuteActionOptions = { deepScanRunId: 'deep-exhausted' };
        const result = await executeAction(runTestsAction as any, ctx, 'run-1', {} as any, target as any, opts);

        expect(result).toContain('exhausted or not granted');
        expect(runTestsMock).not.toHaveBeenCalled();
    });

    it('returns exhausted message when deep-scan approval was denied', async () => {
        brokerMocks.getSessionApproval.mockReturnValue({ granted: false, state: 'denied', reason: 'denied' });
        brokerMocks.consumeSessionApproval.mockReturnValue(false);

        const opts: ExecuteActionOptions = { deepScanRunId: 'deep-denied' };
        const result = await executeAction(runTestsAction as any, ctx, 'run-1', {} as any, target as any, opts);

        expect(result).toContain('exhausted or not granted');
        expect(runTestsMock).not.toHaveBeenCalled();
    });

    it('without deepScanRunId, uses regular per-run approval', async () => {
        const result = await executeAction(runTestsAction as any, ctx, 'run-1', {} as any, target as any, {});

        expect(brokerMocks.getSessionApproval).not.toHaveBeenCalled();
        expect(brokerMocks.consumeSessionApproval).not.toHaveBeenCalled();
        expect(runTestsMock).toHaveBeenCalledTimes(1);
        const callArgs = runTestsMock.mock.calls[0];
        expect(callArgs[2]?.skipApproval).toBeUndefined();
    });
});
