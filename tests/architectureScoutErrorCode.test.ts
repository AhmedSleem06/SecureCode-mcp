/**
 * Architecture scout — API error-code propagation (v0.10.3).
 *
 * Production showed the scout's /agent/architecture/start being rejected
 * with 409 AGENT_SCAN_ALREADY_RUNNING or 429 AGENT_SCAN_DAILY_LIMIT, and
 * those codes were previously lost when the error was stringified into
 * spawn_failed `error`. These tests pin the full propagation chain:
 *
 *   ApiClient rejects (apiCode on the error)
 *     → runArchitectureScout returns spawn_failed + apiCode preserved
 *     → runArchitectureAction (map.ts) rethrows with .apiCode + .statusCode
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

import { runArchitectureScout } from '../src/attack/architectureScoutLoop';
import { toolMap } from '../src/tools/map';
import { ApiClient } from '../src/api/client';
import type { ArchitectureInventory } from '../src/attack/architectureScoutProtocol';

const scoutCtx = { workspaceRoot: '/tmp', apiUrl: 'http://localhost:3000', apiToken: 'test' };

function makeInventory(): ArchitectureInventory {
    return {
        files: [
            { file: 'src/index.ts', language: 'typescript', lines: 50, endpointCount: 0, importCount: 5 },
            { file: 'src/routes/auth.ts', language: 'typescript', lines: 100, endpointCount: 3, importCount: 8 },
        ],
        endpoints: [
            { method: 'POST', path: '/api/login', handler: 'login', sourceFile: 'src/routes/auth.ts', line: 10, authScheme: 'none', dataLayer: 'prisma' },
        ],
        runtimes: ['node'],
        packageManager: 'npm',
        languages: ['typescript'],
    };
}

function mockStartRejection(apiCode: string, message: string, statusCode?: number) {
    const apiErr: any = new Error(message);
    apiErr.apiCode = apiCode;
    if (statusCode !== undefined) apiErr.statusCode = statusCode;
    const postJson = vi.fn().mockRejectedValue(apiErr);
    (ApiClient as any).mockImplementation(() => ({ postJson }));
    return apiErr;
}

describe('runArchitectureScout — apiCode preservation on start failure', () => {
    beforeEach(() => vi.clearAllMocks());

    it('preserves AGENT_SCAN_ALREADY_RUNNING on spawn_failed', async () => {
        mockStartRejection(
            'AGENT_SCAN_ALREADY_RUNNING',
            'Agent scan already running — a previous run is still executing. Wait ~60-120 seconds and retry.',
            409,
        );

        const result = await runArchitectureScout(scoutCtx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.architecture).toBeNull();
        expect(result.stepsUsed).toBe(0);
        expect(result.costSpentUsd).toBe(0);
        expect(result.apiCode).toBe('AGENT_SCAN_ALREADY_RUNNING');
        expect(result.error).toContain('already running');
    });

    it('preserves AGENT_SCAN_DAILY_LIMIT on spawn_failed', async () => {
        mockStartRejection(
            'AGENT_SCAN_DAILY_LIMIT',
            'Agent scan daily limit reached (10/10 runs today)',
            429,
        );

        const result = await runArchitectureScout(scoutCtx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.apiCode).toBe('AGENT_SCAN_DAILY_LIMIT');
        expect(result.error).toContain('daily limit reached (10/10 runs today)');
    });

    it('falls back to err.code when apiCode is absent', async () => {
        const apiErr: any = new Error('Budget exhausted upstream');
        apiErr.code = 'AGENT_SCAN_DAILY_LIMIT';
        const postJson = vi.fn().mockRejectedValue(apiErr);
        (ApiClient as any).mockImplementation(() => ({ postJson }));

        const result = await runArchitectureScout(scoutCtx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.apiCode).toBe('AGENT_SCAN_DAILY_LIMIT');
    });

    it('leaves apiCode empty for a plain network error', async () => {
        const postJson = vi.fn().mockRejectedValue(new Error('Connection refused'));
        (ApiClient as any).mockImplementation(() => ({ postJson }));

        const result = await runArchitectureScout(scoutCtx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.apiCode).toBe('');
        expect(result.error).toContain('Connection refused');
    });
});

describe('runArchitectureAction (toolMap action=architecture) — error code propagation', () => {
    let workspaceRoot: string;
    let ctx: { workspaceRoot: string; apiUrl: string; apiToken: string };

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arch-error-code-'));
        ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test' };
        vi.clearAllMocks();
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    it('throws with apiCode AGENT_SCAN_ALREADY_RUNNING and statusCode 409', async () => {
        mockStartRejection(
            'AGENT_SCAN_ALREADY_RUNNING',
            'Agent scan already running — wait ~60-120 seconds and retry.',
            409,
        );

        let thrown: any;
        try {
            await toolMap(ctx, { action: 'architecture', depth: 'standard', _wait: true });
        } catch (e) {
            thrown = e;
        }

        expect(thrown).toBeDefined();
        expect(thrown.apiCode).toBe('AGENT_SCAN_ALREADY_RUNNING');
        expect(thrown.statusCode).toBe(409);
        expect(thrown.message).toContain('already running');
    });

    it('throws with apiCode AGENT_SCAN_DAILY_LIMIT and statusCode 429', async () => {
        mockStartRejection(
            'AGENT_SCAN_DAILY_LIMIT',
            'Agent scan daily limit reached (10/10 runs today)',
            429,
        );

        let thrown: any;
        try {
            await toolMap(ctx, { action: 'architecture', depth: 'standard', _wait: true });
        } catch (e) {
            thrown = e;
        }

        expect(thrown).toBeDefined();
        expect(thrown.apiCode).toBe('AGENT_SCAN_DAILY_LIMIT');
        expect(thrown.statusCode).toBe(429);
        expect(thrown.message).toContain('daily limit reached (10/10 runs today)');
    });

    it('throws without statusCode for an unknown apiCode', async () => {
        mockStartRejection('AGENT_INTERNAL_ERROR', 'API internal error');

        let thrown: any;
        try {
            await toolMap(ctx, { action: 'architecture', depth: 'standard', _wait: true });
        } catch (e) {
            thrown = e;
        }

        expect(thrown).toBeDefined();
        expect(thrown.apiCode).toBe('AGENT_INTERNAL_ERROR');
        expect(thrown.statusCode).toBeUndefined();
    });
});
