import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({
        postJson: vi.fn(),
    })),
}));

vi.mock('../src/attack/architectureScoutExecutor', () => ({
    executeScoutAction: vi.fn(),
}));

import { runArchitectureScout } from '../src/attack/architectureScoutLoop';
import { ApiClient } from '../src/api/client';
import { executeScoutAction } from '../src/attack/architectureScoutExecutor';
import { ARCHITECTURE_CONTEXT_VERSION } from '../src/project-map/architectureContext';
import type { ArchitectureInventory } from '../src/attack/architectureScoutProtocol';

const ctx = { workspaceRoot: '/tmp', apiUrl: 'http://localhost:3000', apiToken: 'test' };

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

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) {
        mockFn.mockResolvedValueOnce(resp);
    }
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

describe('runArchitectureScout', () => {
    beforeEach(() => vi.clearAllMocks());

    it('terminates on finish with a stamped ArchitectureContext', async () => {
        const archPayload = {
            project: { type: 'Express API', frameworks: ['express'], runtimes: ['node'], packageManager: 'npm', languages: ['typescript'] },
            importantFiles: [
                { file: 'src/index.ts', role: 'entrypoint', importance: 95, reasons: ['bootstrap'] },
                { file: 'src/lib/auth.ts', role: 'authentication', importance: 90, reasons: ['JWT'] },
            ],
            trustBoundaries: [],
            dataFlows: [],
            securityControls: [],
            architectureRisks: [],
            recommendedScanOrder: ['src/lib/auth.ts', 'src/index.ts'],
            summary: 'Express API with JWT auth.',
            completeness: 'full',
        };

        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.50 }, scanCredits: 90, refundId: 'r1' },
            { next: { type: 'read_file', path: 'package.json', rationale: 'read manifest' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 24 },
            { next: { type: 'finish', architecture: archPayload, summary: 'Survey done', selfCritique: 'Covered entrypoint + auth' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 23 },
        ]);
        (executeScoutAction as any).mockResolvedValue('File: package.json (20 lines)...');

        const result = await runArchitectureScout(ctx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        }, {
            projectMapBuiltAt: 1000,
            projectMapVersion: 2,
        });

        expect(result.status).toBe('completed');
        expect(result.architecture).not.toBeNull();
        expect(result.architecture!.project.type).toBe('Express API');
        expect(result.architecture!.importantFiles).toHaveLength(2);
        // Verify cache metadata was stamped by the loop (not by the LLM)
        expect(result.architecture!.version).toBe(ARCHITECTURE_CONTEXT_VERSION);
        expect(result.architecture!.depth).toBe('standard');
        expect(result.architecture!.projectMapBuiltAt).toBe(1000);
        expect(result.architecture!.projectMapVersion).toBe(2);
        expect(result.architecture!.derivedAt).toBeGreaterThan(0);
        expect(result.stepsUsed).toBe(2);
    });

    it('caps importantFiles at maxImportantFiles', async () => {
        // LLM returns 3 files but maxImportantFiles is 2.
        const archPayload = {
            project: { type: 'test', frameworks: [], runtimes: [], packageManager: null, languages: [] },
            importantFiles: [
                { file: 'a.ts', role: 'entrypoint', importance: 50, reasons: ['x'] },
                { file: 'b.ts', role: 'authentication', importance: 90, reasons: ['x'] },
                { file: 'c.ts', role: 'data_access', importance: 70, reasons: ['x'] },
            ],
            trustBoundaries: [],
            dataFlows: [],
            securityControls: [],
            architectureRisks: [],
            recommendedScanOrder: [],
            summary: 'test',
            completeness: 'partial',
        };

        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 12, costSpentUsd: 0, costCapUsd: 0.50 }, scanCredits: 95, refundId: 'r1' },
            { next: { type: 'finish', architecture: archPayload, summary: 'done', selfCritique: 'done' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 11 },
        ]);

        const result = await runArchitectureScout(ctx, {
            depth: 'quick',
            inventory: makeInventory(),
            maxImportantFiles: 2,
        }, {
            projectMapBuiltAt: 1000,
            projectMapVersion: 2,
        });

        expect(result.status).toBe('completed');
        expect(result.architecture!.importantFiles).toHaveLength(2);
        // Should keep the highest-importance files
        expect(result.architecture!.importantFiles.map(f => f.file)).toEqual(['b.ts', 'c.ts']);
    });

    it('terminates on null next (capped)', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.50 }, scanCredits: 90, refundId: 'r1' },
            { next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, stepsRemaining: 24 },
        ]);

        const result = await runArchitectureScout(ctx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('capped');
        expect(result.architecture).toBeNull();
    });

    it('returns spawn_failed on API error', async () => {
        const mockFn = vi.fn().mockRejectedValue(new Error('Connection refused'));
        (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));

        const result = await runArchitectureScout(ctx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.error).toContain('Connection refused');
    });

    it('returns spawn_failed on malformed start response', async () => {
        mockPostJson([
            { /* missing runId */ budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.50 }, refundId: 'r1' },
        ]);

        const result = await runArchitectureScout(ctx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.error).toContain('invalid start response');
    });

    it('returns spawn_failed on AGENT_RUN_NOT_FOUND mid-scout (API restarted)', async () => {
        const apiErr: any = new Error('Invalid or expired agent run');
        apiErr.apiCode = 'AGENT_RUN_NOT_FOUND';

        const postJson = vi.fn()
            .mockResolvedValueOnce({ runId: 'run-1', budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.50 }, scanCredits: 90, refundId: 'r1' })
            .mockRejectedValueOnce(apiErr);
        (ApiClient as any).mockImplementation(() => ({ postJson }));

        const result = await runArchitectureScout(ctx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        expect(result.status).toBe('spawn_failed');
        expect(result.error).toContain('restarted');
    });

    it('dedups repeated read_file on the same range', async () => {
        mockPostJson([
            { runId: 'run-1', budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.50 }, scanCredits: 90, refundId: 'r1' },
            { next: { type: 'read_file', path: 'package.json', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 24 },
            { next: { type: 'read_file', path: 'package.json', rationale: 'r' }, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 23 },
            {
                next: {
                    type: 'finish',
                    architecture: { project: { type: 't', frameworks: [], runtimes: [], packageManager: null, languages: [] }, importantFiles: [], trustBoundaries: [], dataFlows: [], securityControls: [], architectureRisks: [], recommendedScanOrder: [], summary: 't', completeness: 'partial' },
                    summary: 'done', selfCritique: 'done',
                },
                costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 22,
            },
        ]);
        (executeScoutAction as any).mockResolvedValue('content');

        const result = await runArchitectureScout(ctx, {
            depth: 'standard',
            inventory: makeInventory(),
            maxImportantFiles: 50,
        });

        // executeScoutAction should be called only once (first read_file);
        // the second read_file is deduped (blocked).
        expect(executeScoutAction).toHaveBeenCalledTimes(1);
        expect(result.status).toBe('completed');
    });
});
