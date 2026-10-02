/**
 * securecode.architecture — fast-return behavior (v0.10.4).
 *
 * The scout runs 2-5 minutes, but MCP clients time out at ~60s. The tool
 * now returns INSTANTLY ({status:'started'} / {status:'in-progress'}) and
 * runs the scout in a detached background task that writes its result to
 * the architecture cache. Clients poll by retrying the same call.
 *
 * Internal callers (agent-scan-batch) pass `_wait: true` to keep the old
 * blocking behavior, including spawn_failed errors thrown with .apiCode
 * for the v0.10.3 batch preflight taxonomy.
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

vi.mock('../src/attack/architectureScoutExecutor', () => ({
    executeScoutAction: vi.fn().mockResolvedValue('mock observation'),
}));

vi.mock('../src/project-map/mapBuilder', () => ({
    buildProjectMap: vi.fn(),
}));

vi.mock('../src/project-map/cache', () => ({
    readCache: vi.fn().mockReturnValue(null),
    writeCache: vi.fn(),
    cacheStatus: vi.fn(),
}));

import { toolMap, __scoutTrackerForTests, __clearScoutTrackerForTests } from '../src/tools/map';
import { ApiClient } from '../src/api/client';
import { buildProjectMap } from '../src/project-map/mapBuilder';
import { readCache } from '../src/project-map/cache';
import {
    getCachedArchitectureContext,
    readArchitectureCache,
    writeCachedArchitectureContext,
} from '../src/project-map/architectureContext';
import type { ProjectMap } from '../src/project-map/types';

const MAP_BUILT_AT = 12345;
const MAP_VERSION = 2;

const START_RESPONSE = {
    runId: 'run-1',
    budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.5 },
    scanCredits: 90,
    refundId: 'r1',
};

function makeArchPayload() {
    return {
        project: { type: 'Express API', frameworks: ['express'], runtimes: ['node'], packageManager: 'npm', languages: ['typescript'] },
        importantFiles: [
            { file: 'src/index.ts', role: 'entrypoint' as const, importance: 95, reasons: ['bootstrap'] },
        ],
        trustBoundaries: [],
        dataFlows: [],
        securityControls: [],
        architectureRisks: [],
        recommendedScanOrder: ['src/index.ts'],
        summary: 'Express API with JWT auth.',
        completeness: 'full' as const,
    };
}

function makeFinishResponse() {
    return {
        next: {
            type: 'finish',
            architecture: makeArchPayload(),
            summary: 'Survey done',
            selfCritique: 'Covered entrypoint + auth',
        },
        costUsd: 0.01,
        tokens: 100,
        degraded: false,
        costCapped: false,
        stepsRemaining: 23,
    };
}

function makeProjectMap(): ProjectMap {
    const endpoint = {
        id: 'src/routes/auth.ts:10:POST:/api/login',
        method: 'POST' as const,
        path: '/api/login',
        handlerName: 'login',
        sourceFile: 'src/routes/auth.ts',
        line: 10,
        middleware: [],
        params: [],
        authScheme: 'none' as const,
        dataLayer: 'prisma' as const,
        validatorLibrary: 'none' as const,
        callGraph: [],
        responseShape: 'json' as const,
        confidence: 1,
        runtimeConfirmed: false,
    };
    const fileExtraction = (endpoints: any[]) => ({
        file: 'src/routes/auth.ts',
        language: 'typescript' as const,
        endpoints,
        websockets: [],
        dynamicPatterns: [],
        imports: { prisma: 'prisma/client' },
        mtime: 1,
        hash: 'h',
    });
    return {
        files: {
            'src/index.ts': { ...fileExtraction([]), file: 'src/index.ts' },
            'src/routes/auth.ts': fileExtraction([endpoint]),
        },
        endpoints: [endpoint] as any,
        websockets: [],
        dynamicPatterns: [],
        version: MAP_VERSION,
        builtAt: MAP_BUILT_AT,
    };
}

// ── postJson helpers ─────────────────────────────────────────────────────────

let danglingRejects: Array<(reason?: any) => void> = [];

function setPostJson(impl: (...args: any[]) => Promise<any>) {
    (ApiClient as any).mockImplementation(() => ({ postJson: vi.fn(impl) }));
}

function mockScoutSuccess() {
    const fn = vi.fn()
        .mockResolvedValueOnce(START_RESPONSE)
        .mockResolvedValueOnce(makeFinishResponse());
    (ApiClient as any).mockImplementation(() => ({ postJson: fn }));
    return fn;
}

/** Start call never settles — keeps the background scout in 'running'. */
function mockScoutHangs() {
    let reject!: (reason?: any) => void;
    const promise = new Promise<any>((_resolve, rej) => { reject = rej; });
    danglingRejects.push(reject);
    setPostJson(() => promise);
}

function mockScoutStartRejected(apiCode: string, message: string, statusCode?: number) {
    const apiErr: any = new Error(message);
    apiErr.apiCode = apiCode;
    if (statusCode !== undefined) apiErr.statusCode = statusCode;
    setPostJson(() => Promise.reject(apiErr));
    return apiErr;
}

// ── Suite ───────────────────────────────────────────────────────────────────

describe('securecode.architecture — fast-return', () => {
    let workspaceRoot: string;
    let ctx: { workspaceRoot: string; apiUrl: string; apiToken: string };

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arch-fast-return-'));
        ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test' };
        vi.clearAllMocks();
        __clearScoutTrackerForTests();
        (readCache as any).mockReturnValue(makeProjectMap());
        setPostJson(async () => { throw new Error('postJson not configured for this test'); });
    });

    afterEach(async () => {
        const rejects = danglingRejects;
        danglingRejects = [];
        for (const reject of rejects) {
            try { reject(new Error('test teardown')); } catch { /* already settled */ }
        }
        // Let rejected background scouts settle before the workspace vanishes.
        await new Promise((r) => setTimeout(r, 0));
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch { /* best effort */ }
    });

    it('cold cache: returns {status:"started"} immediately without awaiting the scout', async () => {
        // The scout never finishes — if the call awaited it, this test would time out.
        mockScoutHangs();

        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });

        expect(result.status).toBe('started');
        expect(result.depth).toBe('standard');
        expect(result.etaMinutes).toBe(3);
        expect(result.hint).toContain('running in the background');
        expect(result.architecture).toBeUndefined();

        const entry = __scoutTrackerForTests().get(`${workspaceRoot}:standard`);
        expect(entry).toBeDefined();
        expect(entry!.state).toBe('running');

        // The map was served from cache — no rebuild in the foreground.
        expect(buildProjectMap).not.toHaveBeenCalled();

        // Depth partitions the tracker: another depth starts independently.
        mockScoutHangs();
        const deep: any = await toolMap(ctx, { action: 'architecture', depth: 'deep' });
        expect(deep.status).toBe('started');
        expect(deep.etaMinutes).toBe(5);
        const quick: any = await toolMap(ctx, { action: 'architecture', depth: 'quick' });
        expect(quick.status).toBe('started');
        expect(quick.etaMinutes).toBe(1);
    });

    it('background completion writes the cache; the next call serves {cached:true}', async () => {
        mockScoutSuccess();

        const first: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(first.status).toBe('started');

        await vi.waitFor(() => {
            const cached = getCachedArchitectureContext(workspaceRoot, 'standard', MAP_BUILT_AT, MAP_VERSION);
            expect(cached).not.toBeNull();
        });

        // The tracker entry clears on success so the next call serves the cache.
        expect(__scoutTrackerForTests().has(`${workspaceRoot}:standard`)).toBe(false);

        const second: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(second.cached).toBe(true);
        expect(second.architecture).toBeDefined();
        expect(second.architecture.project.type).toBe('Express API');
        expect(second.architecture.depth).toBe('standard');
        expect(second.depth).toBe('standard');
    });

    it('fresh running tracker entry: returns {status:"in-progress"}', async () => {
        mockScoutHangs();

        const first: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(first.status).toBe('started');

        const second: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(second.status).toBe('in-progress');
        expect(second.depth).toBe('standard');
        expect(second.etaMinutes).toBe(2);
        expect(second.hint).toContain('running in the background');

        // A different depth has its own tracker entry and is not reported in-progress.
        mockScoutHangs();
        const quick: any = await toolMap(ctx, { action: 'architecture', depth: 'quick' });
        expect(quick.status).toBe('started');
    });

    it('fresh blocked tracker entry (run pool busy): {status:"in-progress"} with run-pool hint', async () => {
        mockScoutStartRejected(
            'AGENT_SCAN_ALREADY_RUNNING',
            'Agent scan already running — a previous run is still executing.',
            409,
        );

        const first: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(first.status).toBe('started');

        await vi.waitFor(() => {
            const entry = __scoutTrackerForTests().get(`${workspaceRoot}:standard`);
            expect(entry?.state).toBe('blocked');
        });

        const second: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(second.status).toBe('in-progress');
        expect(second.etaMinutes).toBe(2);
        expect(second.hint).toContain('run pool');
        expect(second.hint).toContain('AGENT_SCAN_ALREADY_RUNNING');
    });

    it('stale running entry (older than 10 min): restarts with {status:"started"}', async () => {
        const key = `${workspaceRoot}:standard`;
        __scoutTrackerForTests().set(key, {
            state: 'running',
            startedAt: Date.now() - 11 * 60 * 1000,
        });
        mockScoutHangs();

        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });

        expect(result.status).toBe('started');
        const entry = __scoutTrackerForTests().get(key);
        expect(entry!.state).toBe('running');
        expect(entry!.startedAt).toBeGreaterThan(Date.now() - 10_000); // fresh restart
    });

    it('_wait:true keeps the old synchronous behavior (full result, no "started")', async () => {
        mockScoutSuccess();

        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard', _wait: true });

        expect(result.status).toBe('completed');
        expect(result.status).not.toBe('started');
        expect(result.architecture).toBeDefined();
        expect(result.architecture.project.type).toBe('Express API');
        expect(result.cached).toBe(false);
        expect(result.stepsUsed).toBe(1);

        // The synchronous path wrote the cache before returning.
        expect(getCachedArchitectureContext(workspaceRoot, 'standard', MAP_BUILT_AT, MAP_VERSION)).not.toBeNull();
    });

    it('_wait:true spawn_failed still throws with .apiCode (batch preflight taxonomy)', async () => {
        mockScoutStartRejected(
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

    it('noCache: clears the cache and starts a fresh background scout', async () => {
        // Seed a valid cached context (matching builtAt/version) that a normal
        // call would serve — proving _noCache bypasses it.
        const seeded: any = {
            ...makeArchPayload(),
            version: 1,
            depth: 'standard',
            derivedAt: Date.now(),
            projectMapBuiltAt: MAP_BUILT_AT,
            projectMapVersion: MAP_VERSION,
        };
        writeCachedArchitectureContext(workspaceRoot, seeded);
        expect(getCachedArchitectureContext(workspaceRoot, 'standard', MAP_BUILT_AT, MAP_VERSION)).not.toBeNull();

        mockScoutHangs();

        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard', _noCache: true });

        expect(result.status).toBe('started');
        expect(result.architecture).toBeUndefined();
        expect(readArchitectureCache(workspaceRoot)).toBeNull(); // cleared, not served

        const entry = __scoutTrackerForTests().get(`${workspaceRoot}:standard`);
        expect(entry).toBeDefined();
        expect(entry!.state).toBe('running');
    });
});
