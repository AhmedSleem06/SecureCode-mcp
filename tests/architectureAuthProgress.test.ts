/**
 * securecode.architecture — auth messaging + live progress (v0.10.16).
 *
 * A 401 at /agent/architecture/start used to be reported as pool contention
 * ("wait ~60-120 seconds and retry") — actively misleading. Spawn failures
 * now land in a dedicated 'failed' tracker state with a plain-language
 * error + concrete remedy, the first call pre-flights auth so a doomed
 * scout never claims "started", and in-progress polls carry live step
 * counts so any MCP client can show progress without progressToken support.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({
            postJson: vi.fn(),
            getJson: vi.fn().mockResolvedValue({}),
        })),
    };
});

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
import { ApiClient, ApiClientError } from '../src/api/client';
import { readCache } from '../src/project-map/cache';
import type { ProjectMap } from '../src/project-map/types';

const MAP_BUILT_AT = 12345;
const MAP_VERSION = 2;

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

const START_RESPONSE = {
    runId: 'run-1',
    budget: { stepsRemaining: 25, costSpentUsd: 0, costCapUsd: 1.5 },
    scanCredits: 90,
    refundId: 'r1',
};

let danglingRejects: Array<(reason?: any) => void> = [];

function setPostJson(impl: (...args: any[]) => Promise<any>) {
    (ApiClient as any).mockImplementation(() => ({ postJson: vi.fn(impl), getJson: vi.fn().mockResolvedValue({}) }));
}

function setGetJson(impl: (...args: any[]) => Promise<any>) {
    (ApiClient as any).mockImplementation(() => ({ postJson: vi.fn(), getJson: vi.fn(impl) }));
}

function mockStartHangs() {
    let reject!: (reason?: any) => void;
    const promise = new Promise<any>((_resolve, rej) => { reject = rej; });
    danglingRejects.push(reject);
    setPostJson(() => promise);
}

function authErr(): ApiClientError {
    return new ApiClientError(401, undefined, 'Unauthorized', undefined);
}

describe('describeApiError — plain-language API errors', () => {
    it('401 → not authenticated + login remedy, not retryable', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const d = describeApiError(new ApiClientError(401, undefined, 'Unauthorized', undefined));
        expect(d.error).toContain('Not authenticated');
        expect(d.remedy).toContain('securecode-mcp login');
        expect(d.retryable).toBe(false);
    });

    it('402 → insufficient credits with amounts + top-up remedy', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const err = new ApiClientError(402, 'INSUFFICIENT_CREDITS', 'Insufficient credits', undefined, {
            creditType: 'scan', requested: 10, balance: 4, required: 10, available: 4,
        });
        const d = describeApiError(err);
        expect(d.error).toContain('Insufficient credits');
        expect(d.error).toContain('10');
        expect(d.error).toContain('4');
        expect(d.remedy).toContain('usesecurecode.tech');
        expect(d.retryable).toBe(false);
    });

    it('429 → daily limit, retryable', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const d = describeApiError(new ApiClientError(429, 'AGENT_SCAN_DAILY_LIMIT', 'Daily limit', undefined));
        expect(d.error).toContain('limit');
        expect(d.retryable).toBe(true);
    });

    it('409 → wait hint, retryable', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const d = describeApiError(new ApiClientError(409, 'AGENT_SCAN_ALREADY_RUNNING', 'already running', undefined));
        expect(d.remedy).toContain('60-120 seconds');
        expect(d.retryable).toBe(true);
    });

    it('status 0 (network) → could not reach API + network remedy', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const d = describeApiError(new ApiClientError(0, undefined, 'Network error: timeout', undefined));
        expect(d.error).toContain('Could not reach the API');
        expect(d.remedy).toContain('network');
        expect(d.retryable).toBe(true);
    });

    it('unknown errors keep the raw message, retryable, no remedy', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const d = describeApiError(new Error('something odd'));
        expect(d.error).toBe('something odd');
        expect(d.remedy).toBeUndefined();
        expect(d.retryable).toBe(true);
    });

    it('accepts spawn-failure descriptors ({statusCode, error})', async () => {
        const { describeApiError } = await vi.importActual('../src/api/client') as any;
        const d = describeApiError({ statusCode: 401, error: 'Unauthorized' });
        expect(d.error).toContain('Not authenticated');
        expect(d.remedy).toContain('securecode-mcp login');
    });
});

describe('securecode.architecture — auth pre-flight + failed state + progress', () => {
    let workspaceRoot: string;
    let ctx: { workspaceRoot: string; apiUrl: string; apiToken: string };

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arch-auth-'));
        ctx = { workspaceRoot, apiUrl: 'http://localhost:3000', apiToken: 'test-token' };
        vi.clearAllMocks();
        __clearScoutTrackerForTests();
        (readCache as any).mockReturnValue(makeProjectMap());
        (ApiClient as any).mockImplementation(() => ({
            postJson: vi.fn(),
            getJson: vi.fn().mockResolvedValue({}),
        }));
    });

    afterEach(async () => {
        const rejects = danglingRejects;
        danglingRejects = [];
        for (const reject of rejects) {
            try { reject(new Error('test teardown')); } catch { /* already settled */ }
        }
        await new Promise((r) => setTimeout(r, 0));
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch { /* best effort */ }
    });

    it('no token: fails fast with the login remedy, no HTTP, no tracker entry', async () => {
        ctx.apiToken = '';
        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });

        expect(result.status).toBe('failed');
        expect(result.error).toContain('Not authenticated');
        expect(result.remedy).toContain('securecode-mcp login');
        expect(result.retryable).toBe(false);
        expect(ApiClient).not.toHaveBeenCalled();
        expect(__scoutTrackerForTests().size).toBe(0);
    });

    it('expired token (pre-flight 401): fails fast, scout never starts', async () => {
        setGetJson(() => Promise.reject(authErr()));

        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });

        expect(result.status).toBe('failed');
        expect(result.error).toContain('Not authenticated');
        expect(result.remedy).toContain('securecode-mcp login');
        expect(result.retryable).toBe(false);
        expect(__scoutTrackerForTests().size).toBe(0);
    });

    it('background start 401 → tracker failed; next poll reports the failure + remedy and restarts', async () => {
        // First call: pre-flight passes, scout "starts", background start rejects 401.
        setPostJson(() => Promise.reject(authErr()));
        const first: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(first.status).toBe('started');

        await vi.waitFor(() => {
            const entry = __scoutTrackerForTests().get(`${workspaceRoot}:standard`);
            expect(entry?.state).toBe('failed');
            expect(entry?.remedy).toContain('securecode-mcp login');
        });

        // Second call: auth fixed (getJson now resolves), the start hangs so the
        // restarted scout stays deterministically 'running'.
        mockStartHangs();
        const second: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });

        expect(second.status).toBe('failed');
        expect(second.error).toContain('Not authenticated');
        expect(second.remedy).toContain('securecode-mcp login');
        expect(second.hint).toContain('fresh attempt');

        const entry = __scoutTrackerForTests().get(`${workspaceRoot}:standard`);
        expect(entry?.state).toBe('running');
    });

    it('background start 401 persisting: poll keeps failing honestly, never says "wait"', async () => {
        setPostJson(() => Promise.reject(authErr()));
        const first: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(first.status).toBe('started');

        await vi.waitFor(() => {
            expect(__scoutTrackerForTests().get(`${workspaceRoot}:standard`)?.state).toBe('failed');
        });

        const second: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(second.status).toBe('failed');
        expect(second.remedy).toContain('securecode-mcp login');
        expect(second.error).not.toContain('run pool');
    });

    it('in-progress polls carry live progress from the tracker', async () => {
        const key = `${workspaceRoot}:standard`;
        __scoutTrackerForTests().set(key, {
            state: 'running',
            startedAt: Date.now() - 30_000,
            stepsDone: 4,
            stepsMax: 12,
            lastMessage: 'Reading src/index.ts (step 4)',
            updatedAt: Date.now(),
        });

        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });

        expect(result.status).toBe('in-progress');
        expect(result.progress).toEqual({ done: 4, total: 12 });
        expect(result.lastMessage).toBe('Reading src/index.ts (step 4)');
        expect(result.elapsedMs).toBeGreaterThanOrEqual(30_000);
        expect(result.hint).toContain('live progress');
    });

    it('_wait:true start 401 throws the auth message with the login remedy (batch taxonomy kept)', async () => {
        setPostJson(() => Promise.reject(authErr()));

        let thrown: any;
        try {
            await toolMap(ctx, { action: 'architecture', depth: 'standard', _wait: true });
        } catch (e) {
            thrown = e;
        }

        expect(thrown).toBeDefined();
        expect(thrown.message).toContain('securecode-mcp login');
        expect(thrown.statusCode).toBe(401);
    });

    it('pool contention (409) still reports blocked with the wait hint', async () => {
        const conflict = new ApiClientError(
            409, 'AGENT_SCAN_ALREADY_RUNNING', 'Agent scan already running — a previous run is still executing.', undefined,
        );
        setPostJson(() => Promise.reject(conflict));

        const first: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(first.status).toBe('started');

        await vi.waitFor(() => {
            expect(__scoutTrackerForTests().get(`${workspaceRoot}:standard`)?.state).toBe('blocked');
        });

        const second: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(second.status).toBe('in-progress');
        expect(second.hint).toContain('run pool');
        expect(second.hint).toContain('AGENT_SCAN_ALREADY_RUNNING');
    });

    it('started responses tell the client to poll in ~60-90 seconds', async () => {
        mockStartHangs();
        const result: any = await toolMap(ctx, { action: 'architecture', depth: 'standard' });
        expect(result.status).toBe('started');
        expect(result.hint).toContain('~60-90 seconds');
    });
});
