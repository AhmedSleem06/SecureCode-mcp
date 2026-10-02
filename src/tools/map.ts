import * as fs from 'fs';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { readCache, writeCache, cacheStatus } from '../project-map/cache';
import { buildProjectMap } from '../project-map/mapBuilder';
import type { ProjectMap } from '../project-map/types';
import {
    getCachedArchitectureContext,
    writeCachedArchitectureContext,
    clearArchitectureCache,
    type ArchitectureContext,
    type ArchitectureDepth,
} from '../project-map/architectureContext';
import { runArchitectureScout } from '../attack/architectureScoutLoop';
import { scoutDefaultsForDepth, type ArchitectureInventory } from '../attack/architectureScoutProtocol';

function summarizeFiles(map: ProjectMap) {
    const files = Object.values(map.files);
    const byLanguage: Record<string, number> = {};
    for (const f of files) {
        byLanguage[f.language] = (byLanguage[f.language] || 0) + 1;
    }
    return {
        totalFiles: files.length,
        byLanguage,
        entries: files.map((f) => ({
            file: f.file,
            language: f.language,
            endpointCount: (f.endpoints || []).length,
            websocketCount: (f.websockets || []).length,
            importCount: Object.keys(f.imports || {}).length,
            dynamicPatternCount: (f.dynamicPatterns || []).length,
        })),
    };
}

function buildNote(endpoints: number, websockets: number): string | undefined {
    if (endpoints > 0) return undefined;
    if (websockets > 0) {
        return `No HTTP endpoints found, but ${websockets} WebSocket handler(s) were detected. This project exposes a real-time API. Use securecode.scan or securecode.agent-scan to scan individual WebSocket handler files.`;
    }
    return 'No HTTP endpoints or WebSocket handlers found. This project may be a CLI, library, or SDK with no network surface. Use securecode.scan or securecode.agent-scan to scan individual source files for vulnerabilities.';
}

/**
 * Build the deterministic ArchitectureInventory from the project map. The
 * scout brain consumes this on every step so it doesn't have to re-discover
 * the file list, endpoints, or languages from scratch.
 *
 * Runtimes/packageManager are inferred from lockfiles (cheap, local). The
 * scout reads package.json itself during the survey for deeper detail.
 */
function buildArchitectureInventory(workspaceRoot: string, map: ProjectMap): ArchitectureInventory {
    const files = Object.values(map.files).map(f => ({
        file: f.file,
        language: f.language,
        lines: 0, // not in the map; the scout reads files to get line counts
        endpointCount: (f.endpoints || []).length,
        importCount: Object.keys(f.imports || {}).length,
    }));

    const endpoints = (map.endpoints || []).map(e => ({
        method: e.method,
        path: e.mountedPath || e.path,
        handler: e.handlerName,
        sourceFile: e.sourceFile,
        line: e.line,
        authScheme: e.authScheme,
        dataLayer: e.dataLayer,
    }));

    const languagesSet = new Set<string>();
    for (const f of Object.values(map.files)) {
        if (f.language && f.language !== 'unknown') languagesSet.add(f.language);
    }

    // Infer package manager + runtimes from lockfiles.
    const runtimes: string[] = [];
    let packageManager: string | null = null;
    try {
        if (fs.existsSync(path.join(workspaceRoot, 'package-lock.json'))) { packageManager = 'npm'; runtimes.push('node'); }
        else if (fs.existsSync(path.join(workspaceRoot, 'yarn.lock'))) { packageManager = 'yarn'; runtimes.push('node'); }
        else if (fs.existsSync(path.join(workspaceRoot, 'pnpm-lock.yaml'))) { packageManager = 'pnpm'; runtimes.push('node'); }
        else if (fs.existsSync(path.join(workspaceRoot, 'bun.lockb'))) { packageManager = 'bun'; runtimes.push('bun'); }
        else if (fs.existsSync(path.join(workspaceRoot, 'package.json'))) { runtimes.push('node'); }

        if (fs.existsSync(path.join(workspaceRoot, 'Pipfile.lock')) || fs.existsSync(path.join(workspaceRoot, 'requirements.txt'))) {
            packageManager = packageManager || 'pip'; runtimes.push('python');
        }
        if (fs.existsSync(path.join(workspaceRoot, 'pyproject.toml'))) {
            packageManager = packageManager || 'poetry'; runtimes.push('python');
        }
        if (fs.existsSync(path.join(workspaceRoot, 'go.mod'))) { runtimes.push('go'); }
        if (fs.existsSync(path.join(workspaceRoot, 'Cargo.toml'))) { runtimes.push('rust'); }
    } catch { /* best-effort */ }

    return {
        files,
        endpoints,
        runtimes: [...new Set(runtimes)],
        packageManager,
        languages: [...languagesSet],
    };
}

export async function toolMap(ctx: ServerContext, args: any): Promise<unknown> {
    const action = (args.action as string) || 'endpoints';
    const progressFn = args._progress as ((progress: number, total: number, message: string) => void) | undefined;

    if (action === 'build') {
        let lastProgress = 0;
        const result = await buildProjectMap({
            workspaceRoot: ctx.workspaceRoot,
            onProgress: (processed, total, file) => {
                const pct = Math.floor((processed / total) * 100);
                if (pct >= lastProgress + 5 || processed - lastProgress >= 25 || processed === total) {
                    lastProgress = pct;
                    progressFn?.(processed, total, `Mapping ${file} (${processed}/${total})`);
                }
            },
        });
        writeCache(ctx.workspaceRoot, result.map);
        return {
            built: true,
            endpoints: (result.map.endpoints || []).length,
            websockets: (result.map.websockets || []).length,
            filesProcessed: result.filesProcessed,
            filesSkipped: result.filesSkipped,
            errors: result.errors,
            durationMs: result.durationMs,
            builtAt: result.map.builtAt,
            note: buildNote((result.map.endpoints || []).length, (result.map.websockets || []).length),
        };
    }

    if (action === 'status') {
        return cacheStatus(ctx.workspaceRoot);
    }

    if (action === 'architecture') {
        return runArchitectureAction(ctx, args, progressFn);
    }

    // Default: return the full project inventory (endpoints, websockets,
    // files summary, dynamic patterns). Read from cache, or build if no cache.
    let map: ProjectMap | null = readCache(ctx.workspaceRoot);
    if (!map) {
        const result = await buildProjectMap({ workspaceRoot: ctx.workspaceRoot });
        writeCache(ctx.workspaceRoot, result.map);
        map = result.map;
    }

    const endpoints = (map.endpoints || []);
    const websockets = (map.websockets || []);
    const dynamicPatterns = (map.dynamicPatterns || []);
    const files = summarizeFiles(map);

    return {
        summary: {
            totalFiles: files.totalFiles,
            totalEndpoints: endpoints.length,
            totalWebsockets: websockets.length,
            totalDynamicPatterns: dynamicPatterns.length,
            languages: files.byLanguage,
        },
        endpoints: endpoints.map((e) => ({
            method: e.method,
            path: e.path,
            handler: e.handlerName,
            sourceFile: e.sourceFile,
            line: e.line,
            authScheme: e.authScheme,
            dataLayer: e.dataLayer,
            confidence: e.confidence,
        })),
        websockets: websockets.map((w) => ({
            event: w.event,
            receiver: w.receiver,
            handler: w.handlerName,
            sourceFile: w.sourceFile,
            line: w.line,
            confidence: w.confidence,
        })),
        files: files.entries,
        dynamicPatterns: dynamicPatterns.map((d) => ({
            type: d.type,
            file: d.file,
            line: d.line,
            snippet: d.snippet,
        })),
        note: buildNote(endpoints.length, websockets.length),
        builtAt: map.builtAt,
        version: map.version,
    };
}

// ── Background scout tracker (fast-return) ───────────────────────────────────
//
// `securecode.architecture` used to block its MCP tools/call for the full
// 2-5 minute scout run, so clients (opencode etc.) timed out at ~60s while
// the scout kept running in-process and cached its result. The tool now
// returns instantly and drives the scout in a detached background task;
// the client polls by retrying the same call until the cache serves it.

interface ScoutTrackerEntry {
    state: 'running' | 'blocked';
    startedAt: number;
    lastNote?: string;
}

const activeScouts = new Map<string, ScoutTrackerEntry>();

// Stuck 'running' entries older than this are restartable.
const SCOUT_TRACKER_STALE_MS = 10 * 60 * 1000;

function scoutKey(root: string, depth: string): string {
    return `${root}:${depth}`;
}

/**
 * Start the architecture scout detached from the MCP request. Returns
 * immediately; the scout writes its result to the architecture cache when
 * it finishes. Deliberately does NOT inherit the caller's AbortSignal —
 * the scout must complete (and cache) even if the client hangs up.
 *
 * Tracker lifecycle: the entry is deleted on any non-spawn_failed outcome
 * (so the next call serves the cache) and flips to 'blocked' with a note
 * when the run pool refuses the start, so the next fast-return can tell
 * the client what happened instead of blindly restarting.
 */
function startBackgroundScout(
    ctx: ServerContext,
    depth: ArchitectureDepth,
    map: ProjectMap,
    progressFn: ((progress: number, total: number, message: string) => void) | undefined,
): void {
    const key = scoutKey(ctx.workspaceRoot, depth);
    activeScouts.set(key, { state: 'running', startedAt: Date.now() });
    void (async () => {
        try {
            const inventory = buildArchitectureInventory(ctx.workspaceRoot, map);
            const defaults = scoutDefaultsForDepth(depth);
            const result = await runArchitectureScout(ctx, {
                depth,
                inventory,
                maxImportantFiles: defaults.maxImportantFiles,
            }, {
                projectMapBuiltAt: map.builtAt,
                projectMapVersion: map.version,
                onProgress: (steps, max, msg) => {
                    if (progressFn) progressFn(steps, max, msg);
                },
            });
            if (result.architecture) {
                writeCachedArchitectureContext(ctx.workspaceRoot, result.architecture);
            }
            if (result.status === 'spawn_failed') {
                const apiCode = result.apiCode || '';
                activeScouts.set(key, { state: 'blocked', startedAt: Date.now(), lastNote: `${apiCode}: ${result.error || 'spawn failed'}` });
                console.warn(`[Architecture] background scout failed (${depth}): ${result.error}`);
            } else {
                // 'running' entries clear on success; blocked entries persist
                // for visibility (the stale guard makes them restartable).
                activeScouts.delete(key);
            }
        } catch (err: any) {
            const apiCode = err?.apiCode || err?.code || '';
            activeScouts.set(key, { state: 'blocked', startedAt: Date.now(), lastNote: `${apiCode}: ${err?.message || String(err)}` });
            console.warn(`[Architecture] background scout threw (${depth}): ${err?.message || err}`);
        }
    })();
}

/** Test-only accessor for the in-process scout tracker. */
export function __scoutTrackerForTests(): Map<string, ScoutTrackerEntry> {
    return activeScouts;
}

/** Test-only reset for tracker isolation between tests. */
export function __clearScoutTrackerForTests(): void {
    activeScouts.clear();
}

/**
 * `securecode.architecture` — runs the architecture scout
 * subagent to survey the project and produce an ArchitectureContext.
 *
 * Flow (fast-return, default):
 *   1. Ensure the project map exists (build if not).
 *   2. Check the architecture cache — return if valid and not stale.
 *   3. If a fresh tracker entry says a scout is running (or the run pool
 *      is blocked) → return 'in-progress'; the client retries shortly.
 *   4. Otherwise start a detached background scout → return 'started'.
 *      The background scout writes the result to the cache, which step 2
 *      serves on the next poll.
 *
 * Internal synchronous callers (agent-scan-batch) pass `_wait: true` and
 * keep the old blocking behavior — they already run long and handle
 * their own preflight errors.
 */
async function runArchitectureAction(
    ctx: ServerContext,
    args: any,
    progressFn: ((progress: number, total: number, message: string) => void) | undefined,
): Promise<unknown> {
    const depth: ArchitectureDepth = ['quick', 'standard', 'deep'].includes(args.depth) ? args.depth : 'standard';
    const noCache = !!args._noCache;
    const signal = (args as any)._signal as AbortSignal | undefined;

    // 1. Ensure the project map exists.
    let map = readCache(ctx.workspaceRoot);
    if (!map) {
        if (progressFn) progressFn(0, 1, 'Building project map...');
        const result = await buildProjectMap({ workspaceRoot: ctx.workspaceRoot });
        writeCache(ctx.workspaceRoot, result.map);
        map = result.map;
    }

    // 2. Check the architecture cache.
    if (!noCache) {
        const cached = getCachedArchitectureContext(
            ctx.workspaceRoot, depth, map.builtAt, map.version,
        );
        if (cached) {
            if (progressFn) progressFn(1, 1, 'Cached architecture context — project map unchanged since last derivation.');
            return { architecture: cached, cached: true, depth };
        }
    } else {
        clearArchitectureCache(ctx.workspaceRoot);
    }

    if (args._wait === true) {
        // 3. Build the deterministic inventory.
        const inventory = buildArchitectureInventory(ctx.workspaceRoot, map);
        const defaults = scoutDefaultsForDepth(depth);

        // 4. Run the scout loop (blocking — internal caller).
        if (progressFn) progressFn(0, defaults.maxSteps, `Architecture scout (${depth}) starting...`);
        const result = await runArchitectureScout(ctx, {
            depth,
            inventory,
            maxImportantFiles: defaults.maxImportantFiles,
        }, {
            signal,
            projectMapBuiltAt: map.builtAt,
            projectMapVersion: map.version,
            onProgress: (steps, max, msg) => {
                if (progressFn) progressFn(steps, max, msg);
            },
        });

        if (result.status === 'spawn_failed') {
            const e: any = new Error(result.error || 'Architecture scout failed to start.');
            e.apiCode = result.apiCode || '';
            e.statusCode = result.apiCode === 'AGENT_SCAN_ALREADY_RUNNING' ? 409 : result.apiCode === 'AGENT_SCAN_DAILY_LIMIT' ? 429 : undefined;
            throw e;
        }

        // 5. Cache + return.
        if (result.architecture) {
            writeCachedArchitectureContext(ctx.workspaceRoot, result.architecture);
        }

        return {
            architecture: result.architecture,
            status: result.status,
            summary: result.summary,
            stepsUsed: result.stepsUsed,
            costSpentUsd: result.costSpentUsd,
            depth,
            cached: false,
        };
    }

    // Fast-return path for MCP clients (default): never block tools/call.
    const key = scoutKey(ctx.workspaceRoot, depth);
    const entry = activeScouts.get(key);
    const fresh = entry && (Date.now() - entry.startedAt) < SCOUT_TRACKER_STALE_MS;

    if (fresh && entry!.state === 'running') {
        return {
            status: 'in-progress',
            depth,
            etaMinutes: depth === 'quick' ? 1 : depth === 'deep' ? 4 : 2,
            hint: 'The architecture scout is running in the background. Retry this same call to retrieve the result when done.',
        };
    }
    if (fresh && entry!.state === 'blocked') {
        return {
            status: 'in-progress',
            depth,
            etaMinutes: 2,
            hint: `Another operation holds the agent run pool (${entry!.lastNote || 'already running'}). Wait ~60-120 seconds and retry this call.`,
        };
    }

    // No fresh entry → cold cache, a noCache refresh, or a stale tracker
    // entry: (re)start a background scout and return instantly.
    startBackgroundScout(ctx, depth, map, progressFn);
    return {
        status: 'started',
        depth,
        etaMinutes: depth === 'quick' ? 1 : depth === 'deep' ? 5 : 3,
        hint: 'The scout is running in the background. Retry this same call in a few minutes to retrieve the cached result.',
    };
}
