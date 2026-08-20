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

/**
 * `securecode.map action:architecture` — runs the architecture scout
 * subagent to survey the project and produce an ArchitectureContext.
 *
 * Flow:
 *   1. Ensure the project map exists (build if not).
 *   2. Check the architecture cache — return if valid and not stale.
 *   3. Build the deterministic inventory from the project map.
 *   4. Run the architecture scout loop (MCP loop + API brain).
 *   5. Cache the result.
 *   6. Return the architecture context.
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

    // 3. Build the deterministic inventory.
    const inventory = buildArchitectureInventory(ctx.workspaceRoot, map);
    const defaults = scoutDefaultsForDepth(depth);

    // 4. Run the scout loop.
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
        throw new Error(result.error || 'Architecture scout failed to start.');
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
