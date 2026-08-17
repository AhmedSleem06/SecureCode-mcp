import * as fs from 'fs';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { readCache, writeCache, cacheStatus } from '../project-map/cache';
import { buildProjectMap } from '../project-map/mapBuilder';
import type { ProjectMap } from '../project-map/types';

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

export async function toolMap(ctx: ServerContext, args: any): Promise<unknown> {
    const action = (args.action as string) || 'endpoints';
    const progressFn = args._progress as ((progress: number, total: number, message: string) => void) | undefined;

    if (action === 'build') {
        let lastProgress = 0;
        const result = await buildProjectMap({
            workspaceRoot: ctx.workspaceRoot,
            onProgress: (processed, total, file) => {
                // Send progress at most every 5% or every 25 files
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
