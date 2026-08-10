import * as fs from 'fs';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { readCache, writeCache, cacheStatus } from '../project-map/cache';
import { buildProjectMap } from '../project-map/mapBuilder';

export async function toolMap(ctx: ServerContext, args: any): Promise<unknown> {
    const action = (args.action as string) || 'endpoints';

    if (action === 'build') {
        const result = await buildProjectMap({ workspaceRoot: ctx.workspaceRoot });
        writeCache(ctx.workspaceRoot, result.map);
        return {
            built: true,
            endpoints: (result.map.endpoints || []).length,
            filesProcessed: result.filesProcessed,
            filesSkipped: result.filesSkipped,
            errors: result.errors,
            durationMs: result.durationMs,
            builtAt: result.map.builtAt,
        };
    }

    if (action === 'status') {
        return cacheStatus(ctx.workspaceRoot);
    }

    // Default: return endpoints (read from cache, or build if no cache)
    let map = readCache(ctx.workspaceRoot);
    if (!map) {
        const result = await buildProjectMap({ workspaceRoot: ctx.workspaceRoot });
        writeCache(ctx.workspaceRoot, result.map);
        map = result.map;
    }

    return {
        endpoints: (map.endpoints || []).map((e) => ({
            method: e.method,
            path: e.path,
            handler: e.handlerName,
            sourceFile: e.sourceFile,
            line: e.line,
            authScheme: e.authScheme,
            dataLayer: e.dataLayer,
            confidence: e.confidence,
        })),
        builtAt: map.builtAt,
        version: map.version,
    };
}
