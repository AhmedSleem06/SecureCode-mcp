/**
 * Project Map context extraction for the scan tool.
 *
 * Wraps cache reading, map building, and context extraction so the scan
 * tool can get `endpointContext` and `relatedFiles` for a file in one call.
 *
 * Best-effort: if the map can't be built or the file isn't in it, returns
 * empty arrays — the scan proceeds without cross-file context (same as
 * today).
 */
import * as path from 'path';
import { readCache, writeCache } from './cache';
import { buildProjectMap } from './mapBuilder';
import { collectRelatedFiles } from './relatedFiles';
import { toEndpointContext, type EndpointContext, type ProjectMap, type RelatedFile } from './types';

/**
 * Get the project map — from cache if available, or build + cache if not.
 * Returns null on any failure (best-effort).
 */
async function getMap(workspaceRoot: string): Promise<ProjectMap | null> {
    let map = readCache(workspaceRoot);
    if (map) return map;

    try {
        const result = await buildProjectMap({ workspaceRoot });
        writeCache(workspaceRoot, result.map);
        return result.map;
    } catch {
        return null;
    }
}

/**
 * Get the EndpointContext for every endpoint in the given file.
 * Returns [] if the file isn't in the map (no endpoints or map unavailable).
 */
export async function getEndpointContextForFile(
    filePath: string,
    workspaceRoot: string,
): Promise<EndpointContext[]> {
    const map = await getMap(workspaceRoot);
    if (!map) return [];

    const rel = path.relative(workspaceRoot, filePath).replace(/\\/g, '/');
    const fileEntry = map.files[rel];
    if (!fileEntry) return [];

    return fileEntry.endpoints.map(toEndpointContext);
}

/**
 * Get the related files to ship with a scan of the given file.
 * Returns [] if the file isn't in the map or no neighbours are found.
 */
export async function getRelatedFilesForFile(
    filePath: string,
    workspaceRoot: string,
): Promise<RelatedFile[]> {
    const map = await getMap(workspaceRoot);
    if (!map) return [];

    return collectRelatedFiles({ filePath, workspaceRoot, map });
}
