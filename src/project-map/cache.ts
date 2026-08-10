import * as fs from 'fs';
import * as path from 'path';
import type { ProjectMap } from './types';
import { PROJECT_MAP_SCHEMA_VERSION } from './types';

const CACHE_DIR = '.securecode';
const CACHE_FILE = 'project-map.json';

export function cachePath(workspaceRoot: string): string {
    return path.join(workspaceRoot, CACHE_DIR, CACHE_FILE);
}

export function readCache(workspaceRoot: string): ProjectMap | null {
    const p = cachePath(workspaceRoot);
    try {
        if (!fs.existsSync(p)) return null;
        const raw = fs.readFileSync(p, 'utf8');
        const map = JSON.parse(raw) as ProjectMap;
        if (!map.version || map.version > PROJECT_MAP_SCHEMA_VERSION) {
            return null;
        }
        return map;
    } catch {
        return null;
    }
}

export function writeCache(workspaceRoot: string, map: ProjectMap): void {
    const dir = path.join(workspaceRoot, CACHE_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    const p = cachePath(workspaceRoot);
    const tmp = p + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(map, null, 2), 'utf8');
    fs.renameSync(tmp, p);
}

export function cacheStatus(workspaceRoot: string): {
    exists: boolean;
    builtAt?: number;
    version?: number;
    endpointCount?: number;
    fileCount?: number;
} {
    const map = readCache(workspaceRoot);
    if (!map) return { exists: false };
    return {
        exists: true,
        builtAt: map.builtAt,
        version: map.version,
        endpointCount: (map.endpoints || []).length,
        fileCount: map.files ? Object.keys(map.files).length : 0,
    };
}
