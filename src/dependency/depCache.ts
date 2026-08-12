import * as fs from 'fs';
import * as path from 'path';
import { CacheStore } from './finding';

/**
 * File-based NVD CVSS cache for the MCP server.
 *
 * The extension uses `vscode.Memento` (workspaceState) for this. The MCP
 * server has no VS Code API, so we store the cache as a JSON file at
 * `.securecode/nvd-cache.json` inside the workspace root.
 *
 * Implements the `CacheStore` interface ({ get, update }) that
 * `enrichWithNvd` expects.
 */

const CACHE_DIR = '.securecode';
const CACHE_FILE = 'nvd-cache.json';
const SCHEMA_VERSION = 1;

interface CacheFile {
    version: number;
    entries: Record<string, { fetchedAt: number; score?: number; url?: string }>;
}

/**
 * A file-backed CacheStore. Loads the cache file lazily on first `get`,
 * buffers updates in memory, and flushes to disk atomically on each
 * `update`. Safe for the single-threaded MCP server; not safe for
 * concurrent processes writing the same file.
 */
export class FileCacheStore implements CacheStore {
    private workspaceRoot: string;
    private cachePath: string;
    private loaded: CacheFile | null = null;
    private dirty = false;

    constructor(workspaceRoot: string) {
        this.workspaceRoot = workspaceRoot;
        this.cachePath = path.join(workspaceRoot, CACHE_DIR, CACHE_FILE);
    }

    private load(): CacheFile {
        if (this.loaded) return this.loaded;
        try {
            if (fs.existsSync(this.cachePath)) {
                const raw = fs.readFileSync(this.cachePath, 'utf8');
                const parsed = JSON.parse(raw) as CacheFile;
                if (parsed.version === SCHEMA_VERSION && parsed.entries) {
                    this.loaded = parsed;
                    return this.loaded;
                }
            }
        } catch { /* file corrupt or missing — start fresh */ }
        this.loaded = { version: SCHEMA_VERSION, entries: {} };
        return this.loaded;
    }

    get<T>(key: string): T | undefined {
        const cache = this.load();
        return cache.entries[key] as T | undefined;
    }

    update(key: string, value: unknown): void {
        const cache = this.load();
        cache.entries[key] = value as { fetchedAt: number; score?: number; url?: string };
        this.dirty = true;
        this.flush();
    }

    /**
     * Write the cache to disk atomically (.tmp + rename). Called after
     * each `update` so a crash never loses more than the last entry.
     */
    private flush(): void {
        if (!this.dirty || !this.loaded) return;
        try {
            const dir = path.join(this.workspaceRoot, CACHE_DIR);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            const tmp = this.cachePath + '.tmp';
            fs.writeFileSync(tmp, JSON.stringify(this.loaded, null, 2), 'utf8');
            fs.renameSync(tmp, this.cachePath);
            this.dirty = false;
        } catch { /* best effort — cache is optional */ }
    }
}
