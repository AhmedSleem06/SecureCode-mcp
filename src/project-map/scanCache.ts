/**
 * Scan result cache — stores agent scan findings keyed by file content hash.
 *
 * Lives in `.securecode/scan-cache.json` alongside the project map cache.
 * Invalidates when:
 *   - File content changes (hash mismatch)
 *   - Agent scan prompt version changes (AGENT_SCAN_CACHE_VERSION bump)
 *   - Cache entry expires (TTL)
 *
 * This makes scans deterministic: re-scanning an unchanged file returns the
 * cached findings instantly without calling the LLM again.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const CACHE_DIR = '.securecode';
const CACHE_FILE = 'scan-cache.json';

/**
 * Bump this when the agent scan prompt or logic changes in a way that
 * would produce different findings for the same file. All cached entries
 * with an older version are invalidated.
 */
export const AGENT_SCAN_CACHE_VERSION = 19;

/** Cache TTL: 7 days. Findings older than this are re-scanned. */
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface ScanCacheEntry {
    /** SHA-256 of the file content at scan time. */
    fileHash: string;
    /** Agent scan cache version when this entry was created. */
    version: number;
    /** Unix timestamp (ms) when the entry was created. */
    timestamp: number;
    /** The findings from the scan. */
    findings: any[];
    /** Scan status (completed, capped, etc.). */
    status: string;
    /** Summary from the agent. */
    summary?: string;
    /** Steps used by the agent. */
    stepsUsed: number;
    /** Cost in USD. */
    costSpentUsd: number;
    /** File path (for debugging). */
    filePath: string;
}

export interface ScanCacheData {
    version: number;
    entries: Record<string, ScanCacheEntry>;
}

function cachePath(workspaceRoot: string): string {
    return path.join(workspaceRoot, CACHE_DIR, CACHE_FILE);
}

function hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

/**
 * Read the scan cache. Returns null if the cache file doesn't exist
 * or is corrupted.
 */
export function readScanCache(workspaceRoot: string): ScanCacheData | null {
    const p = cachePath(workspaceRoot);
    try {
        if (!fs.existsSync(p)) return null;
        const raw = fs.readFileSync(p, 'utf8');
        const data = JSON.parse(raw) as ScanCacheData;
        if (!data.version || data.version > AGENT_SCAN_CACHE_VERSION) {
            return null;
        }
        return data;
    } catch {
        return null;
    }
}

/**
 * Look up a cached scan result by file path + content hash.
 * Returns null if not found, expired, or version mismatch.
 */
export function getCachedScan(
    workspaceRoot: string,
    filePath: string,
    content: string,
): ScanCacheEntry | null {
    const cache = readScanCache(workspaceRoot);
    if (!cache) return null;

    const fileHash = hashContent(content);
    const key = `${filePath}:${fileHash}`;
    const entry = cache.entries[key];
    if (!entry) return null;

    // Version check — invalidate on prompt/logic changes
    if (entry.version !== AGENT_SCAN_CACHE_VERSION) return null;

    // TTL check — re-scan after CACHE_TTL_MS
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) return null;

    return entry;
}

/**
 * Write a scan result to the cache. Merges with existing entries.
 */
export function writeCachedScan(
    workspaceRoot: string,
    filePath: string,
    content: string,
    result: {
        findings: any[];
        status: string;
        summary?: string;
        stepsUsed: number;
        costSpentUsd: number;
    },
): void {
    const dir = path.join(workspaceRoot, CACHE_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    const fileHash = hashContent(content);
    const key = `${filePath}:${fileHash}`;

    // Read existing cache or create new
    let cache: ScanCacheData;
    const existing = readScanCache(workspaceRoot);
    if (existing && existing.version === AGENT_SCAN_CACHE_VERSION) {
        cache = existing;
    } else {
        cache = { version: AGENT_SCAN_CACHE_VERSION, entries: {} };
    }

    // Prune expired entries (keep cache from growing unbounded)
    const now = Date.now();
    for (const [k, e] of Object.entries(cache.entries)) {
        if (now - e.timestamp > CACHE_TTL_MS) {
            delete cache.entries[k];
        }
    }

    // Add/update the entry
    cache.entries[key] = {
        fileHash,
        version: AGENT_SCAN_CACHE_VERSION,
        timestamp: now,
        findings: result.findings,
        status: result.status,
        summary: result.summary,
        stepsUsed: result.stepsUsed,
        costSpentUsd: result.costSpentUsd,
        filePath,
    };

    // Atomic write
    const p = cachePath(workspaceRoot);
    const tmp = p + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(cache, null, 2), 'utf8');
    fs.renameSync(tmp, p);
}

/**
 * Clear the scan cache for a workspace (e.g., when the user requests
 * a fresh scan with --no-cache).
 */
export function clearScanCache(workspaceRoot: string): void {
    const p = cachePath(workspaceRoot);
    try {
        if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch { /* best effort */ }
}
