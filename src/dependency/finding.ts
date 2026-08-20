/**
 * Shared types for the MCP dependency scanner.
 *
 * ScanFinding is copied from the extension's apiClient.ts (line 74-97) to
 * avoid importing that file, which drags in `axios` and `vscode` — neither
 * available in the MCP server.
 *
 * CacheStore replaces the extension's `vscode.Memento` dependency. The MCP
 * server implements this with a file-based cache (depCache.ts).
 */

export interface ScanFinding {
    check_id: string;
    severity: 'ERROR' | 'WARNING';
    message: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    source?: 'code' | 'dependency';
    dependency?: {
        ecosystem: 'npm' | 'yarn' | 'pnpm' | 'pip' | 'pipenv';
        name: string;
        installedVersion: string;
        fixedVersion?: string;
        license?: string;
        manifestPath?: string;
        unresolved?: boolean;
        /** Number of advisory sources that confirmed (1-3: osv, ghsa, nvd). */
        sourceCount?: number;
        /** Comma-separated list of confirming sources. */
        confirmedBy?: string;
        /** Exploit-priority score 0-100 (higher = more urgent). */
        exploitPriority?: number;
        /** True if listed in CISA KEV catalog. */
        knownExploited?: boolean;
        /** True if a public exploit/PoC is referenced. */
        exploitAvailable?: boolean;
        /** EPSS percentile 0-100. */
        epssPercentile?: number;
        /** True if the package is a direct (not transitive) dependency. */
        isDirect?: boolean;
        /** Total number of distinct advisories for this package. */
        advisoryCount?: number;
    };
}

/**
 * Minimal cache interface — the only part of `vscode.Memento` the dependency
 * checker uses (`get<T>(key)` and `update(key, value)`). The MCP server
 * implements this with a file-based JSON cache (see depCache.ts).
 */
export interface CacheStore {
    get<T>(key: string): T | undefined;
    update(key: string, value: unknown): Promise<void> | void;
}
