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
