/**
 * Blast radius computation — given a set of changed files, compute which
 * other files in the workspace are affected by those changes.
 *
 * Uses the Project Map's import graph (forward: what this file imports;
 * reverse: who imports this file) to traverse the dependency graph to a
 * depth cap. The result is a set of files that the agent scan should focus
 * on, plus the changed files themselves.
 *
 * Algorithm:
 *   1. Invert the Project Map's `imports` records once into a reverse map:
 *      for each file F that imports module M, record F as an importer of M.
 *   2. BFS from each changed file:
 *      - Forward edges: files that THIS file imports (if F changes, the
 *        files F depends on might behave differently — but they're
 *        dependencies, not dependents. We skip forward edges for blast
 *        radius because changing a file doesn't affect its dependencies.)
 *      - Reverse edges: files that import THIS file (if F changes, files
 *        that depend on F are affected — these are the blast radius.)
 *   3. Cap depth at `maxDepth` (default 3) to avoid traversing the entire
 *      workspace for a large change.
 *   4. Cap total files at `maxFiles` (default 100) to keep the scope
 *      manageable.
 *
 * Security:
 *   - All file paths come from the Project Map (already workspace-confined)
 *   - No filesystem access — pure graph computation
 *   - Output is a list of workspace-relative paths
 */

import type { ProjectMap } from './types';

export interface BlastRadiusOptions {
    /** Changed files (workspace-relative paths). */
    changedFiles: string[];
    /** The project map (from cache or freshly built). */
    map: ProjectMap;
    /** Max BFS depth (default 3). */
    maxDepth?: number;
    /** Max total files in the result (default 100). */
    maxFiles?: number;
}

export interface BlastRadiusResult {
    /** All files in the blast radius (changed + affected), workspace-relative. */
    files: string[];
    /** Only the changed files that exist in the project map. */
    changedFiles: string[];
    /** Files affected by the changes (not the changed files themselves). */
    affectedFiles: string[];
    /** BFS depth reached (0 = only changed files, 1 = direct importers, etc.). */
    depthReached: number;
    /** Whether the result was truncated by maxFiles. */
    truncated: boolean;
}

const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_MAX_FILES = 100;

function normalizePath(p: string): string {
    return p.replace(/\\/g, '/');
}

function buildReverseImportMap(map: ProjectMap): Map<string, string[]> {
    const reverse = new Map<string, string[]>();

    for (const [fileRel, extraction] of Object.entries(map.files)) {
        const importer = normalizePath(fileRel);
        if (!extraction.imports) continue;

        for (const [, sourceFile] of Object.entries(extraction.imports)) {
            if (!sourceFile) continue;
            const imported = normalizePath(sourceFile);
            if (imported === importer) continue;

            let importers = reverse.get(imported);
            if (!importers) {
                importers = [];
                reverse.set(imported, importers);
            }
            if (!importers.includes(importer)) {
                importers.push(importer);
            }
        }
    }

    return reverse;
}

function buildReverseCallGraph(map: ProjectMap): Map<string, string[]> {
    const reverse = new Map<string, string[]>();

    for (const [fileRel, extraction] of Object.entries(map.files)) {
        const caller = normalizePath(fileRel);
        for (const endpoint of extraction.endpoints) {
            if (!endpoint.callGraph) continue;
            for (const node of endpoint.callGraph) {
                if (!node.calleeFile) continue;
                const callee = normalizePath(node.calleeFile);
                if (callee === caller) continue;

                let callers = reverse.get(callee);
                if (!callers) {
                    callers = [];
                    reverse.set(callee, callers);
                }
                if (!callers.includes(caller)) {
                    callers.push(caller);
                }
            }
        }
    }

    return reverse;
}

function buildReverseMiddlewareMap(map: ProjectMap): Map<string, string[]> {
    const reverse = new Map<string, string[]>();

    for (const [fileRel, extraction] of Object.entries(map.files)) {
        const handler = normalizePath(fileRel);
        for (const endpoint of extraction.endpoints) {
            if (!endpoint.middleware) continue;
            for (const mw of endpoint.middleware) {
                if (!mw.sourceFile) continue;
                const mwFile = normalizePath(mw.sourceFile);
                if (mwFile === handler) continue;

                let handlers = reverse.get(mwFile);
                if (!handlers) {
                    handlers = [];
                    reverse.set(mwFile, handlers);
                }
                if (!handlers.includes(handler)) {
                    handlers.push(handler);
                }
            }
        }
    }

    return reverse;
}

export function computeBlastRadius(options: BlastRadiusOptions): BlastRadiusResult {
    const {
        changedFiles,
        map,
        maxDepth = DEFAULT_MAX_DEPTH,
        maxFiles = DEFAULT_MAX_FILES,
    } = options;

    const normalizedChanged = changedFiles
        .map(normalizePath)
        .filter(f => f.length > 0);

    if (normalizedChanged.length === 0) {
        return { files: [], changedFiles: [], affectedFiles: [], depthReached: 0, truncated: false };
    }

    const reverseImports = buildReverseImportMap(map);
    const reverseCallGraph = buildReverseCallGraph(map);
    const reverseMiddleware = buildReverseMiddlewareMap(map);

    function getReverseDeps(file: string): string[] {
        const deps = new Set<string>();
        for (const dep of reverseImports.get(file) || []) deps.add(dep);
        for (const dep of reverseCallGraph.get(file) || []) deps.add(dep);
        for (const dep of reverseMiddleware.get(file) || []) deps.add(dep);
        return [...deps];
    }

    const visited = new Set<string>();
    const queue: Array<{ file: string; depth: number }> = [];

    for (const f of normalizedChanged) {
        if (!visited.has(f)) {
            visited.add(f);
            queue.push({ file: f, depth: 0 });
        }
    }

    let depthReached = 0;

    while (queue.length > 0 && visited.size < maxFiles) {
        const { file, depth } = queue.shift()!;

        if (depth >= maxDepth) continue;
        if (depth + 1 > depthReached) depthReached = depth + 1;

        const dependents = getReverseDeps(file);
        for (const dep of dependents) {
            if (visited.has(dep)) continue;
            if (visited.size >= maxFiles) break;
            visited.add(dep);
            queue.push({ file: dep, depth: depth + 1 });
        }
    }

    const truncated = visited.size >= maxFiles && queue.length > 0;
    const allFiles = [...visited];
    const changedSet = new Set(normalizedChanged);
    const affectedFiles = allFiles.filter(f => !changedSet.has(f));
    const changedInMap = normalizedChanged.filter(f => map.files[f] !== undefined || visited.has(f));

    return {
        files: allFiles,
        changedFiles: changedInMap,
        affectedFiles,
        depthReached,
        truncated,
    };
}

export function formatBlastRadius(result: BlastRadiusResult): string {
    if (result.files.length === 0) {
        return 'No blast radius — no changed files provided.';
    }

    const lines: string[] = [
        `Blast radius: ${result.files.length} file(s) (changed: ${result.changedFiles.length}, affected: ${result.affectedFiles.length}, depth: ${result.depthReached})${result.truncated ? ' [truncated]' : ''}:`,
        '',
    ];

    lines.push('Changed files:');
    for (const f of result.changedFiles.slice(0, 50)) {
        lines.push(`  [changed] ${f}`);
    }

    lines.push('');
    lines.push('Affected files (importers/callers):');
    for (const f of result.affectedFiles.slice(0, 50)) {
        lines.push(`  [affected] ${f}`);
    }

    if (result.files.length > 100) {
        lines.push(`  ... and ${result.files.length - 100} more`);
    }

    return lines.join('\n');
}
