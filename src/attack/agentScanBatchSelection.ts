/**
 * Deterministic file selection for the agent scan batch tool.
 *
 * Selects the top N security-relevant files from the architecture context,
 * using either the recommended scan order or the important files list.
 * Filters out missing, empty, binary, and oversized files before selection.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ArchitectureContext, ImportantFile } from '../project-map/architectureContext';

export interface SelectedBatchFile {
    filePath: string;
    rank: number;
    role?: string;
    importance?: number;
}

export interface SkippedBatchFile {
    filePath: string;
    reason: string;
}

export interface BatchFileSelection {
    selected: SelectedBatchFile[];
    skipped: SkippedBatchFile[];
}

const MAX_FILE_BYTES = 1_500_000;
const MIN_TOP_N = 1;
const MAX_TOP_N = 20;
const DEFAULT_TOP_N = 3;

function normalizePath(filePath: string): string {
    return filePath.replace(/\\/g, '/').replace(/^\.\//, '');
}

function checkFile(workspaceRoot: string, filePath: string): { ok: true } | { ok: false; reason: string } {
    const absPath = path.isAbsolute(filePath)
        ? filePath
        : path.join(workspaceRoot, filePath);

    if (!fs.existsSync(absPath)) {
        return { ok: false, reason: 'file does not exist' };
    }

    let stat: fs.Stats;
    try {
        stat = fs.statSync(absPath);
    } catch {
        return { ok: false, reason: 'cannot stat file' };
    }

    if (!stat.isFile()) {
        return { ok: false, reason: 'not a regular file' };
    }

    if (stat.size === 0) {
        return { ok: false, reason: 'file is empty' };
    }

    if (stat.size > MAX_FILE_BYTES) {
        return { ok: false, reason: `file too large (${(stat.size / 1_000_000).toFixed(1)}MB > 1.5MB limit)` };
    }

    let content: string;
    try {
        content = fs.readFileSync(absPath, 'utf8');
    } catch {
        return { ok: false, reason: 'cannot read file' };
    }

    if (content.trim().length === 0) {
        return { ok: false, reason: 'file is empty (whitespace only)' };
    }

    const headBytes = Buffer.from(content.slice(0, 1000), 'utf8');
    if (headBytes.includes(0)) {
        return { ok: false, reason: 'binary file' };
    }

    return { ok: true };
}

/**
 * Select the top N files for sequential agent scanning.
 *
 * Algorithm:
 *  1. Start with recommendedScanOrder (or importantFiles if selected).
 *  2. Normalize paths to forward-slash workspace-relative.
 *  3. Remove duplicates.
 *  4. Filter out missing, empty, binary, and oversized files.
 *  5. Fill remaining slots from the other list if needed.
 *  6. Clamp topN to 1..20.
 *  7. Freeze the selection before returning.
 */
export function selectAgentScanBatchFiles(
    workspaceRoot: string,
    architecture: ArchitectureContext | null,
    options: {
        topN?: number;
        fileSelection?: 'recommendedScanOrder' | 'importantFiles';
    },
): BatchFileSelection {
    const topN = Math.max(MIN_TOP_N, Math.min(MAX_TOP_N, options.topN ?? DEFAULT_TOP_N));
    const useImportantFirst = options.fileSelection === 'importantFiles';

    if (!architecture) {
        return { selected: [], skipped: [] };
    }

    const seen = new Set<string>();
    const selected: SelectedBatchFile[] = [];
    const skipped: SkippedBatchFile[] = [];

    const importantMap = new Map<string, ImportantFile>();
    for (const f of architecture.importantFiles || []) {
        importantMap.set(normalizePath(f.file), f);
    }

    const buildEntry = (filePath: string, rank: number): SelectedBatchFile => {
        const norm = normalizePath(filePath);
        const info = importantMap.get(norm);
        return {
            filePath: norm,
            rank,
            role: info?.role as string | undefined,
            importance: info?.importance,
        };
    };

    const tryAdd = (filePath: string): void => {
        const norm = normalizePath(filePath);
        if (seen.has(norm)) return;
        seen.add(norm);

        const check = checkFile(workspaceRoot, norm);
        if (!check.ok) {
            skipped.push({ filePath: norm, reason: check.reason });
            return;
        }

        if (selected.length < topN) {
            selected.push(buildEntry(filePath, selected.length + 1));
        }
    };

    const primaryList = useImportantFirst
        ? (architecture.importantFiles || [])
            .slice()
            .sort((a, b) => (b.importance || 0) - (a.importance || 0))
            .map(f => f.file)
        : (architecture.recommendedScanOrder || []);

    for (const filePath of primaryList) {
        if (selected.length >= topN) break;
        tryAdd(filePath);
    }

    if (selected.length < topN) {
        const fallback = useImportantFirst
            ? (architecture.recommendedScanOrder || [])
            : (architecture.importantFiles || [])
                .slice()
                .sort((a, b) => (b.importance || 0) - (a.importance || 0))
                .map(f => f.file);

        for (const filePath of fallback) {
            if (selected.length >= topN) break;
            tryAdd(filePath);
        }
    }

    return { selected, skipped };
}
