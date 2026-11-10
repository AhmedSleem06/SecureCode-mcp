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
import { detectDeclarationOnly } from './fileShape';

export interface BatchFileReplacement {
    from: string;
    to: string;
    reason: 'types only';
}

export interface SelectedBatchFile {
    filePath: string;
    rank: number;
    role?: string;
    importance?: number;
    replaced?: BatchFileReplacement;
}

export interface SkippedBatchFile {
    filePath: string;
    reason: string;
}

export interface BatchFileSelection {
    selected: SelectedBatchFile[];
    skipped: SkippedBatchFile[];
}

export const TYPES_ONLY_SKIP_REASON = 'types only (no implementation found)';

const MAX_FILE_BYTES = 1_500_000;
const MIN_TOP_N = 1;
const MAX_TOP_N = 20;
const DEFAULT_TOP_N = 3;
const IMPLEMENTATION_DIR_NAMES = ['Layers', 'layers', 'Live', 'live', 'impl', 'Impl', 'implementation', 'implementations'];
const IMPLEMENTATION_SUFFIXES = ['impl', 'service', 'live'];
const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);
const REFERENCE_SEARCH_MAX_FILES = 2000;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.turbo', '.securecode']);

function normalizePath(filePath: string): string {
    return filePath.replace(/\\/g, '/').replace(/^\.\//, '');
}

function toAbs(workspaceRoot: string, filePath: string): string {
    return path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
}

function toRel(workspaceRoot: string, absPath: string): string {
    return normalizePath(path.relative(workspaceRoot, absPath));
}

function readText(absPath: string): string | null {
    try {
        return fs.readFileSync(absPath, 'utf8');
    } catch {
        return null;
    }
}

function isFile(absPath: string): boolean {
    try {
        return fs.statSync(absPath).isFile();
    } catch {
        return false;
    }
}

function realPath(absPath: string): string {
    try {
        return fs.realpathSync.native(absPath);
    } catch {
        return path.resolve(absPath);
    }
}

function listDir(absDir: string): fs.Dirent[] {
    try {
        return fs.readdirSync(absDir, { withFileTypes: true });
    } catch {
        return [];
    }
}

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Find the implementation of a types-only file, in order:
 *  1. the same basename in a sibling directory (Services/X.ts → Layers/X.ts, Live/X.ts, impl/X.ts, …);
 *  2. X.impl.*, X.service.*, X.live.* next to the file;
 *  3. a nearby file that references X with `implements X`, `Layer.*(X` or `X.of(`.
 * Returns workspace-relative candidates in priority order.
 */
export function findImplementationCandidates(workspaceRoot: string, filePath: string): string[] {
    const abs = toAbs(workspaceRoot, filePath);
    const dir = path.dirname(abs);
    const parent = path.dirname(dir);
    const ext = path.extname(abs);
    const base = path.basename(abs, ext);
    const fileName = path.basename(abs);
    const out: string[] = [];
    const selfReal = realPath(abs);
    const rootReal = realPath(workspaceRoot);
    const push = (candidateAbs: string) => {
        if (!isFile(candidateAbs)) return;
        const real = realPath(candidateAbs);
        if (real.toLowerCase() === selfReal.toLowerCase()) return;
        const rel = toRel(rootReal, real);
        if (!out.some(o => o.toLowerCase() === rel.toLowerCase())) out.push(rel);
    };

    for (const name of IMPLEMENTATION_DIR_NAMES) {
        push(path.join(parent, name, fileName));
    }
    const siblingDirs = listDir(parent)
        .filter(d => d.isDirectory() && path.join(parent, d.name) !== dir && !SKIP_DIRS.has(d.name))
        .map(d => d.name)
        .sort();
    for (const name of siblingDirs) {
        push(path.join(parent, name, fileName));
    }

    const suffixPattern = new RegExp(`^${escapeRegExp(base)}\\.(${IMPLEMENTATION_SUFFIXES.join('|')})\\.[A-Za-z0-9]+$`, 'i');
    for (const entry of listDir(dir).filter(d => d.isFile()).map(d => d.name).sort()) {
        if (suffixPattern.test(entry)) push(path.join(dir, entry));
    }

    const symbol = escapeRegExp(base);
    const referencePatterns = [
        new RegExp(`\\bimplements\\s+(?:[\\w$]+\\s*,\\s*)*${symbol}\\b`),
        new RegExp(`\\bLayer\\.[A-Za-z]+\\(\\s*${symbol}\\b`),
        new RegExp(`\\b${symbol}\\.of\\(`),
    ];
    const searchRoot = path.resolve(workspaceRoot) === path.resolve(parent) || !path.resolve(parent).startsWith(path.resolve(workspaceRoot))
        ? dir
        : parent;
    const queue = [searchRoot];
    let scanned = 0;
    const referenced: string[] = [];
    while (queue.length > 0 && scanned < REFERENCE_SEARCH_MAX_FILES) {
        const current = queue.shift()!;
        for (const entry of listDir(current).sort((a, b) => a.name.localeCompare(b.name))) {
            const full = path.join(current, entry.name);
            if (entry.isDirectory()) {
                if (!SKIP_DIRS.has(entry.name)) queue.push(full);
                continue;
            }
            if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
            if (path.resolve(full) === path.resolve(abs)) continue;
            scanned++;
            const content = readText(full);
            if (!content || !new RegExp(`\\b${symbol}\\b`).test(content)) continue;
            if (referencePatterns.some(p => p.test(content))) referenced.push(full);
            if (scanned >= REFERENCE_SEARCH_MAX_FILES) break;
        }
    }
    for (const full of referenced) push(full);

    return out;
}

function checkFile(workspaceRoot: string, filePath: string): { ok: true; content: string } | { ok: false; reason: string } {
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

    return { ok: true, content };
}

/**
 * Select the top N files for sequential agent scanning.
 *
 * Algorithm:
 *  1. Start with recommendedScanOrder (or importantFiles if selected).
 *  2. Normalize paths to forward-slash workspace-relative.
 *  3. Remove duplicates.
 *  4. Filter out missing, empty, binary, and oversized files.
 *  5. Swap a types-only file for its implementation (`replaced`), or skip it
 *     when no implementation is found.
 *  6. Fill remaining slots from the other list if needed.
 *  7. Clamp topN to 1..20.
 *  8. Freeze the selection before returning.
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

    const buildEntry = (filePath: string, rank: number, replacedFrom?: string): SelectedBatchFile => {
        const norm = normalizePath(filePath);
        const info = importantMap.get(norm) ?? (replacedFrom ? importantMap.get(replacedFrom) : undefined);
        const entry: SelectedBatchFile = {
            filePath: norm,
            rank,
            role: info?.role as string | undefined,
            importance: info?.importance,
        };
        if (replacedFrom) entry.replaced = { from: replacedFrom, to: norm, reason: 'types only' };
        return entry;
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

        if (selected.length >= topN) return;

        if (detectDeclarationOnly(check.content)) {
            let implementationAlreadySelected = false;
            for (const candidate of findImplementationCandidates(workspaceRoot, norm)) {
                const candidateKey = candidate.toLowerCase();
                if ([...seen].some(s => s.toLowerCase() === candidateKey)) {
                    if (selected.some(s => s.filePath.toLowerCase() === candidateKey)) implementationAlreadySelected = true;
                    continue;
                }
                const implCheck = checkFile(workspaceRoot, candidate);
                if (!implCheck.ok || detectDeclarationOnly(implCheck.content)) continue;
                seen.add(candidate);
                selected.push(buildEntry(candidate, selected.length + 1, norm));
                return;
            }
            skipped.push({
                filePath: norm,
                reason: implementationAlreadySelected ? 'types only (implementation already selected)' : TYPES_ONLY_SKIP_REASON,
            });
            return;
        }

        selected.push(buildEntry(filePath, selected.length + 1));
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
