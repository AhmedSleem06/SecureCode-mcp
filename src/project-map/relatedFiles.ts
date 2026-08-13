/**
 * Cross-file context for a single-file scan — MCP port of the extension's
 * relatedFiles.ts.
 *
 * Uses the Project Map (already built by `buildProjectMap`) to find
 * neighbouring files the scanned file depends on: middleware, call-graph
 * callees, and imports. These are shipped alongside the scanned file so
 * the API's Scout and Juror can see the guard that is in another file.
 *
 * Differences from the extension version:
 *   - No VS Code settings (getRelatedFilesLimit / getSkipSecretFiles) —
 *     constants are used directly.
 *   - No .gitignore loading — the MCP has no gitignore parser; secret files
 *     are filtered by `isSecretFileName` from utils/ignore.ts.
 */
import * as fs from 'fs';
import * as path from 'path';
import { isSecretFileName } from '../utils/ignore';
import type { FileRelationship, ProjectMap, RelatedFile } from './types';

export const RELATED_FILES_BYTE_BUDGET = 48 * 1024;
const MIN_USEFUL_BYTES = 2 * 1024;
const DEFAULT_LIMIT = 10;

const RANK: Record<FileRelationship, number> = {
    middleware: 0,
    route_handler: 1,
    imports: 2,
    imported_by: 3,
    shared_type: 4,
    config: 5,
};

interface Candidate {
    rel: string;
    relationship: FileRelationship;
}

function toRel(absolutePath: string, workspaceRoot: string): string {
    return path.relative(workspaceRoot, absolutePath).replace(/\\/g, '/');
}

function readFile(absolutePath: string): string | null {
    try {
        return fs.readFileSync(absolutePath, 'utf8');
    } catch {
        return null;
    }
}

function candidateExists(absolutePath: string): boolean {
    try {
        return fs.existsSync(absolutePath) && fs.statSync(absolutePath).isFile();
    } catch {
        return false;
    }
}

export function resolveSpec(
    spec: string,
    fromRel: string,
    workspaceRoot: string,
): string | null {
    if (!spec || spec === '?') return null;

    if (!spec.startsWith('.')) {
        const asWorkspacePath = path.join(workspaceRoot, spec);
        if (candidateExists(asWorkspacePath)) return toRel(asWorkspacePath, workspaceRoot);
        return null;
    }

    const base = path.resolve(path.dirname(path.join(workspaceRoot, fromRel)), spec);
    const candidates = [
        base + '.ts', base + '.tsx', base + '.js', base + '.jsx',
        base + '.mjs', base + '.cjs', base + '.py', base,
        path.join(base, 'index.ts'), path.join(base, 'index.tsx'),
        path.join(base, 'index.js'), path.join(base, '__init__.py'),
    ];
    for (const c of candidates) {
        if (!candidateExists(c)) continue;
        const rel = toRel(c, workspaceRoot);
        if (rel.startsWith('../') || path.isAbsolute(rel)) return null;
        return rel;
    }
    return null;
}

function gatherCandidates(
    entryRel: string,
    map: ProjectMap,
    workspaceRoot: string,
): Candidate[] {
    const entry = map.files[entryRel];
    if (!entry) return [];

    const best = new Map<string, FileRelationship>();
    const order: string[] = [];

    const add = (spec: string | undefined, relationship: FileRelationship): void => {
        if (!spec) return;
        const rel = resolveSpec(spec, entryRel, workspaceRoot);
        if (!rel || rel === entryRel) return;
        const current = best.get(rel);
        if (current === undefined) {
            best.set(rel, relationship);
            order.push(rel);
            return;
        }
        if (RANK[relationship] < RANK[current]) best.set(rel, relationship);
    };

    for (const endpoint of entry.endpoints) {
        for (const mw of endpoint.middleware) add(mw.sourceFile, 'middleware');
    }
    for (const endpoint of entry.endpoints) {
        for (const node of endpoint.callGraph) add(node.calleeFile, 'route_handler');
    }
    for (const spec of Object.values(entry.imports ?? {})) add(spec, 'imports');

    return order
        .map(rel => ({ rel, relationship: best.get(rel)! }))
        .sort((a, b) => RANK[a.relationship] - RANK[b.relationship]);
}

function truncateToBudget(content: string, maxBytes: number): string {
    if (Buffer.byteLength(content, 'utf8') <= maxBytes) return content;
    const marker = '\n// ... [truncated by SecureCode: related-file budget reached] ...\n';
    const room = maxBytes - Buffer.byteLength(marker, 'utf8');
    if (room <= 0) return marker;

    const lines = content.split('\n');
    const kept: string[] = [];
    let used = 0;
    for (const line of lines) {
        const cost = Buffer.byteLength(line + '\n', 'utf8');
        if (used + cost > room) break;
        kept.push(line);
        used += cost;
    }
    return kept.join('\n') + marker;
}

export interface CollectRelatedFilesOptions {
    filePath: string;
    workspaceRoot: string;
    map: ProjectMap;
    limit?: number;
    byteBudget?: number;
}

export function collectRelatedFiles(options: CollectRelatedFilesOptions): RelatedFile[] {
    const {
        filePath,
        workspaceRoot,
        map,
        limit = DEFAULT_LIMIT,
        byteBudget = RELATED_FILES_BYTE_BUDGET,
    } = options;

    if (limit <= 0 || byteBudget <= 0) return [];
    if (!workspaceRoot) return [];

    const entryRel = toRel(filePath, workspaceRoot);
    if (entryRel.startsWith('../') || path.isAbsolute(entryRel)) return [];

    const candidates = gatherCandidates(entryRel, map, workspaceRoot);
    if (candidates.length === 0) return [];

    const out: RelatedFile[] = [];
    let remaining = byteBudget;

    for (const candidate of candidates) {
        if (out.length >= limit || remaining < MIN_USEFUL_BYTES) break;

        const absolute = path.join(workspaceRoot, candidate.rel);

        if (isSecretFileName(absolute)) continue;

        const content = readFile(absolute);
        if (content === null || content.trim() === '') continue;

        const size = Buffer.byteLength(content, 'utf8');
        const body = size <= remaining ? content : truncateToBudget(content, remaining);
        remaining -= Buffer.byteLength(body, 'utf8');

        out.push({
            filePath: candidate.rel,
            content: body,
            relationship: candidate.relationship,
        });
    }

    return out;
}
