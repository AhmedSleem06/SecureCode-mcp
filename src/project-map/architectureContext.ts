/**
 * Architecture context — the structured output of the architecture scout
 * subagent and the cached input to later agent-scan runs.
 *
 * The architecture scout is triggered by `securecode.map action:architecture`.
 * It consumes the deterministic project map (endpoints, imports, call graph,
 * config, deps) plus a bounded set of file reads, and produces this context:
 *   - project type / frameworks / runtimes / package manager
 *   - ranked important files (entrypoints, auth, data, config, security controls)
 *   - trust boundaries (where untrusted input enters)
 *   - data-flow summaries (source → sink across the architecture)
 *   - security controls in place (and what's missing)
 *   - architecture-level risks
 *   - recommended scan order (which files to scan first)
 *
 * Cache lives at `.securecode/architecture-context.json`. Invalidates when:
 *   - the project map is rebuilt (builtAt changes)
 *   - the project map schema version changes
 *   - the requested depth differs (quick/standard/deep produce different ctx)
 *   - ARCHITECTURE_CONTEXT_VERSION bumps (prompt/logic change)
 *   - 7-day TTL
 *
 * agent-scan auto-loads a cached architecture context (if present and valid)
 * and passes it into the agent target so the vulnerability investigator starts
 * with project-wide context instead of having to discover it from scratch.
 */

import * as fs from 'fs';
import * as path from 'path';

const CACHE_DIR = '.securecode';
const CACHE_FILE = 'architecture-context.json';

/**
 * Bump when the architecture scout prompt or logic changes in a way that
 * would produce a different context for the same project. All cached
 * entries with an older version are invalidated.
 */
export const ARCHITECTURE_CONTEXT_VERSION = 1;

/** Cache TTL: 7 days. Older entries are re-derived. */
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// ── Public types ─────────────────────────────────────────────────────────────

export type ArchitectureDepth = 'quick' | 'standard' | 'deep';

export type FileRole =
    | 'entrypoint'
    | 'route_handler'
    | 'middleware'
    | 'authentication'
    | 'authorization'
    | 'data_access'
    | 'validation'
    | 'security_config'
    | 'config'
    | 'service'
    | 'repository'
    | 'model'
    | 'migration'
    | 'external_integration'
    | 'shared_helper'
    | 'dynamic_loader'
    | 'test'
    | 'dependency_manifest'
    | 'other';

export interface ImportantFile {
    /** Workspace-relative path. */
    file: string;
    role: FileRole;
    /** 0-100 importance. Higher = more security-critical. */
    importance: number;
    /** Why this file matters (1-3 short reasons). */
    reasons: string[];
    /** Functions/symbols in this file that are security-relevant, if known. */
    keySymbols?: string[];
}

export interface TrustBoundary {
    /** Where untrusted input enters (file:line or route path). */
    entry: string;
    /** What kind of input (HTTP body, query, cookie, file upload, WebSocket, CLI arg, env). */
    inputType: string;
    /** What validates/sanitizes it, if anything. */
    guard: string | null;
}

export interface DataFlowSummary {
    /** Short label, e.g. "user input → SQL query" or "cookie → session lookup". */
    label: string;
    /** Files the flow passes through, in order. */
    path: string[];
    /** Whether a guard is present at the sink. */
    guarded: boolean;
}

export interface SecurityControl {
    /** What control this is (auth, authorization, rate_limit, cors, csp, headers, input_validation, output_encoding, secrets_management). */
    kind: string;
    /** Where it's implemented (file or file:line). */
    location: string;
    /** Whether it covers the whole app or is partial. */
    coverage: 'full' | 'partial' | 'unknown';
    /** Notes on gaps, if any. */
    notes?: string;
}

export interface ArchitectureRisk {
    /** Short label. */
    title: string;
    /** Why it's a risk, in 1-2 sentences. */
    description: string;
    /** Files involved. */
    files: string[];
    /** Severity for triage purposes (not a vulnerability finding — an architecture-level concern). */
    severity: 'high' | 'medium' | 'low';
}

export interface ArchitectureContext {
    /** Schema version of this context (for cache invalidation). */
    version: number;
    /** Depth that produced this context. */
    depth: ArchitectureDepth;
    /** When the context was derived (ms epoch). */
    derivedAt: number;
    /** Project map builtAt when this was derived (invalidates on map rebuild). */
    projectMapBuiltAt: number;
    /** Project map schema version when this was derived. */
    projectMapVersion: number;

    // ── The interpretation ──────────────────────────────────────────────────
    project: {
        type: string;
        frameworks: string[];
        runtimes: string[];
        packageManager: string | null;
        languages: string[];
    };
    importantFiles: ImportantFile[];
    trustBoundaries: TrustBoundary[];
    dataFlows: DataFlowSummary[];
    securityControls: SecurityControl[];
    architectureRisks: ArchitectureRisk[];
    /** Files to scan first, in priority order (paths only). */
    recommendedScanOrder: string[];
    /** One-paragraph architecture summary for prompts. */
    summary: string;
    /** Scout's self-assessment of completeness. */
    completeness: 'full' | 'partial' | 'failed';
    /** What the scout couldn't cover, if partial/failed. */
    gaps?: string[];
}

// ── Cache entry ──────────────────────────────────────────────────────────────

interface ArchitectureCacheEntry {
    context: ArchitectureContext;
    storedAt: number;
}

interface ArchitectureCacheData {
    version: number;
    /** Keyed by depth — quick/standard/deep produce different contexts. */
    entries: Partial<Record<ArchitectureDepth, ArchitectureCacheEntry>>;
}

// ── Path helpers ────────────────────────────────────────────────────────────

function cachePath(workspaceRoot: string): string {
    return path.join(workspaceRoot, CACHE_DIR, CACHE_FILE);
}

// ── Read / Write ────────────────────────────────────────────────────────────

/**
 * Read the architecture cache. Returns null if the file doesn't exist,
 * is corrupt, or is a forward-incompatible version.
 */
export function readArchitectureCache(workspaceRoot: string): ArchitectureCacheData | null {
    const p = cachePath(workspaceRoot);
    try {
        if (!fs.existsSync(p)) return null;
        const raw = fs.readFileSync(p, 'utf8');
        const data = JSON.parse(raw) as ArchitectureCacheData;
        if (!data.version || data.version > ARCHITECTURE_CONTEXT_VERSION) {
            return null;
        }
        return data;
    } catch {
        return null;
    }
}

/**
 * Look up a cached architecture context by depth.
 * Returns null if not found, expired, or stale (project map changed).
 *
 * Stale check: the caller passes the CURRENT project map's builtAt + version.
 * If the cached entry was derived against a different map, it's invalid —
 * the architecture may have changed.
 */
export function getCachedArchitectureContext(
    workspaceRoot: string,
    depth: ArchitectureDepth,
    currentMapBuiltAt: number,
    currentMapVersion: number,
): ArchitectureContext | null {
    const cache = readArchitectureCache(workspaceRoot);
    if (!cache) return null;

    const entry = cache.entries[depth];
    if (!entry) return null;

    // Version check
    if (entry.context.version !== ARCHITECTURE_CONTEXT_VERSION) return null;

    // TTL check
    if (Date.now() - entry.storedAt > CACHE_TTL_MS) return null;

    // Project map staleness check — if the map was rebuilt after the context
    // was derived, the context is stale.
    if (entry.context.projectMapBuiltAt !== currentMapBuiltAt) return null;
    if (entry.context.projectMapVersion !== currentMapVersion) return null;

    return entry.context;
}

/**
 * Write an architecture context to the cache, keyed by depth.
 */
export function writeCachedArchitectureContext(
    workspaceRoot: string,
    context: ArchitectureContext,
): void {
    const dir = path.join(workspaceRoot, CACHE_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    let cache: ArchitectureCacheData;
    const existing = readArchitectureCache(workspaceRoot);
    if (existing && existing.version === ARCHITECTURE_CONTEXT_VERSION) {
        cache = existing;
    } else {
        cache = { version: ARCHITECTURE_CONTEXT_VERSION, entries: {} };
    }

    // Prune expired entries
    const now = Date.now();
    for (const [k, e] of Object.entries(cache.entries)) {
        if (e && now - e.storedAt > CACHE_TTL_MS) {
            delete cache.entries[k as ArchitectureDepth];
        }
    }

    cache.entries[context.depth] = { context, storedAt: now };

    // Atomic write
    const p = cachePath(workspaceRoot);
    const tmp = p + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(cache, null, 2), 'utf8');
    fs.renameSync(tmp, p);
}

/**
 * Clear the architecture cache for a workspace (e.g., when the user requests
 * a fresh derivation with --no-cache).
 */
export function clearArchitectureCache(workspaceRoot: string): void {
    const p = cachePath(workspaceRoot);
    try {
        if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch { /* best effort */ }
}

/**
 * Format an architecture context into a compact string for injection into
 * the agent-scan target prompt. Returns empty string if context is empty.
 *
 * This is what the vulnerability investigator sees at the start of a scan —
 * a distilled view of the project's architecture so it doesn't have to
 * re-discover "where is auth?", "what's the data layer?", "what are the
 * entrypoints?" from scratch.
 */
export function formatArchitectureContextForPrompt(ctx: ArchitectureContext): string {
    if (!ctx || !ctx.importantFiles || ctx.importantFiles.length === 0) return '';

    const lines: string[] = ['Project architecture (from a prior architecture-scout run — use this as context, verify with tools when relevant):'];

    lines.push('');
    lines.push(`Project: ${ctx.project.type}`);
    if (ctx.project.frameworks.length) lines.push(`Frameworks: ${ctx.project.frameworks.join(', ')}`);
    if (ctx.project.runtimes.length) lines.push(`Runtimes: ${ctx.project.runtimes.join(', ')}`);
    if (ctx.project.packageManager) lines.push(`Package manager: ${ctx.project.packageManager}`);

    if (ctx.summary) {
        lines.push('');
        lines.push(`Summary: ${ctx.summary}`);
    }

    lines.push('');
    lines.push(`Important files (${ctx.importantFiles.length}, ranked by security importance):`);
    for (const f of ctx.importantFiles.slice(0, 30)) {
        lines.push(`  [${f.importance}] ${f.file} (${f.role}) — ${f.reasons.join('; ')}`);
    }
    if (ctx.importantFiles.length > 30) {
        lines.push(`  ... and ${ctx.importantFiles.length - 30} more (see architecture context)`);
    }

    if (ctx.trustBoundaries.length > 0) {
        lines.push('');
        lines.push(`Trust boundaries (${ctx.trustBoundaries.length}):`);
        for (const tb of ctx.trustBoundaries.slice(0, 15)) {
            lines.push(`  ${tb.entry} — input: ${tb.inputType} — guard: ${tb.guard || 'NONE'}`);
        }
    }

    if (ctx.securityControls.length > 0) {
        lines.push('');
        lines.push(`Security controls (${ctx.securityControls.length}):`);
        for (const sc of ctx.securityControls.slice(0, 15)) {
            lines.push(`  [${sc.coverage}] ${sc.kind} at ${sc.location}${sc.notes ? ` — ${sc.notes}` : ''}`);
        }
    }

    if (ctx.architectureRisks.length > 0) {
        lines.push('');
        lines.push(`Architecture-level risks (${ctx.architectureRisks.length}) — these are NOT vulnerability findings, they are structural concerns to investigate:`);
        for (const r of ctx.architectureRisks.slice(0, 10)) {
            lines.push(`  [${r.severity}] ${r.title}: ${r.description} (${r.files.join(', ')})`);
        }
    }

    if (ctx.recommendedScanOrder.length > 0) {
        lines.push('');
        lines.push(`Recommended scan order (first ${Math.min(10, ctx.recommendedScanOrder.length)}):`);
        for (const f of ctx.recommendedScanOrder.slice(0, 10)) {
            lines.push(`  ${f}`);
        }
    }

    return lines.join('\n');
}
