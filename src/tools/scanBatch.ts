/**
 * Batch scan tool — scans multiple files for vulnerabilities.
 *
 * Discovers scannable files from a directory or explicit file list, then
 * runs the full scan pipeline (Scout → Juror → Phase3) on each file
 * sequentially. Reports progress via the MCP progress notification.
 * Stops early on credit exhaustion or maxFiles cap.
 */
import * as fs from 'fs';
import * as path from 'path';
import { ApiClient } from '../api/client';
import type { ScanResponse, FinalFinding, ScanFinding } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace, inferLanguage } from '../utils/files';
import { readSecurecodeIgnore, isIgnored, isSecretFileName, SKIP_DIRS } from '../utils/ignore';
import { findSinks } from '../project-map/sinkFinder';
import { trackTaint } from '../project-map/taintTracker';
import { evaluateGuards } from '../project-map/guardEvaluator';
import type { AttackType } from '../project-map/guardPatterns';
import { grammarForFile } from '../project-map/parserLoader';

const MAX_FILE_SIZE = 1024 * 1024; // 1 MB
const DEFAULT_MAX_FILES = 200;

/** Test file patterns — skipped by default to avoid wasting credits on non-production code. */
const TEST_FILE_PATTERNS = [
    /\.test\.(ts|js|tsx|jsx|mjs|cjs)$/i,
    /\.spec\.(ts|js|tsx|jsx|mjs|cjs)$/i,
    /__tests__\//i,
    /\.e2e\.test\.(ts|js)$/i,
];

function isTestFile(relPath: string): boolean {
    return TEST_FILE_PATTERNS.some(re => re.test(relPath));
}

interface ScanBatchArgs {
    directory?: string;
    filePaths?: string[];
    maxFiles?: number;
    includeTests?: boolean;
    _progress?: (progress: number, total: number, message: string) => void;
}

interface FileResult {
    filePath: string;
    scanId?: string;
    findings: any[];
    degraded?: boolean;
    scanCredits?: number;
    error?: string;
}

interface SkippedFile {
    path: string;
    reason: 'ignored' | 'unsupported' | 'secret' | 'too_large' | 'empty' | 'error' | 'test_file';
}

/** Discover scannable files under a directory, respecting .securecodeignore and secret files. */
function discoverFiles(
    root: string,
    dir: string,
    ignorePatterns: Set<string>,
    maxFiles: number,
    includeTests: boolean,
): { files: string[]; skipped: SkippedFile[] } {
    const files: string[] = [];
    const skipped: SkippedFile[] = [];
    const stack: string[] = [dir];
    let count = 0;

    while (stack.length > 0 && count < maxFiles) {
        const current = stack.pop()!;
        let entries: fs.Dirent[];
        try {
            entries = fs.readdirSync(current, { withFileTypes: true });
        } catch { continue; }

        for (const entry of entries) {
            if (count >= maxFiles) break;
            const fullPath = path.join(current, entry.name);
            const relPath = path.relative(root, fullPath).replace(/\\/g, '/');

            if (entry.isDirectory()) {
                if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                    stack.push(fullPath);
                }
                continue;
            }

            if (entry.isFile()) {
                if (isIgnored(relPath, ignorePatterns)) {
                    skipped.push({ path: relPath, reason: 'ignored' });
                    continue;
                }
                if (isSecretFileName(fullPath)) {
                    skipped.push({ path: relPath, reason: 'secret' });
                    continue;
                }
                if (!includeTests && isTestFile(relPath)) {
                    skipped.push({ path: relPath, reason: 'test_file' });
                    continue;
                }
                const lang = inferLanguage(fullPath);
                if (!lang) {
                    skipped.push({ path: relPath, reason: 'unsupported' });
                    continue;
                }
                files.push(relPath);
                count++;
            }
        }
    }

    return { files: files.sort(), skipped };
}

/** Run deterministic analysis on a file and return the deterministic facts. */
async function runDeterministicAnalysis(
    code: string,
    grammar: string,
    filePath: string,
): Promise<{ sinks?: any[]; taint?: any[]; guards?: any[] } | undefined> {
    if (grammar === 'unknown') return undefined;
    try {
        const taint = await trackTaint(code, grammar as any);
        const sinks = await findSinks(code, grammar as any, taint);

        let guards: any[] | undefined;
        const attackTypes = new Set<AttackType>();
        for (const s of sinks) attackTypes.add(s.canonicalType as AttackType);
        for (const t of taint) attackTypes.add(t.canonicalType as AttackType);
        if (attackTypes.size > 0) {
            guards = await evaluateGuards(
                [{ source: code, name: filePath }],
                [...attackTypes],
                grammar as any,
            );
            if (guards.length === 0) guards = undefined;
        }

        if (sinks.length > 0 || taint.length > 0 || (guards && guards.length > 0)) {
            return {
                ...(sinks.length > 0 && { sinks }),
                ...(taint.length > 0 && { taint }),
                ...(guards && { guards }),
            };
        }
    } catch {
        // Best-effort — tree-sitter may be unavailable.
    }
    return undefined;
}

/** Map a scan response to the per-file findings shape (same as toolScan). */
function mapFindings(data: ScanResponse): any[] {
    const findings: (FinalFinding | ScanFinding)[] =
        data.scanType === 'advanced' && data.finalFindings
            ? data.finalFindings
            : data.findings || [];
    return findings.map((f: any) => ({
        type: f.type || f.check_id,
        severity: f.severity || f.extra?.severity,
        location: f.location || {
            line_start: f.start?.line,
            line_end: f.end?.line ?? f.start?.line,
        },
        message: f.message || f.extra?.message,
        evidence: f.evidence_snippet,
        confidence: f.confidence,
        why: f.why_real,
        fixStrategy: f.fix_strategy,
        fixSnippet: f.fix_snippet,
    }));
}

export async function toolScanBatch(ctx: ServerContext, args: any): Promise<unknown> {
    const opts = args as ScanBatchArgs;
    const progressFn = opts._progress;
    const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;
    const includeTests = opts.includeTests ?? false;

    // Determine the file list.
    let files: string[] = [];
    let skipped: SkippedFile[] = [];

    if (opts.filePaths && Array.isArray(opts.filePaths) && opts.filePaths.length > 0) {
        const ignorePatterns = readSecurecodeIgnore(ctx.workspaceRoot);
        for (const fp of opts.filePaths) {
            const relPath = fp.replace(/\\/g, '/');
            if (isIgnored(relPath, ignorePatterns)) {
                skipped.push({ path: relPath, reason: 'ignored' });
                continue;
            }
            const absPath = path.join(ctx.workspaceRoot, relPath);
            if (isSecretFileName(absPath)) {
                skipped.push({ path: relPath, reason: 'secret' });
                continue;
            }
            if (!includeTests && isTestFile(relPath)) {
                skipped.push({ path: relPath, reason: 'test_file' });
                continue;
            }
            if (!inferLanguage(absPath)) {
                skipped.push({ path: relPath, reason: 'unsupported' });
                continue;
            }
            files.push(relPath);
        }
    } else if (opts.directory) {
        const dirAbs = path.resolve(ctx.workspaceRoot, opts.directory);
        const ignorePatterns = readSecurecodeIgnore(ctx.workspaceRoot);
        const result = discoverFiles(ctx.workspaceRoot, dirAbs, ignorePatterns, maxFiles, includeTests);
        files = result.files;
        skipped = result.skipped;
    } else {
        throw Object.assign(
            new Error('Provide either "directory" or "filePaths".'),
            { code: -32602 },
        );
    }

    if (files.length === 0) {
        return {
            scanned: 0,
            skipped,
            results: [],
            summary: { totalFindings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 } },
            stoppedEarly: false,
            stopReason: null,
            remainingCredits: null,
        };
    }

    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const results: FileResult[] = [];
    let totalFindings = 0;
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    let stoppedEarly = false;
    let stopReason: string | null = null;
    let remainingCredits: number | null = null;

    let lastProgress = 0;
    const total = Math.min(files.length, maxFiles);

    for (let i = 0; i < total; i++) {
        const filePath = files[i];

        // Progress reporting (throttled to every 5% or every 10 files).
        const pct = Math.floor(((i + 1) / total) * 100);
        if (pct >= lastProgress + 5 || (i + 1) % 10 === 0 || i === 0 || i === total - 1) {
            lastProgress = pct;
            progressFn?.(i + 1, total, `Scanning ${path.basename(filePath)} (${i + 1}/${total})`);
        }

        try {
            const absPath = path.join(ctx.workspaceRoot, filePath);
            const stat = fs.statSync(absPath);
            if (stat.size > MAX_FILE_SIZE) {
                skipped.push({ path: filePath, reason: 'too_large' });
                continue;
            }
            const code = fs.readFileSync(absPath, 'utf8');
            if (code.length === 0) {
                skipped.push({ path: filePath, reason: 'empty' });
                continue;
            }

            const language = inferLanguage(absPath)!;
            const grammar = grammarForFile(filePath);
            const deterministicFacts = await runDeterministicAnalysis(code, grammar, filePath);

            const data = await client.postJson<ScanResponse>('/scan', {
                code,
                language,
                filePath,
                scanDepth: 'auto',
                ...(deterministicFacts && { deterministicFacts }),
            });

            const findings = mapFindings(data);
            totalFindings += findings.length;
            for (const f of findings) {
                const sev = (f.severity || '').toLowerCase();
                if (sev === 'critical') bySeverity.critical++;
                else if (sev === 'high') bySeverity.high++;
                else if (sev === 'medium') bySeverity.medium++;
                else if (sev === 'low') bySeverity.low++;
            }

            results.push({
                filePath,
                scanId: data.scanId,
                findings,
                degraded: data.degraded,
                scanCredits: data.scanCredits,
            });

            remainingCredits = data.scanCredits ?? remainingCredits;

            // Credit guard — stop if exhausted.
            if (data.scanCredits !== undefined && data.scanCredits <= 0) {
                stoppedEarly = true;
                stopReason = 'no_credits';
                break;
            }
        } catch (err: any) {
            results.push({
                filePath,
                findings: [],
                error: err.message || String(err),
            });
        }
    }

    if (results.length >= maxFiles && !stoppedEarly) {
        stoppedEarly = true;
        stopReason = 'max_files';
    }

    return {
        scanned: results.length,
        skipped,
        results,
        summary: { totalFindings, bySeverity },
        stoppedEarly,
        stopReason,
        remainingCredits,
    };
}
