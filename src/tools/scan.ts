import * as fs from 'fs';
import * as path from 'path';
import { ApiClient } from '../api/client';
import type { ScanResponse, FinalFinding, ScanFinding } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace, inferLanguage } from '../utils/files';
import { findSinks } from '../project-map/sinkFinder';
import { trackTaint } from '../project-map/taintTracker';
import { evaluateGuards } from '../project-map/guardEvaluator';
import type { AttackType } from '../project-map/guardPatterns';
import { grammarForFile } from '../project-map/parserLoader';
import { getEndpointContextForFile, getRelatedFilesForFile } from '../project-map/mapContext';

export async function toolScan(ctx: ServerContext, args: any): Promise<unknown> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });

    let code: string | undefined = args.code;
    let language: string | undefined = args.language;
    const filePath = args.filePath as string | undefined;

    if (!code && filePath) {
        const file = readFileFromWorkspace(ctx.workspaceRoot, filePath);
        code = file.code;
        language = language || file.language;
    }

    if (!code) {
        throw Object.assign(new Error('Provide code or filePath.'), { code: -32602 });
    }
    if (!language) {
        throw Object.assign(new Error('Provide language or filePath with a known extension.'), { code: -32602 });
    }

    // ── Cross-file context: endpointContext + relatedFiles ──────────────
    // The extension sends these from its Project Map; the MCP now does the
    // same so the API's Scout and Juror can see the middleware, call-graph
    // callees, and imports the scanned file depends on. Best-effort: if
    // the map can't be built or the file isn't in it, both are omitted and
    // the scan proceeds without cross-file context.
    let endpointContext: any[] | undefined;
    let relatedFiles: any[] | undefined;
    if (filePath && ctx.workspaceRoot) {
        try {
            const absPath = path.isAbsolute(filePath)
                ? filePath
                : path.join(ctx.workspaceRoot, filePath);
            const [eps, rels] = await Promise.all([
                getEndpointContextForFile(absPath, ctx.workspaceRoot),
                getRelatedFilesForFile(absPath, ctx.workspaceRoot),
            ]);
            if (eps.length > 0) endpointContext = eps;
            if (rels.length > 0) relatedFiles = rels;
        } catch {
            // Best-effort: map building or file resolution may fail.
        }
    }

    // Phase B/C/E: AST-based sink finder + taint tracker + guard evaluator.
    // Runs locally via tree-sitter and attaches deterministic facts to the
    // scan request. When relatedFiles are available, the guard evaluator
    // sees ALL files (scanned file + related files) so it can detect guards
    // in middleware that protect the scanned sink.
    //
    // Taint runs first so its results can feed the sink finder's
    // requireUserSource gate — this catches indirect flows like
    // `const url = req.query.url; fetch(url)` that a local text check misses.
    let deterministicFacts: {
        sinks?: Awaited<ReturnType<typeof findSinks>>;
        taint?: Awaited<ReturnType<typeof trackTaint>>;
        guards?: Awaited<ReturnType<typeof evaluateGuards>>;
    } | undefined;
    if (filePath) {
        const grammar = grammarForFile(filePath);
        if (grammar !== 'unknown') {
            try {
                const taint = await trackTaint(code, grammar);
                const sinks = await findSinks(code, grammar, taint);

                // Phase E: evaluate guards from the scanned file AND related
                // files. When relatedFiles are available, the guard evaluator
                // can see middleware defined in other modules — the biggest
                // source of false positives is a guard in a different file.
                let guards: Awaited<ReturnType<typeof evaluateGuards>> | undefined;
                const attackTypes = new Set<AttackType>();
                for (const s of sinks) attackTypes.add(s.canonicalType as AttackType);
                for (const t of taint) attackTypes.add(t.canonicalType as AttackType);
                if (attackTypes.size > 0) {
                    const guardSources = [{ source: code, name: filePath }];
                    if (relatedFiles) {
                        for (const rf of relatedFiles) {
                            guardSources.push({ source: rf.content, name: rf.filePath });
                        }
                    }
                    guards = await evaluateGuards(
                        guardSources,
                        [...attackTypes],
                        grammar,
                    );
                    if (guards.length === 0) guards = undefined;
                }

                if (sinks.length > 0 || taint.length > 0 || (guards && guards.length > 0)) {
                    deterministicFacts = {
                        ...(sinks.length > 0 && { sinks }),
                        ...(taint.length > 0 && { taint }),
                        ...(guards && { guards }),
                    };
                }
            } catch {
                // Best-effort: tree-sitter may be unavailable.
            }
        }
    }

    const data = await client.postJson<ScanResponse>('/scan', {
        code,
        language,
        ...(filePath ? { filePath } : {}),
        scanDepth: (args.scanDepth as 'fast' | 'deep' | 'auto') || 'auto',
        ...(deterministicFacts && { deterministicFacts }),
        ...(endpointContext && { endpointContext }),
        ...(relatedFiles && { workspaceHints: { relatedFiles } }),
    });

    const findings: (FinalFinding | ScanFinding)[] =
        (data.scanType === 'advanced' || data.scanType === 'fast') && data.finalFindings
            ? data.finalFindings
            : data.findings || [];

    return {
        scanType: data.scanType,
        scanId: data.scanId,
        findings: findings.map((f: any) => ({
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
        })),
        scanSummary: data.scanSummary,
        degraded: data.degraded,
        remainingScans: data.remainingAIScans,
        plan: data.plan,
        scanCredits: data.scanCredits,
    };
}
