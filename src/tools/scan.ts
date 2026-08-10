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

    // Phase B/C/E: AST-based sink finder + taint tracker + guard evaluator.
    // Runs locally via tree-sitter and attaches deterministic facts to the
    // scan request. The MCP has no related-files infrastructure, so the
    // guard evaluator only evaluates guards found in the scanned file itself.
    let deterministicFacts: {
        sinks?: Awaited<ReturnType<typeof findSinks>>;
        taint?: Awaited<ReturnType<typeof trackTaint>>;
        guards?: Awaited<ReturnType<typeof evaluateGuards>>;
    } | undefined;
    if (filePath) {
        const grammar = grammarForFile(filePath);
        if (grammar !== 'unknown') {
            try {
                const [sinks, taint] = await Promise.all([
                    findSinks(code, grammar),
                    trackTaint(code, grammar),
                ]);

                // Phase E: evaluate guards from the scanned file itself against
                // the attack types found by the sink finder + taint tracker.
                let guards: Awaited<ReturnType<typeof evaluateGuards>> | undefined;
                const attackTypes = new Set<AttackType>();
                for (const s of sinks) attackTypes.add(s.canonicalType as AttackType);
                for (const t of taint) attackTypes.add(t.canonicalType as AttackType);
                if (attackTypes.size > 0) {
                    guards = await evaluateGuards(
                        [{ source: code, name: filePath }],
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
        scanDepth: 'auto',
        ...(deterministicFacts && { deterministicFacts }),
    });

    const findings: (FinalFinding | ScanFinding)[] =
        data.scanType === 'advanced' && data.finalFindings
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
