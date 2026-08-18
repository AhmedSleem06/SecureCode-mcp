/**
 * securecode.agent-scan MCP tool — agent-mode scan with exploit verification.
 *
 * An AI investigator that reads files, traces data flows, checks guards,
 * and compares endpoint policies to find vulnerabilities. Each high/critical
 * finding is then verified by the verify subagent — a round-based loop that
 * generates a local integration test, runs it on the user's machine, and
 * analyzes the output for a PROVEN/UNPROVEN/INCONCLUSIVE verdict.
 *
 * Flow:
 *   1. Resolve code + language from filePath
 *   2. Build endpoint context from the project map
 *   3. Run the agent loop (POST /agent/scan/start + /step loop)
 *   4. For each finding → runVerifyLoop (generate test → run locally → analyze)
 *   5. Generate fixes for proven/suspected findings
 *   6. Return result with proven stamps
 */

import { ApiClient } from '../api/client';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';
import { getEndpointContextForFile, getRelatedFilesForFile } from '../project-map/mapContext';
import { getCachedScan, writeCachedScan } from '../project-map/scanCache';
import { loadAgentMemory, formatMemoryForPrompt } from '../project-map/agentMemory';
import { runAgentScan } from '../attack/agentScanLoop';
import { runVerifyLoop } from '../attack/verifyLoop';
import type { AgentScanFinding, AgentScanTarget } from '../attack/agentScanProtocol';
import type { SandboxProveResponse, FixResponse } from '../api/types';

interface ProvenFinding extends AgentScanFinding {
    proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE' | 'SKIPPED';
    provenReason?: string;
}

/** Prove high/critical/medium findings — skip only low. */
function shouldProve(finding: AgentScanFinding): boolean {
    return finding.severity === 'critical' || finding.severity === 'high' || finding.severity === 'medium';
}

export async function toolAgentScan(ctx: ServerContext, args: any): Promise<unknown> {
    const progress = args._progress as ((progress: number, total: number, message: string) => void) | undefined;

    // 1. Resolve code + language
    let code: string;
    let language: string;
    let filePath: string | undefined;

    if (args.filePath) {
        filePath = args.filePath;
        const fileResult = readFileFromWorkspace(ctx.workspaceRoot, args.filePath);
        code = fileResult.code;
        language = args.language || fileResult.language;
    } else if (args.code) {
        code = args.code;
        language = args.language || 'javascript';
    } else {
        throw new Error('Either filePath or code must be provided.');
    }

    // 1b. Validate the code — empty, binary, or too-large files cause confusing
    // downstream errors (HTTP 400/413) that the user can't interpret.
    // The API server has a 2MB body limit; we cap at 1.5MB to leave room for
    // the JSON envelope and transcript.
    const MAX_FILE_BYTES = 1_500_000;
    if (code.trim().length === 0) {
        return {
            status: 'completed',
            summary: 'File is empty — nothing to scan.',
            agentFindings: [],
            findings: [],
            stepsUsed: 0,
            costSpentUsd: 0,
            transcript: [],
            cached: false,
            provenCount: 0,
        };
    }
    // Binary file detection: if the first 1000 bytes contain a NUL byte, it's
    // almost certainly binary (compiled, image, archive). Sending it to the LLM
    // would produce garbage results.
    const headBytes = Buffer.from(code.slice(0, 1000), 'utf8');
    if (headBytes.includes(0)) {
        throw new Error('Cannot scan binary file. SecureCode only scans text source files (.ts, .js, .py, etc.).');
    }
    if (Buffer.byteLength(code, 'utf8') > MAX_FILE_BYTES) {
        const sizeMB = (Buffer.byteLength(code, 'utf8') / 1_000_000).toFixed(1);
        throw new Error(`File too large (${sizeMB}MB). Maximum is 1.5MB. Split the file or scan a specific section using the API directly.`);
    }

    // 2. Build endpoint context + related files from the project map
    let endpointContext: any[] = [];
    let relatedFiles: any[] = [];
    if (filePath) {
        try {
            const absPath = path.isAbsolute(filePath)
                ? filePath
                : path.join(ctx.workspaceRoot, filePath);
            const [eps, rels] = await Promise.all([
                getEndpointContextForFile(filePath, ctx.workspaceRoot),
                getRelatedFilesForFile(absPath, ctx.workspaceRoot),
            ]);
            endpointContext = eps;
            relatedFiles = rels;
        } catch {
            // best-effort — proceed without context
        }
    }

    // 2b. Check scan cache — if the file hasn't changed, return cached results
    const skipCacheRead = !!args._noCache;
    const useCache = !!filePath;
    if (useCache && !skipCacheRead) {
        try {
            const cached = getCachedScan(ctx.workspaceRoot, filePath!, code);
            if (cached) {
                if (progress) progress(1, 1, 'Cached result — file unchanged since last scan.');
                return {
                    status: cached.status,
                    summary: cached.summary || 'Agent completed (cached).',
                    agentFindings: cached.findings,
                    findings: [],
                    stepsUsed: cached.stepsUsed,
                    costSpentUsd: 0,
                    transcript: [],
                    cached: true,
                    provenCount: (cached.findings as any[]).filter((f: any) => f.proven === 'PROVEN').length,
                };
            }
        } catch (err: any) {
            // Cache read failure (corrupt file, permissions, etc) should NOT
            // block the scan — just skip the cache and proceed.
            console.warn(`[Agent Scan] Cache read skipped: ${err?.message || err}`);
        }
    }

    // 3. Run the agent loop
    // Load workspace memory (false positives + known facts) to inject into target
    let workspaceMemory: string | undefined;
    try {
        const memory = loadAgentMemory(ctx.workspaceRoot);
        workspaceMemory = formatMemoryForPrompt(memory) || undefined;
    } catch {
        // best-effort — proceed without memory
    }

    const target: AgentScanTarget = {
        filePath: filePath || 'inline-code',
        language,
        fileContent: code,
        endpointContext,
        workspaceMemory,
    };

    const agentResult = await runAgentScan(ctx, target, {
        signal: (args as any)._signal as AbortSignal | undefined,
        onProgress: (steps, max, msg) => {
            if (progress) progress(steps, max, msg);
        },
    });

    if (agentResult.status === 'spawn_failed') {
        throw new Error(agentResult.error || 'Agent scan failed to start.');
    }

    // 4. Verify each finding via the verify subagent (replaces sandbox prove + juror)
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const provenFindings: ProvenFinding[] = [];

    const proveable = agentResult.findings.filter(shouldProve);
    if (proveable.length > 0 && progress) {
        progress(0, proveable.length, `Verifying ${proveable.length} finding(s)...`);
    }

    let proveIdx = 0;
    for (const finding of agentResult.findings) {
        if (!shouldProve(finding)) {
            provenFindings.push({ ...finding, proven: 'SKIPPED', provenReason: 'Low severity — not verified' });
            continue;
        }

        if (progress) {
            proveIdx++;
            progress(proveIdx, proveable.length, `Verifying ${finding.type} at line ${finding.line}...`);
        }

        try {
            const result = await runVerifyLoop({
                finding: {
                    type: finding.type,
                    line: finding.line,
                    lineEnd: finding.lineEnd,
                    evidence: finding.evidence,
                    why: finding.why,
                    severity: finding.severity,
                },
                filePath: filePath || '',
                code,
                relatedFiles: relatedFiles.map(rf => ({
                    filePath: rf.filePath,
                    content: rf.content,
                    relationship: rf.relationship,
                })),
                workspaceRoot: ctx.workspaceRoot,
                language,
                client,
                onProgress: (round, maxR, msg) => {
                    if (progress) progress(proveIdx, proveable.length, `Verify round ${round}/${maxR}: ${msg}`);
                },
            });

            provenFindings.push({
                ...finding,
                proven: result.verdict,
                provenReason: result.reason,
            });
        } catch (err: any) {
            console.warn(`[Agent Scan] Verify loop failed: ${err.message}. Falling back to sandbox prove.`);
            try {
                const proveResp = await client.postJson<SandboxProveResponse>('/sandbox/prove', {
                    code,
                    language,
                    vulnerabilityType: finding.type,
                    line: finding.line,
                    lineEnd: finding.lineEnd,
                    evidence: finding.evidence,
                    why: finding.why,
                });
                provenFindings.push({
                    ...finding,
                    proven: proveResp.proven,
                    provenReason: proveResp.rationale || proveResp.skipReason || proveResp.sandbox?.reason,
                });
            } catch (err2: any) {
                provenFindings.push({
                    ...finding,
                    proven: 'INCONCLUSIVE',
                    provenReason: `Verify failed: ${err.message}; Sandbox fallback also failed: ${err2.message}`,
                });
            }
        }
    }

    // 4b. Generate fixes for proven/suspected findings
    const fixableFindings = provenFindings.filter(f =>
        f.proven === 'PROVEN' || (f.proven !== 'UNPROVEN' && f.confidence >= 60)
    );

    if (fixableFindings.length > 0 && progress) {
        progress(0, fixableFindings.length, `Generating fixes for ${fixableFindings.length} finding(s)...`);
    }

    let fixIdx = 0;
    for (const finding of fixableFindings) {
        if (progress) {
            fixIdx++;
            progress(fixIdx, fixableFindings.length, `Fixing ${finding.type} at line ${finding.line}...`);
        }

        try {
            const fixResp = await client.postJson<FixResponse>('/fix', {
                code,
                language,
                vulnerability: {
                    type: finding.type,
                    line_start: finding.line,
                    line_end: finding.lineEnd || finding.line,
                    evidence_snippet: finding.evidence,
                },
            });

            if (fixResp.fixed_code) {
                finding.fix = {
                    fixedCode: fixResp.fixed_code,
                    replaceRange: { start_line: finding.line, end_line: finding.lineEnd || finding.line },
                    fixSummary: fixResp.fix_summary || '',
                    importsNeeded: fixResp.imports_needed,
                    confidence: fixResp.confidence,
                };
            }
        } catch (err: any) {
            // Best-effort — finding stays without fix
            console.warn(`[Agent Scan] Fix generation failed for ${finding.type} at L${finding.line}: ${err.message}`);
        }
    }

    // 5. Write to cache before returning
    if (useCache) {
        try {
            writeCachedScan(ctx.workspaceRoot, filePath!, code, {
                findings: provenFindings,
                status: agentResult.status,
                summary: agentResult.summary,
                stepsUsed: agentResult.stepsUsed,
                costSpentUsd: agentResult.costSpentUsd,
            });
        } catch (err: any) {
            console.warn(`[Agent Scan] Cache write skipped: ${err?.message || err}`);
        }
    }

    // 6. Return result — the verify subagent IS the verifier (no separate Juror call)
    return {
        status: agentResult.status,
        summary: agentResult.summary,
        agentFindings: provenFindings,
        verifiedFindings: provenFindings.filter(f => f.proven === 'PROVEN'),
        allFindings: [],
        stepsUsed: agentResult.stepsUsed,
        costSpentUsd: agentResult.costSpentUsd,
        transcript: agentResult.transcript,
        provenCount: provenFindings.filter(f => f.proven === 'PROVEN').length,
        unprovenCount: provenFindings.filter(f => f.proven === 'UNPROVEN').length,
        inconclusiveCount: provenFindings.filter(f => f.proven === 'INCONCLUSIVE').length,
        notReproducibleCount: provenFindings.filter(f => f.proven === 'NOT_REPRODUCIBLE').length,
        skippedCount: provenFindings.filter(f => f.proven === 'SKIPPED').length,
    };
}
