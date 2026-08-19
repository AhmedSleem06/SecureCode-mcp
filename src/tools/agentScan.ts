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
import {
    getCachedScan,
    writeCachedScan,
    computeMemoryFingerprint,
    filterCachedFindingsAgainstMemory,
} from '../project-map/scanCache';
import { loadAgentMemory, formatMemoryForPrompt } from '../project-map/agentMemory';
import { getCapability, evidenceLevelTag } from '../project-map/capabilityRegistry';
import { runAgentScan } from '../attack/agentScanLoop';
import { runVerifyLoop } from '../attack/verifyLoop';
import { VerifyBudgetTracker, defaultVerifyBudget, type VerifyBudget } from '../attack/agentScanProtocol';
import type { AgentScanFinding, AgentScanTarget } from '../attack/agentScanProtocol';
import type { SandboxProveResponse, FixResponse } from '../api/types';

interface ProvenFinding extends AgentScanFinding {
    proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE' | 'SKIPPED';
    provenReason?: string;
    evidenceLevel?: string;
    originalConfidence?: number;
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

    // 2b. Load workspace memory BEFORE the cache check.
    //
    // Memory (dismissed false positives + known facts) is part of the cache
    // key now — a cache hit on an unchanged file must still respect findings
    // the user has dismissed since the cache was written. We load memory
    // first, compute its fingerprint, and:
    //   - On cache hit with a matching fingerprint: return as-is.
    //   - On cache hit with a different fingerprint (or no fingerprint, for
    //     pre-v22 entries): filter the cached findings against current
    //     memory before returning.
    //   - On cache miss: pass the memory into the agent target as before.
    let workspaceMemory: string | undefined;
    let memoryFingerprint = '';
    let falsePositives: Array<{ findingType: string; evidenceHash: string }> = [];
    try {
        const memory = loadAgentMemory(ctx.workspaceRoot);
        workspaceMemory = formatMemoryForPrompt(memory) || undefined;
        falsePositives = memory.falsePositives.map(fp => ({ findingType: fp.findingType, evidenceHash: fp.evidenceHash }));
        memoryFingerprint = computeMemoryFingerprint(falsePositives);
    } catch {
        // best-effort — proceed without memory
    }

    // 2c. Check scan cache — if the file hasn't changed, return cached results
    const skipCacheRead = !!args._noCache;
    const useCache = !!filePath;
    if (useCache && !skipCacheRead) {
        try {
            const cached = getCachedScan(ctx.workspaceRoot, filePath!, code);
            if (cached) {
                // Filter against current memory. If the fingerprint matches
                // what was stored at write time, no findings need to be
                // dropped — we can return the cached list as-is. If it
                // differs (or the entry predates memoryHash), filter.
                let filteredFindings = cached.findings;
                if (cached.memoryHash !== memoryFingerprint) {
                    filteredFindings = filterCachedFindingsAgainstMemory(cached.findings, falsePositives);
                }
                if (progress) progress(1, 1, 'Cached result — file unchanged since last scan.');
                return {
                    status: cached.status,
                    summary: cached.summary || 'Agent completed (cached).',
                    agentFindings: filteredFindings,
                    findings: [],
                    stepsUsed: cached.stepsUsed,
                    costSpentUsd: 0,
                    transcript: [],
                    cached: true,
                    provenCount: (filteredFindings as any[]).filter((f: any) => f.proven === 'PROVEN').length,
                };
            }
        } catch (err: any) {
            // Cache read failure (corrupt file, permissions, etc) should NOT
            // block the scan — just skip the cache and proceed.
            console.warn(`[Agent Scan] Cache read skipped: ${err?.message || err}`);
        }
    }

    // 3. Run the agent loop
    // (workspaceMemory was loaded above)

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

    // Aggregate verify budget — prevents Phase 2 from spawning unbounded
    // LLM calls (8 rounds × N findings × 2 calls) and unbounded wall-clock.
    const verifyBudget: VerifyBudget = defaultVerifyBudget();
    const verifyTracker = new VerifyBudgetTracker(verifyBudget);
    const abortSignal = (args as any)._signal as AbortSignal | undefined;

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

        // Pre-flight budget check — stop before spending any LLM calls if
        // the aggregate is already exhausted. This is also enforced inside
        // runVerifyLoop, but checking here lets us mark the finding SKIPPED
        // with a clean reason instead of running INCONCLUSIVE.
        if (!verifyTracker.canAttemptFinding()) {
            provenFindings.push({
                ...finding,
                proven: 'INCONCLUSIVE',
                provenReason: `Verification budget exhausted (${verifyTracker.findingsAttempted}/${verifyBudget.maxFindings} findings, ${verifyTracker.llmCallsUsed}/${verifyBudget.maxLlmCalls} LLM calls, ${Math.round(verifyTracker.wallClockElapsedMs / 1000)}s/${Math.round(verifyBudget.maxWallClockMs / 1000)}s).`,
            });
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
                budgetTracker: verifyTracker,
                signal: abortSignal,
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

    // 4a. Capability-based confidence clamping
    // Confidence must reflect what was actually proven, not what the LLM believes.
    // A finding with no structural evidence (no taint trace, no guard check, no
    // verify) cannot be reported at 95% confidence — that's how false positives
    // erode trust in a security tool. The clamp is deterministic and based on:
    //   1. What tools the agent actually used (transcript scan)
    //   2. What tools were available for this language (capability registry)
    //   3. The verify subagent's verdict (PROVEN/UNPROVEN/INCONCLUSIVE)
    clampConfidenceByCapability(provenFindings, agentResult.transcript, language);

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
            }, memoryFingerprint);
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
        verifyUsage: {
            findingsAttempted: verifyTracker.findingsAttempted,
            roundsUsed: verifyTracker.roundsUsed,
            llmCallsUsed: verifyTracker.llmCallsUsed,
            costSpentUsd: verifyTracker.costSpentUsd,
            wallClockMs: verifyTracker.wallClockElapsedMs,
            budget: verifyBudget,
        },
    };
}

function clampConfidenceByCapability(
    findings: ProvenFinding[],
    transcript: { action: { type: string }; observation: string }[],
    language: string,
): void {
    const cap = getCapability(language);

    let usedTaint = false;
    let usedGuard = false;
    let usedPolicy = false;
    for (const step of transcript) {
        const t = step.action.type;
        if (t === 'trace_flow' || t === 'trace_flow_cross_file') usedTaint = true;
        if (t === 'check_guard') usedGuard = true;
        if (t === 'check_policy') usedPolicy = true;
    }

    let evidenceTools = 0;
    if (usedTaint) evidenceTools++;
    if (usedGuard) evidenceTools++;
    if (usedPolicy) evidenceTools++;

    for (const f of findings) {
        const original = f.confidence;
        const ceiling = confidenceCeilingForFinding(f.proven, cap.tier, evidenceTools);
        // The ceiling is the maximum allowed confidence for this verdict +
        // capability combination. PROVEN findings have no ceiling (undefined)
        // — they're already proven, let the LLM's confidence stand (but still
        // floor at 80 because PROVEN should look confident).
        let clamped = original;
        if (ceiling !== undefined) {
            clamped = Math.min(clamped, ceiling);
        }
        // PROVEN floor — a finding verified by exploit test should not
        // display with a wishy-washy 40% confidence; if the agent is unsure
        // about a PROVEN finding, the proof overrules the agent's doubt.
        if (f.proven === 'PROVEN') {
            clamped = Math.max(clamped, 80);
        }

        clamped = Math.round(clamped);
        f.evidenceLevel = evidenceLevelTag(usedTaint, usedGuard, usedPolicy, f.proven);
        if (clamped !== original) {
            f.originalConfidence = original;
            f.confidence = clamped;
        }
    }
}

/**
 * Explicit confidence-ceiling policy for a finding, based on:
 *   - the verify verdict (PROVEN / UNPROVEN / INCONCLUSIVE /
 *     NOT_REPRODUCIBLE / SKIPPED)
 *   - the language capability tier (deep / standard / fallback)
 *   - how many structural evidence tools the agent actually used
 *     (trace_flow, check_guard, check_policy)
 *
 * Returns `undefined` for PROVEN (no ceiling — the proof overrules the
 * LLM's belief). For everything else, returns the maximum allowed
 * confidence. The caller takes `Math.min(confidence, ceiling)` so multiple
 * applicable bounds compose correctly — last-write-wins is impossible.
 *
 * Verdict semantics:
 *   - PROVEN: exploit test ran and reproduced the vulnerability. Strong
 *     evidence. No ceiling; floor at 80.
 *   - UNPROVEN: exploit test ran and did NOT reproduce. The finding is
 *     likely a false positive. Hard cap at 25.
 *   - NOT_REPRODUCIBLE: exploit test ran, but the test setup couldn't
 *     trigger the vulnerability (e.g. the path requires a live DB). This
 *     is NOT the same as UNPROVEN (which actively disproved) and NOT the
 *     same as INCONCLUSIVE (which couldn't even run a test). Treat it as
 *     "we tried and couldn't confirm" — cap at 35, tighter than
 *     INCONCLUSIVE but looser than UNPROVEN.
 *   - INCONCLUSIVE: no test could be generated or the sandbox was
 *     unavailable. The finding is unverified — keep the LLM's confidence
 *     but cap it based on structural evidence (no tools → ≤40, ≥2 tools
 *     → ≤75). Fallback-tier languages get ≤55 across the board.
 *   - SKIPPED: low severity, we didn't even try. Same as INCONCLUSIVE.
 */
export function confidenceCeilingForFinding(
    verdict: ProvenFinding['proven'],
    capabilityTier: 'deep' | 'standard' | 'fallback',
    evidenceTools: number,
): number | undefined {
    switch (verdict) {
        case 'PROVEN':
            return undefined;
        case 'UNPROVEN':
            return 25;
        case 'NOT_REPRODUCIBLE':
            return 35;
        case 'INCONCLUSIVE':
        case 'SKIPPED':
            if (capabilityTier === 'fallback') return 55;
            if (evidenceTools === 0) return 40;
            if (evidenceTools === 1) return 60;
            return 75;
        default:
            return 40;
    }
}

/**
 * Apply the confidence clamp to a single finding. Exported for testing
 * so the test imports the real policy, not a copy that can drift.
 */
export function applyConfidenceClamp(
    original: number,
    verdict: ProvenFinding['proven'],
    capabilityTier: 'deep' | 'standard' | 'fallback',
    evidenceTools: number,
): number {
    const ceiling = confidenceCeilingForFinding(verdict, capabilityTier, evidenceTools);
    let clamped = original;
    if (ceiling !== undefined) clamped = Math.min(clamped, ceiling);
    if (verdict === 'PROVEN') clamped = Math.max(clamped, 80);
    return Math.round(clamped);
}
