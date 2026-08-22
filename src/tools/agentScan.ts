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
import { getEndpointContextForFile, getRelatedFilesForFile, getMap } from '../project-map/mapContext';
import {
    getCachedScan,
    writeCachedScan,
    computeMemoryFingerprint,
    filterCachedFindingsAgainstMemory,
} from '../project-map/scanCache';
import { loadAgentMemory, formatMemoryForPrompt, saveInvestigationNotes, saveCoverageGaps, invalidateStaleEntries } from '../project-map/agentMemory';
import { getCapability, evidenceLevelTag } from '../project-map/capabilityRegistry';
import { readCache } from '../project-map/cache';
import {
    getCachedArchitectureContext,
    formatArchitectureContextForPrompt,
    formatArchitectureRiskTasksForTarget,
} from '../project-map/architectureContext';
import { runAgentScan } from '../attack/agentScanLoop';
import { runVerifyLoop } from '../attack/verifyLoop';
import { runFixVerifyLoop } from '../attack/fixVerifyLoop';
import { VerifyBudgetTracker, defaultVerifyBudget, defaultFixVerifyBudget, type VerifyBudget, type AgentScanScope, type FixVerificationStatus } from '../attack/agentScanProtocol';
import type { AgentScanFinding, AgentScanTarget, VerificationLevel } from '../attack/agentScanProtocol';
import { SANDBOX_UNAVAILABLE_MESSAGE } from '../utils/localTestRunner';
import { ApprovalBroker } from '../approval/broker';
import { getGitChangedFiles } from '../utils/gitContext';
import { computeBlastRadius } from '../project-map/blastRadius';
import { recordScanAuditSample } from '../audit/scanAuditLog';
import {
    enqueueFindingReview,
    type ReviewReason,
    type FindingReviewItem,
} from '../audit/findingReviewQueue';
import type { SandboxProveResponse, FixResponse } from '../api/types';

interface ProvenFinding extends AgentScanFinding {
    proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE' | 'SKIPPED';
    provenReason?: string;
    evidenceLevel?: string;
    originalConfidence?: number;
    verificationLevel?: VerificationLevel;
    fixStatus?: 'fix-generated' | 'fix-denied' | 'fix-error'
        | 'fix-verified-closed' | 'fix-still-vulnerable'
        | 'fix-verification-inconclusive' | 'fix-syntax-invalid';
    fixDeniedReason?: string;
    fixApprovalId?: string;
    /** Sub-verdict from the verify loop — used to map to a review reason. */
    verifySubVerdict?: string;
    /** Human review queue status for INCONCLUSIVE findings. */
    reviewStatus?: 'pending' | 'confirmed' | 'rejected' | 'deferred';
    reviewId?: string;
    /** Result of re-verifying the exploit against the fixed code. */
    fixVerification?: FixVerificationResult;
}

export interface FixVerificationResult {
    status: 'not-run' | 'closed' | 'still-vulnerable' | 'inconclusive'
        | 'syntax-invalid' | 'sandbox-unavailable' | 'cancelled';
    reason: string;
    originalVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'SKIPPED';
    fixedVerdict?: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    roundsUsed: number;
    fixedCodeHash: string;
}

/** Prove high/critical/medium findings — skip only low. */
function shouldProve(finding: AgentScanFinding): boolean {
    return finding.severity === 'critical' || finding.severity === 'high' || finding.severity === 'medium';
}

/**
 * Map a verification verdict to a precision verification level.
 *
 * PROVEN via local sandbox → exploit-confirmed (end-to-end test ran)
 * PROVEN via API sandbox → impact-confirmed (server-side test ran)
 * UNPROVEN → logic-confirmed (test proved behavior is safe)
 * INCONCLUSIVE/SKIPPED → logic-confirmed (couldn't determine)
 *
 * If the finding already has a verificationLevel from the agent, keep the
 * higher of the two (agent's level vs verify-mapped level).
 */
function mapVerificationLevel(
    proven: string,
    viaApiSandbox: boolean,
    agentLevel?: VerificationLevel,
): VerificationLevel {
    let mapped: VerificationLevel;
    if (proven === 'PROVEN') {
        mapped = viaApiSandbox ? 'impact-confirmed' : 'exploit-confirmed';
    } else if (proven === 'UNPROVEN') {
        mapped = 'logic-confirmed';
    } else {
        mapped = 'logic-confirmed';
    }

    const order: VerificationLevel[] = ['logic-confirmed', 'path-confirmed', 'impact-confirmed', 'exploit-confirmed'];
    if (agentLevel) {
        const agentIdx = order.indexOf(agentLevel);
        const mappedIdx = order.indexOf(mapped);
        return agentIdx > mappedIdx ? agentLevel : mapped;
    }
    return mapped;
}

/**
 * Map a verify loop sub-verdict to a human-readable review reason.
 * Falls back to 'inconclusive-verification' when no specific reason is known.
 */
function mapToReviewReason(finding: ProvenFinding): ReviewReason {
    const sv = finding.verifySubVerdict;
    switch (sv) {
        case 'sandbox-unavailable': return 'sandbox-unavailable';
        case 'budget-exhausted': return 'verification-budget-exhausted';
        case 'runtime-blocked': return 'runtime-blocked';
        case 'cannot-test': return 'test-generation-failed';
        case 'blocked': return 'runtime-blocked';
        default: return 'inconclusive-verification';
    }
}

/**
 * Determine whether a finding should be queued for human review.
 *
 * Queue when:
 *   - proven === 'INCONCLUSIVE' (verification couldn't decide)
 *   - proven === 'SKIPPED' for medium/high/critical (intentionally skipped but
 *     still potentially real)
 *   - proven === 'UNPROVEN' but confidence remains high (≥60) — the LLM still
 *     believes it's real despite the verify test not reproducing
 *
 * Do NOT queue:
 *   - Low-severity SKIPPED findings (intentionally not verified)
 *   - PROVEN findings (already confirmed by exploit)
 *   - UNPROVEN findings with low confidence (likely false positive)
 *   - Cancelled/aborted findings (user ended the scan)
 */
function shouldQueueForHumanReview(finding: ProvenFinding): boolean {
    if (finding.proven === 'PROVEN') return false;
    if (finding.proven === 'NOT_REPRODUCIBLE') return false;

    // Don't queue aborted/cancelled findings.
    if (finding.verifySubVerdict === 'cancelled' || finding.verifySubVerdict === 'aborted') {
        return false;
    }

    if (finding.proven === 'INCONCLUSIVE') return true;

    // SKIPPED: queue medium/high/critical, skip low.
    if (finding.proven === 'SKIPPED') {
        return finding.severity === 'critical' || finding.severity === 'high' || finding.severity === 'medium';
    }

    // UNPROVEN: queue only if high confidence remains after clamping.
    if (finding.proven === 'UNPROVEN' && finding.confidence >= 60) return true;

    return false;
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

    // 2a. Diff-aware blast radius scoping — if baseRef is provided, compute
    // the set of changed files and their blast radius from the project map.
    // The scope is passed to the agent target so the API prompt can guide
    // the agent to focus on changed files and their dependents.
    let scope: AgentScanScope | undefined;
    const baseRef = args.baseRef as string | undefined;
    if (baseRef) {
        try {
            const diffResult = await getGitChangedFiles(ctx.workspaceRoot, baseRef, args.headRef);
            if (diffResult.ok && diffResult.files.length > 0) {
                let blastFiles = diffResult.files;
                try {
                    const map = await getMap(ctx.workspaceRoot);
                    if (map && map.files) {
                        const blastResult = computeBlastRadius({
                            changedFiles: diffResult.files,
                            map,
                        });
                        blastFiles = blastResult.files;
                    }
                } catch {
                    // map not available — use just the changed files
                }
                scope = {
                    changedFiles: diffResult.files,
                    blastRadius: blastFiles,
                    baseRef: diffResult.baseRef,
                    headRef: diffResult.headRef,
                };
            }
        } catch {
            // best-effort — proceed without scope
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
        if (filePath) {
            const fileHash = require('crypto').createHash('sha256').update(code).digest('hex').substring(0, 16);
            invalidateStaleEntries(ctx.workspaceRoot, new Map([[filePath, fileHash]]));
        }
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
                try {
                    const fileHash = require('crypto').createHash('sha256').update(code).digest('hex').substring(0, 16);
                    recordScanAuditSample(ctx.workspaceRoot, {
                        filePath: filePath!,
                        fileHash,
                        language,
                        scanStatus: cached.status,
                        stepsUsed: cached.stepsUsed,
                        costSpentUsd: 0,
                        agentFindings: filteredFindings,
                        transcript: [],
                        cached: true,
                    });
                } catch {
                    // best-effort
                }
                return {
                    status: cached.status,
                    summary: cached.summary || 'Agent completed (cached).',
                    agentFindings: filteredFindings,
                    findings: [],
                    investigationNotes: cached.investigationNotes ?? [],
                    coverageGaps: cached.coverageGaps ?? [],
                    stepsUsed: cached.stepsUsed,
                    costSpentUsd: 0,
                    transcript: [],
                    cached: true,
                    provenCount: (filteredFindings as any[]).filter((f: any) => f.proven === 'PROVEN').length,
                    reviewQueue: {
                        added: [],
                        pendingCount: (filteredFindings as any[]).filter((f: any) => f.reviewStatus === 'pending').length,
                    },
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

    // 3b. Auto-load a cached architecture context (if present and valid)
    // so the vulnerability investigator starts with project-wide context
    // instead of having to discover "where is auth?", "what's the data
    // layer?" from scratch. The architecture context is produced by
    // `securecode.map action:architecture` and cached in
    // .securecode/architecture-context.json. If it's stale or absent, the
    // agent proceeds without it (no extra cost).
    let architectureContextStr: string | undefined;
    if (filePath) {
        try {
            const map = readCache(ctx.workspaceRoot);
            if (map) {
                // Try each depth; 'standard' is the most common. The cache
                // returns null if the entry is stale or missing.
                for (const d of ['standard', 'deep', 'quick'] as const) {
                    const cached = getCachedArchitectureContext(
                        ctx.workspaceRoot, d, map.builtAt, map.version,
                    );
                    if (cached) {
                        architectureContextStr = formatArchitectureContextForPrompt(cached);
                        // Append architecture risk tasks specific to this target file
                        const riskTasks = formatArchitectureRiskTasksForTarget(cached, filePath);
                        if (riskTasks) {
                            architectureContextStr = (architectureContextStr || '') + '\n\n' + riskTasks;
                        }
                        break;
                    }
                }
            }
        } catch {
            // best-effort — proceed without architecture context
        }
    }

    const target: AgentScanTarget = {
        filePath: filePath || 'inline-code',
        language,
        fileContent: code,
        endpointContext,
        workspaceMemory,
        scope,
        architectureContext: architectureContextStr,
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

    // Track why findings ended up INCONCLUSIVE so the final result can
    // surface one actionable hint instead of N identical per-finding
    // reasons. The most common case on a developer's laptop is
    // `sandbox-unavailable` (no Docker/Deno installed) — that gets a
    // top-level `verifyHint` with install URLs so the user sees it once,
    // at the top of the result, rather than buried in finding.reason.
    let sandboxUnavailableCount = 0;
    let budgetExhaustedCount = 0;

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
            budgetExhaustedCount++;
            provenFindings.push({
                ...finding,
                proven: 'INCONCLUSIVE',
                provenReason: `Verification budget exhausted (${verifyTracker.findingsAttempted}/${verifyBudget.maxFindings} findings, ${verifyTracker.llmCallsUsed}/${verifyBudget.maxLlmCalls} LLM calls, ${Math.round(verifyTracker.wallClockElapsedMs / 1000)}s/${Math.round(verifyBudget.maxWallClockMs / 1000)}s).`,
                verifySubVerdict: 'budget-exhausted',
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

            if (result.subVerdict === 'budget-exhausted') budgetExhaustedCount++;

            // User cancelled mid-verify: stop verifying further findings and
            // mark the rest as SKIPPED so the report still includes them.
            if (result.subVerdict === 'cancelled') {
                provenFindings.push({
                    ...finding,
                    proven: result.verdict,
                    provenReason: result.reason,
                    verifySubVerdict: result.subVerdict,
                });
                for (const remaining of agentResult.findings.slice(agentResult.findings.indexOf(finding) + 1)) {
                    provenFindings.push({
                        ...remaining,
                        proven: 'SKIPPED',
                        provenReason: 'Scan cancelled by user — not verified.',
                    });
                }
                break;
            }

            // No local sandbox (Docker/Deno) on the user's machine. Fall back to
            // the API-side sandbox on Vultr, which has Docker installed. This
            // gives every user exploit verification without a local install.
            if (result.subVerdict === 'sandbox-unavailable') {
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
                        verifySubVerdict: result.subVerdict,
                        verificationLevel: mapVerificationLevel(proveResp.proven, true, finding.verificationLevel),
                    });
                } catch (proveErr: any) {
                    sandboxUnavailableCount++;
                    provenFindings.push({
                        ...finding,
                        proven: 'INCONCLUSIVE',
                        provenReason: result.reason,
                        verifySubVerdict: result.subVerdict,
                        verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
                    });
                }
                continue;
            }

            provenFindings.push({
                ...finding,
                proven: result.verdict,
                provenReason: result.reason,
                verifySubVerdict: result.subVerdict,
                verificationLevel: mapVerificationLevel(result.verdict, false, finding.verificationLevel),
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
                    verificationLevel: mapVerificationLevel(proveResp.proven, true, finding.verificationLevel),
                });
            } catch (err2: any) {
                provenFindings.push({
                    ...finding,
                    proven: 'INCONCLUSIVE',
                    provenReason: `Verify failed: ${err.message}; Sandbox fallback also failed: ${err2.message}`,
                    verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
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

    // 4a-bis. Queue INCONCLUSIVE findings for non-blocking human review.
    //
    // Findings the verify subagent couldn't prove or disprove are added to a
    // local review queue (.securecode/finding-review-queue.json). The scan
    // does NOT block — the user can later adjudicate each item via the
    // securecode.review-findings and securecode.decide-finding MCP tools.
    // Only findings with a real file path are queued (inline-code scans have
    // no persistent location to review).
    const reviewQueueAdded: string[] = [];
    if (filePath) {
        for (const finding of provenFindings) {
            if (!shouldQueueForHumanReview(finding)) continue;
            try {
                const reviewItem = enqueueFindingReview(ctx.workspaceRoot, {
                    workspaceRelativePath: filePath,
                    fileContent: code,
                    line: finding.line,
                    lineEnd: finding.lineEnd,
                    findingType: finding.type,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    proven: finding.proven as 'INCONCLUSIVE' | 'SKIPPED' | 'UNPROVEN',
                    reviewReason: mapToReviewReason(finding),
                    verificationReason: finding.provenReason,
                    evidence: finding.evidence || '',
                });
                finding.reviewStatus = 'pending';
                finding.reviewId = reviewItem.id;
                reviewQueueAdded.push(reviewItem.id);
            } catch (reviewErr: any) {
                // Review queue persistence failure must not block the scan.
                console.warn(`[Agent Scan] Review queue enqueue failed: ${reviewErr?.message || reviewErr}`);
            }
        }
    }

    // 4b. Generate fixes for proven/suspected findings (requires approval)
    const fixableFindings = provenFindings.filter(f =>
        f.proven === 'PROVEN' || (f.proven !== 'UNPROVEN' && f.confidence >= 60)
    );

    if (fixableFindings.length > 0 && progress) {
        progress(0, fixableFindings.length, `Generating fixes for ${fixableFindings.length} finding(s)...`);
    }

    let fixIdx = 0;
    const fixBroker = fixableFindings.length > 0 ? new ApprovalBroker() : null;
    if (fixBroker) await fixBroker.start();

    try {
        for (const finding of fixableFindings) {
            if (progress) {
                fixIdx++;
                progress(fixIdx, fixableFindings.length, `Fixing ${finding.type} at line ${finding.line}...`);
            }

            const fixSummary = `Generate fix for ${finding.type} at line ${finding.line}${finding.lineEnd ? `-${finding.lineEnd}` : ''}\nSeverity: ${finding.severity} | Confidence: ${finding.confidence}%\nEvidence: ${finding.evidence?.substring(0, 200) || '(none)'}`;

            try {
                const approval = await fixBroker!.requestApproval(
                    'securecode.agent-scan (fix generation)',
                    fixSummary,
                    [code, language, finding.type, finding.line, finding.lineEnd, finding.evidence, finding.severity, finding.confidence],
                    60_000,
                    'paid-generation',
                    ctx.workspaceRoot,
                );

                if (!approval.approved) {
                    finding.fixStatus = 'fix-denied';
                    finding.fixDeniedReason = approval.reason;
                    continue;
                }

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
                    finding.fixStatus = 'fix-generated';
                    finding.fixApprovalId = approval.requestId;

                    // 4c. Re-verify the fix — re-run the exploit against the
                    // merged fixed code to prove the fix actually closed the
                    // vulnerability. Uses a separate, smaller budget so a
                    // single fix verification cannot consume the entire
                    // original scan verification budget. No second approval
                    // needed: the user already approved fix generation, and
                    // this runs inside the existing sandbox without modifying
                    // any workspace files.
                    try {
                        if (progress) {
                            progress(fixIdx, fixableFindings.length, `Verifying fix for ${finding.type} at line ${finding.line}...`);
                        }
                        const fixVerifyBudget = defaultFixVerifyBudget();
                        const fixVerifyTracker = new VerifyBudgetTracker(fixVerifyBudget);
                        const fixVerifyResult = await runFixVerifyLoop({
                            finding: {
                                type: finding.type,
                                line: finding.line,
                                lineEnd: finding.lineEnd,
                                evidence: finding.evidence,
                                why: finding.why,
                                severity: finding.severity,
                            },
                            originalCode: code,
                            fixedCode: fixResp.fixed_code,
                            replaceRange: { start_line: finding.line, end_line: finding.lineEnd || finding.line },
                            filePath: filePath || '',
                            relatedFiles: relatedFiles.map(rf => ({
                                filePath: rf.filePath,
                                content: rf.content,
                                relationship: rf.relationship,
                            })),
                            workspaceRoot: ctx.workspaceRoot,
                            language,
                            client,
                            originalVerdict: finding.proven as 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'SKIPPED',
                            budgetTracker: fixVerifyTracker,
                            signal: abortSignal,
                            onProgress: (round, maxR, msg) => {
                                if (progress) progress(fixIdx, fixableFindings.length, `Fix verify round ${round}/${maxR}: ${msg}`);
                            },
                        });

                        finding.fixVerification = fixVerifyResult;
                        // Map the fix verification status to the fixStatus field.
                        switch (fixVerifyResult.status) {
                            case 'closed':
                                finding.fixStatus = 'fix-verified-closed';
                                break;
                            case 'still-vulnerable':
                                finding.fixStatus = 'fix-still-vulnerable';
                                break;
                            case 'inconclusive':
                                finding.fixStatus = 'fix-verification-inconclusive';
                                break;
                            case 'syntax-invalid':
                                finding.fixStatus = 'fix-syntax-invalid';
                                break;
                            // sandbox-unavailable and cancelled leave fixStatus as 'fix-generated'
                        }
                    } catch (fixVerifyErr: any) {
                        // Fix verification failure must not block the scan — the
                        // fix is still generated, just not re-verified.
                        console.warn(`[Agent Scan] Fix verification failed for ${finding.type} at L${finding.line}: ${fixVerifyErr?.message || fixVerifyErr}`);
                    }
                }
            } catch (err: any) {
                finding.fixStatus = 'fix-error';
                finding.fixDeniedReason = err.message;
                console.warn(`[Agent Scan] Fix generation failed for ${finding.type} at L${finding.line}: ${err.message}`);
            }
        }
    } finally {
        if (fixBroker) await fixBroker.stop();
    }

    // 5. Write to cache before returning
    if (useCache) {
        try {
            writeCachedScan(ctx.workspaceRoot, filePath!, code, {
                findings: provenFindings,
                investigationNotes: agentResult.investigationNotes,
                coverageGaps: agentResult.coverageGaps,
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
    //
    // verifyHint: surfaced once at the top level when one or more findings
    // couldn't be exploit-verified. The local sandbox (Docker/Deno) was
    // unavailable AND the API-side sandbox fallback failed — so the finding
    // got INCONCLUSIVE. The hint tells the user what to install for local
    // verification (faster, no round-trip) and reminds them the API sandbox
    // is the automatic fallback.
    let verifyHint: string | undefined;
    if (sandboxUnavailableCount > 0) {
        verifyHint = `Exploit verification was skipped for ${sandboxUnavailableCount} finding(s). No local sandbox (Docker or Deno) was detected and the API-side sandbox was unavailable. Findings are reported as INCONCLUSIVE with confidence capped at 75%.\n${SANDBOX_UNAVAILABLE_MESSAGE}`;
    } else if (budgetExhaustedCount > 0) {
        verifyHint = `Exploit verification was skipped for ${budgetExhaustedCount} finding(s) because the per-scan verification budget (${verifyBudget.maxFindings} findings, ${verifyBudget.maxLlmCalls} LLM calls, ${Math.round(verifyBudget.maxWallClockMs / 1000)}s) was exhausted. Re-run the scan to verify the remaining findings, or raise the budget via the VerifyBudget config.`;
    }

    // 6a. Record metadata-only audit sample (no source code, no evidence strings)
    try {
        const fileHash = require('crypto').createHash('sha256').update(code).digest('hex').substring(0, 16);
        recordScanAuditSample(ctx.workspaceRoot, {
            filePath: filePath || 'inline-code',
            fileHash,
            language,
            scanStatus: agentResult.status,
            stepsUsed: agentResult.stepsUsed,
            costSpentUsd: agentResult.costSpentUsd,
            agentFindings: provenFindings,
            transcript: agentResult.transcript,
            cached: false,
            verifyUsage: {
                findingsAttempted: verifyTracker.findingsAttempted,
                roundsUsed: verifyTracker.roundsUsed,
                llmCallsUsed: verifyTracker.llmCallsUsed,
                costSpentUsd: verifyTracker.costSpentUsd,
                wallClockMs: verifyTracker.wallClockElapsedMs,
            },
            scope,
            investigationNotes: agentResult.investigationNotes,
            coverageGaps: agentResult.coverageGaps,
            hasArchitectureContext: !!architectureContextStr,
        });
    } catch {
        // best-effort — audit failure must not block scan results
    }

    // 6b. Persist investigation notes and coverage gaps to workspace memory
    // so future scans can use them as context. These are NOT findings —
    // they guide future investigation without suppressing new discoveries.
    try {
        const fileHashes = new Map<string, string>();
        if (filePath) {
            fileHashes.set(filePath, require('crypto').createHash('sha256').update(code).digest('hex').substring(0, 16));
        }
        if (agentResult.investigationNotes && agentResult.investigationNotes.length > 0) {
            saveInvestigationNotes(ctx.workspaceRoot, {
                notes: agentResult.investigationNotes,
                fileHashes,
            });
        }
        if (agentResult.coverageGaps && agentResult.coverageGaps.length > 0) {
            saveCoverageGaps(ctx.workspaceRoot, {
                gaps: agentResult.coverageGaps,
                fileHashes,
            });
        }
    } catch {
        // best-effort — memory persistence failure must not block results
    }

    return {
        status: agentResult.status,
        summary: agentResult.summary,
        agentFindings: provenFindings,
        verifiedFindings: provenFindings.filter(f => f.proven === 'PROVEN'),
        allFindings: [],
        investigationNotes: agentResult.investigationNotes ?? [],
        coverageGaps: agentResult.coverageGaps ?? [],
        stepsUsed: agentResult.stepsUsed,
        costSpentUsd: agentResult.costSpentUsd,
        transcript: agentResult.transcript,
        provenCount: provenFindings.filter(f => f.proven === 'PROVEN').length,
        unprovenCount: provenFindings.filter(f => f.proven === 'UNPROVEN').length,
        inconclusiveCount: provenFindings.filter(f => f.proven === 'INCONCLUSIVE').length,
        notReproducibleCount: provenFindings.filter(f => f.proven === 'NOT_REPRODUCIBLE').length,
        skippedCount: provenFindings.filter(f => f.proven === 'SKIPPED').length,
        verifyHint,
        verifyUsage: {
            findingsAttempted: verifyTracker.findingsAttempted,
            roundsUsed: verifyTracker.roundsUsed,
            llmCallsUsed: verifyTracker.llmCallsUsed,
            costSpentUsd: verifyTracker.costSpentUsd,
            wallClockMs: verifyTracker.wallClockElapsedMs,
            budget: verifyBudget,
        },
        reviewQueue: {
            added: reviewQueueAdded,
            pendingCount: provenFindings.filter(f => f.reviewStatus === 'pending').length,
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
