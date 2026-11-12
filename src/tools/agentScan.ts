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
import { LEAD_GAP_TITLE_PREFIX } from '../attack/finishGate';
import { globalScanCoordinator, SINGLE_SCAN_OPERATION_TIMEOUT_MS } from '../attack/agentScanCoordinator';
import {
    planFileSegments,
    planFileSegmentsForPath,
    countFileLines,
    formatSegmentEstimate,
    formatSegmentRange,
    type PlannedFileSegment,
} from '../attack/fileSegments';
import { buildGuardMap } from '../attack/guardMap';
import { runVerifyLoop } from '../attack/verifyLoop';
import { runFixVerifyLoop } from '../attack/fixVerifyLoop';
import { mergeFixedCode } from '../attack/fixCodeMerge';
import { testFix } from '../project-map/fixTester';
import {
    detectDevServer,
    executeProbePlan,
    isProbeEligible,
    isProbeEligibleType,
    hasProbeEligibleReason,
    matchEndpointForFinding,
    deriveEndpointFallback,
    type DevServerTarget,
    type ProbeEndpointCandidate,
} from '../attack/runtimeProbe';
import { detectRuntime } from '../utils/runtimeDetect';
import { VerifyBudgetTracker, defaultVerifyBudget, defaultFixVerifyBudget, AGENT_SCAN_DEFAULTS, type VerifyBudget, type AgentScanScope, type FixVerificationStatus } from '../attack/agentScanProtocol';
import {
    AgentScanRunCloser,
    isAgentScanBudgetExhausted,
    formatCreditUsage,
    VERIFY_BUDGET_EXHAUSTED_REASON,
} from '../attack/agentScanCredits';
import type { AgentScanFinding, AgentScanSegment, AgentScanTarget, VerificationLevel } from '../attack/agentScanProtocol';
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
import type { SandboxProveResponse, FixResponse, VerifyProbePlanResponse } from '../api/types';

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
    /** How many fix-generation attempts ran (1 = single, 2 = one regeneration after a failed verification). */
    fixAttempts?: number;
    /** Cheap local differential check on the merged fix (tree-sitter based). */
    fixQuality?: { passes: boolean; newVulnerabilities: string[]; regressions: string[] };
    /** Sub-verdict from the verify loop — used to map to a review reason. */
    verifySubVerdict?: string;
    /** Human review queue status for INCONCLUSIVE findings. */
    reviewStatus?: 'pending' | 'confirmed' | 'rejected' | 'deferred';
    reviewId?: string;
    /** Result of re-verifying the exploit against the fixed code. */
    fixVerification?: FixVerificationResult;
    /** Structured proof evidence from the proof gate, if the finding was verified. */
    proofEvidence?: import('../attack/proofTypes').ProofEvidence;
    /** Result of the deterministic proof gate evaluation. */
    proofGateResult?: import('../attack/proofTypes').ProofGateResult;
    /** Whether human review is required before acting on this finding. */
    humanReviewRequired?: boolean;
    /** Redacted live-server evidence from the runtime probe, when one executed. */
    probeEvidence?: string;
    /** Deterministic rule that decided the runtime probe verdict. */
    probeRule?: string;
    /** Runtime probe could verify this finding but was blocked (no dev server, approval denied, or plan refused). */
    probePending?: boolean;
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

/** Max runtime-probe verifications per scan — each probe plan draws from the scan's credit budget. */
const MAX_PROBE_FINDINGS_PER_SCAN = 3;

const RUN_CLOSE_TIMEOUT_MS = 30_000;

/**
 * Map a verification verdict to a precision verification level.
 *
 * PROVEN via local sandbox → exploit-confirmed (end-to-end test ran)
 * PROVEN via API sandbox → impact-confirmed (server-side test ran)
 * PROVEN via runtime probe → impact-confirmed (live-server evidence)
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
    viaRuntimeProbe?: boolean,
): VerificationLevel {
    let mapped: VerificationLevel;
    if (proven === 'PROVEN') {
        mapped = viaApiSandbox || viaRuntimeProbe ? 'impact-confirmed' : 'exploit-confirmed';
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
    if (finding.probePending) return 'runtime-probe-pending';
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
    if (args._skipCoordinator) {
        return toolAgentScanInner(ctx, args);
    }
    return globalScanCoordinator.runExclusive(
        ctx.workspaceRoot,
        () => toolAgentScanInner(ctx, args),
        {
            signal: args._signal as AbortSignal | undefined,
            maxWaitMs: 10_000,
            ...segmentedOperationTimeout(ctx, args),
        },
    );
}

function segmentedOperationTimeout(ctx: ServerContext, args: any): { operationTimeoutMs?: number } {
    try {
        if (!args.filePath) return {};
        const parts = planFileSegments(readFileFromWorkspace(ctx.workspaceRoot, args.filePath).code).length;
        return parts > 1 ? { operationTimeoutMs: SINGLE_SCAN_OPERATION_TIMEOUT_MS * (parts + 1) } : {};
    } catch {
        return {};
    }
}

async function toolAgentScanInner(ctx: ServerContext, args: any): Promise<unknown> {
    const runCloser = new AgentScanRunCloser();
    try {
        return await toolAgentScanBody(ctx, args, runCloser);
    } finally {
        await runCloser.close();
    }
}

async function toolAgentScanBody(ctx: ServerContext, args: any, runCloser: AgentScanRunCloser): Promise<unknown> {
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
                getEndpointContextForFile(absPath, ctx.workspaceRoot),
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

    // 2c. Check scan cache — if the file hasn't changed, return cached results.
    // `noCache` is the documented arg; `_noCache` is the internal alias used
    // by batch scans — both bypass the cache read for a fresh scan.
    const noCacheRequested = !!(args as any).noCache || !!(args as any)._noCache;
    const useCache = !!filePath;
    if (useCache && !noCacheRequested) {
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
                    terminationReason: cached.terminationReason,
                    summary: cached.summary || 'Agent completed (cached).',
                    agentFindings: filteredFindings,
                    findings: [],
                    investigationNotes: cached.investigationNotes ?? [],
                    coverageGaps: cached.coverageGaps ?? [],
                    stepsUsed: cached.stepsUsed,
                    stepsGranted: cached.stepsGranted ?? 40,
                    extensionsGranted: cached.extensionsGranted ?? 0,
                    costSpentUsd: 0,
                    creditsUsed: 0,
                    transcript: [],
                    cached: true,
                    provenCount: (filteredFindings as any[]).filter((f: any) => f.proven === 'PROVEN').length,
                    reviewQueue: {
                        added: [],
                        pendingCount: (filteredFindings as any[]).filter((f: any) => f.reviewStatus === 'pending').length,
                    },
                    ...(cached.segments && cached.segments.length > 0 ? { segments: cached.segments } : {}),
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
    // `securecode.architecture` and cached in
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

    const prep: ScanPrep = {
        code,
        language,
        filePath,
        endpointContext,
        relatedFiles,
        scope,
        architectureContextStr,
        memoryFingerprint,
        useCache,
        target,
    };

    if (filePath) {
        const segments = await planFileSegmentsForPath(code, filePath);
        if (segments.length > 1) return runSegmentedScan(ctx, args, prep, segments);
    }

    return (await scanTarget(ctx, args, prep, runCloser)).result;
}

interface ScanPrep {
    code: string;
    language: string;
    filePath?: string;
    endpointContext: any[];
    relatedFiles: any[];
    scope?: AgentScanScope;
    architectureContextStr?: string;
    memoryFingerprint: string;
    useCache: boolean;
    target: AgentScanTarget;
}

interface ScanPart {
    segment: AgentScanSegment;
    progress?: (progress: number, total: number, message: string) => void;
}

interface ScanOutput {
    result: Record<string, any>;
    agentSummary?: string;
}

async function scanTarget(
    ctx: ServerContext,
    args: any,
    prep: ScanPrep,
    runCloser: AgentScanRunCloser,
    part?: ScanPart,
): Promise<ScanOutput> {
    const progress = part
        ? part.progress
        : args._progress as ((progress: number, total: number, message: string) => void) | undefined;
    const skipFix = !!args._skipFix;
    const { code, language, filePath, endpointContext, relatedFiles, scope, architectureContextStr, memoryFingerprint, useCache, target } = prep;

    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const agentResult = await runAgentScan(ctx, part ? { ...target, segment: part.segment } : target, {
        signal: (args as any)._signal as AbortSignal | undefined,
        onProgress: (steps, max, msg) => {
            if (progress) progress(steps, max, msg);
        },
        deferClose: true,
        ...(part ? { segment: part.segment } : {}),
        ...(typeof (args as any)._role === 'string' ? { role: (args as any)._role } : {}),
    });
    const scanRunId = agentResult.runId;
    runCloser.attach(
        new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken, timeoutMs: RUN_CLOSE_TIMEOUT_MS }),
        scanRunId,
        agentResult.status,
        agentResult.terminationReason,
    );
    const runIdField = scanRunId ? { runId: scanRunId } : {};

    if (agentResult.status === 'failed') {
        if (!part) throw new Error(agentResult.error || 'Agent scan failed to start.');
        const settlement = await runCloser.close();
        return {
            result: failedPartResult(part.segment, agentResult.error || 'Agent scan failed to start.', {
                creditsUsed: settlement?.creditsUsed ?? agentResult.creditsUsed,
                creditsRefunded: settlement?.creditsRefunded ?? agentResult.creditsRefunded,
                baseCredits: agentResult.baseCredits,
                stepsUsed: agentResult.stepsUsed,
                costSpentUsd: agentResult.costSpentUsd,
                terminationReason: agentResult.terminationReason,
                capReason: agentResult.capReason,
            }),
        };
    }

    // 4. Verify each finding via the verify subagent (replaces sandbox prove + juror)
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
    let scanBudgetExhausted = false;
    let scanBudgetExhaustedCount = 0;
    const runtimeProbeDisabled = process.env.SECURECODE_DISABLE_RUNTIME_PROBE === '1';
    const probeCandidates: Array<{ finding: ProvenFinding; endpoint: ProbeEndpointCandidate }> = [];

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

        if (scanBudgetExhausted) {
            scanBudgetExhaustedCount++;
            provenFindings.push({
                ...finding,
                proven: 'INCONCLUSIVE',
                provenReason: VERIFY_BUDGET_EXHAUSTED_REASON,
                verifySubVerdict: 'budget-exhausted',
                verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
            });
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
                ...runIdField,
                onProgress: (round, maxR, msg) => {
                    if (progress) progress(proveIdx, proveable.length, `Verify round ${round}/${maxR}: ${msg}`);
                },
            });

            if (result.budgetExhaustedReason === 'scan-budget') {
                scanBudgetExhausted = true;
                scanBudgetExhaustedCount++;
                provenFindings.push({
                    ...finding,
                    proven: 'INCONCLUSIVE',
                    provenReason: result.reason,
                    verifySubVerdict: result.subVerdict,
                    verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
                });
                continue;
            }

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
                        ...runIdField,
                    });
                    provenFindings.push({
                        ...finding,
                        proven: proveResp.proven,
                        provenReason: proveResp.rationale || proveResp.skipReason || proveResp.sandbox?.reason,
                        verifySubVerdict: result.subVerdict,
                        verificationLevel: mapVerificationLevel(proveResp.proven, true, finding.verificationLevel),
                        proofEvidence: proveResp.proofEvidence,
                        proofGateResult: proveResp.proofGateResult,
                    });
                } catch (proveErr: any) {
                    if (isAgentScanBudgetExhausted(proveErr)) {
                        scanBudgetExhausted = true;
                        scanBudgetExhaustedCount++;
                        provenFindings.push({
                            ...finding,
                            proven: 'INCONCLUSIVE',
                            provenReason: VERIFY_BUDGET_EXHAUSTED_REASON,
                            verifySubVerdict: 'budget-exhausted',
                            verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
                        });
                        continue;
                    }
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

            // Runtime-probe candidate: an INCONCLUSIVE verify whose shape
            // (HTTP-routable vuln type + timeout/full-runtime reason) means
            // the live dev server could exercise what the sandbox could not.
            // Endpoint candidates come from the project map first, then the
            // framework fallback (derived from route registrations in the
            // scanned code / finding evidence) for files the map doesn't
            // extract — Effect-TS, NestJS, Hono, Koa.
            // Collected here, resolved after the loop so the whole scan gets
            // one approval and one severity-ordered probe budget.
            if (
                !runtimeProbeDisabled &&
                result.verdict === 'INCONCLUSIVE' &&
                isProbeEligibleType(finding.type) &&
                hasProbeEligibleReason(result.reason ?? '')
            ) {
                const probeEndpoint = matchEndpointForFinding(finding, endpointContext)
                    ?? deriveEndpointFallback(finding, code);
                if (probeEndpoint) {
                    const probeFinding: ProvenFinding = {
                        ...finding,
                        proven: 'INCONCLUSIVE',
                        provenReason: result.reason,
                        verifySubVerdict: result.subVerdict,
                        verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
                        proofEvidence: result.proofEvidence,
                        proofGateResult: result.proofGateResult,
                    };
                    provenFindings.push(probeFinding);
                    probeCandidates.push({ finding: probeFinding, endpoint: probeEndpoint });
                    continue;
                }
            }

            provenFindings.push({
                ...finding,
                proven: result.verdict,
                provenReason: result.reason,
                verifySubVerdict: result.subVerdict,
                verificationLevel: mapVerificationLevel(result.verdict, false, finding.verificationLevel),
                proofEvidence: result.proofEvidence,
                proofGateResult: result.proofGateResult,
            });
        } catch (err: any) {
            if (isAgentScanBudgetExhausted(err)) {
                scanBudgetExhausted = true;
                scanBudgetExhaustedCount++;
                provenFindings.push({
                    ...finding,
                    proven: 'INCONCLUSIVE',
                    provenReason: VERIFY_BUDGET_EXHAUSTED_REASON,
                    verifySubVerdict: 'budget-exhausted',
                    verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
                });
                continue;
            }
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
                    ...runIdField,
                });
                provenFindings.push({
                    ...finding,
                    proven: proveResp.proven,
                    provenReason: proveResp.rationale || proveResp.skipReason || proveResp.sandbox?.reason,
                    verificationLevel: mapVerificationLevel(proveResp.proven, true, finding.verificationLevel),
                    proofEvidence: proveResp.proofEvidence,
                    proofGateResult: proveResp.proofGateResult,
                });
            } catch (err2: any) {
                const exhausted = isAgentScanBudgetExhausted(err2);
                if (exhausted) {
                    scanBudgetExhausted = true;
                    scanBudgetExhaustedCount++;
                }
                provenFindings.push({
                    ...finding,
                    proven: 'INCONCLUSIVE',
                    provenReason: exhausted
                        ? VERIFY_BUDGET_EXHAUSTED_REASON
                        : `Verify failed: ${err.message}; Sandbox fallback also failed: ${err2.message}`,
                    ...(exhausted ? { verifySubVerdict: 'budget-exhausted' } : {}),
                    verificationLevel: mapVerificationLevel('INCONCLUSIVE', false, finding.verificationLevel),
                });
            }
        }
    }

    // 4-pre. Runtime probe — live-server verification for HTTP-shaped findings
    // the sandbox could not exercise (timeout / full-runtime shapes). One
    // approval covers the whole scan; at most MAX_PROBE_FINDINGS_PER_SCAN
    // findings are probed, severity-first; the rest stay INCONCLUSIVE and are
    // queued for review with the dev-server hint.
    let probeBlockedCount = 0;
    let approvalSkippedCount = 0;
    if (probeCandidates.length > 0 && !runtimeProbeDisabled) {
        const markAllProbeBlocked = (suffix: string) => {
            for (const candidate of probeCandidates) {
                candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''}${suffix}`;
                candidate.finding.probePending = true;
            }
            probeBlockedCount += probeCandidates.length;
        };

        let devServer: DevServerTarget | null = null;
        try {
            devServer = await detectDevServer(ctx.workspaceRoot);
        } catch {
            devServer = null;
        }

        if (!devServer) {
            markAllProbeBlocked(' Live-server probe available — start your dev server and re-scan to attempt runtime proof.');
        } else {
            const probeBroker = new ApprovalBroker();
            let probeBrokerReady = true;
            try {
                await probeBroker.start();
            } catch {
                probeBrokerReady = false;
            }
            try {
                const probeSummary =
                    `Runtime probe verification: ${probeCandidates.length} finding(s) need live-server confirmation against ${devServer.host}:${devServer.port}. ` +
                    'Planned: short HTTP probe plans (baseline + attack requests, read-only payloads).';
                const probeApproval = probeBrokerReady
                    ? await probeBroker.requestApproval(
                        'securecode.runtime-probe',
                        probeSummary,
                        [
                            devServer.host,
                            devServer.port,
                            ...probeCandidates.map(c => `${c.endpoint.method} ${String(c.endpoint.mountedPath ?? '') || c.endpoint.path}`),
                        ],
                        120_000,
                        'paid-generation',
                        ctx.workspaceRoot,
                        { onUrl: progress ? (url) => progress(0, 1, `⏸ Approval required — open ${url} (expires in 120s)`) : undefined },
                    )
                    : { approved: false, reason: 'Approval broker unavailable', requestId: '', duration: 0 };

                if (!probeApproval.approved) {
                    const skipReason = probeApproval.reason === 'User denied'
                        ? PROOF_SKIPPED_DENIED_REASON
                        : PROOF_SKIPPED_NO_APPROVAL_REASON;
                    for (const candidate of probeCandidates) {
                        candidate.finding.provenReason = [skipReason, candidate.finding.provenReason].filter(Boolean).join(' ');
                    }
                    approvalSkippedCount += probeCandidates.length;
                    markAllProbeBlocked(' Live-server probe available — start your dev server and re-scan to attempt runtime proof.');
                } else {
                    const severityRank: string[] = ['critical', 'high', 'medium', 'low'];
                    const orderedCandidates = [...probeCandidates].sort((a, b) =>
                        severityRank.indexOf(a.finding.severity) - severityRank.indexOf(b.finding.severity));
                    let probedCount = 0;
                    const runtimeInfo = filePath ? detectRuntime(ctx.workspaceRoot, filePath) : null;
                    for (const candidate of orderedCandidates) {
                        if (scanBudgetExhausted) {
                            probeBlockedCount++;
                            candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''} Runtime probe skipped: ${VERIFY_BUDGET_EXHAUSTED_REASON}`;
                            candidate.finding.probePending = true;
                            continue;
                        }
                        if (probedCount >= MAX_PROBE_FINDINGS_PER_SCAN) {
                            probeBlockedCount++;
                            candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''} Live-server probe budget reached (${MAX_PROBE_FINDINGS_PER_SCAN} per scan) — re-scan to attempt runtime proof of this finding.`;
                            candidate.finding.probePending = true;
                            continue;
                        }
                        try {
                            const planResp = await client.postJson<VerifyProbePlanResponse>('/verify/probe-plan', {
                                finding: {
                                    type: candidate.finding.type,
                                    line: candidate.finding.line,
                                    lineEnd: candidate.finding.lineEnd,
                                    evidence: candidate.finding.evidence,
                                    why: candidate.finding.why,
                                    severity: candidate.finding.severity,
                                },
                                endpoint: {
                                    method: candidate.endpoint.method,
                                    path: (candidate.endpoint.mountedPath as string) || candidate.endpoint.path,
                                    mountedPath: candidate.endpoint.mountedPath as string | undefined,
                                    params: candidate.endpoint.params as unknown[] | undefined,
                                    authScheme: candidate.endpoint.authScheme as string | undefined,
                                    middleware: candidate.endpoint.middleware as unknown[] | undefined,
                                },
                                framework: runtimeInfo?.framework ?? undefined,
                                devServerPort: devServer.port,
                                ...runIdField,
                            });
                            if (!planResp.canProbe || !planResp.plan) {
                                probeBlockedCount++;
                                candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''} Runtime probe skipped: ${planResp.skipReason || 'API declined to build a probe plan.'}`;
                                candidate.finding.probePending = true;
                                continue;
                            }
                            const probeResult = await executeProbePlan(planResp.plan, {
                                signal: abortSignal,
                                host: devServer.host,
                                port: devServer.port,
                            });
                            probedCount++;
                            candidate.finding.probeEvidence = probeResult.evidence;
                            candidate.finding.probeRule = probeResult.rule;
                            const liveEvidence = probeResult.evidence.length > 300
                                ? probeResult.evidence.slice(0, 300) + '…'
                                : probeResult.evidence;
                            if (probeResult.verdict === 'PROVEN') {
                                candidate.finding.proven = 'PROVEN';
                                candidate.finding.provenReason = `Runtime probe confirmed (${probeResult.rule}): ${probeResult.reason} — live evidence: ${liveEvidence}`;
                                candidate.finding.verificationLevel = mapVerificationLevel('PROVEN', false, candidate.finding.verificationLevel, true);
                            } else if (probeResult.verdict === 'UNPROVEN') {
                                candidate.finding.proven = 'UNPROVEN';
                                candidate.finding.provenReason = `Runtime probe refuted (${probeResult.rule}): ${probeResult.reason} — live evidence: ${liveEvidence}`;
                                candidate.finding.verificationLevel = mapVerificationLevel('UNPROVEN', false, candidate.finding.verificationLevel, true);
                            } else {
                                candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''} Runtime probe inconclusive: ${probeResult.reason}`;
                            }
                        } catch (probeErr: any) {
                            if (isAgentScanBudgetExhausted(probeErr)) {
                                scanBudgetExhausted = true;
                                probeBlockedCount++;
                                candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''} Runtime probe skipped: ${VERIFY_BUDGET_EXHAUSTED_REASON}`;
                                candidate.finding.probePending = true;
                                continue;
                            }
                            candidate.finding.provenReason = `${candidate.finding.provenReason ?? ''} Runtime probe failed: ${probeErr?.message || probeErr}`;
                            candidate.finding.probePending = true;
                        }
                    }
                }
            } finally {
                await probeBroker.stop();
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

    // 4a-ter. Mark findings requiring human review based on proof quality.
    for (const finding of provenFindings) {
        if (finding.proven !== 'PROVEN') continue;
        const needsReview =
            finding.severity === 'critical' ||
            (finding.proofEvidence && finding.proofEvidence.assumptions.length > 0) ||
            !finding.proofEvidence ||
            !finding.proofGateResult ||
            !finding.proofGateResult.eligibleForProven;
        finding.humanReviewRequired = needsReview;
    }

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
    if (skipFix) {
        console.log('[Agent Scan] Skipping fix generation (_skipFix=true)');
    } else {
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

            const fixSummary = `Generate fix for ${finding.type} at line ${finding.line}${finding.lineEnd ? `-${finding.lineEnd}` : ''}\nSeverity: ${finding.severity} | Confidence: ${finding.confidence}%\nEvidence: ${finding.evidence?.substring(0, 200) || '(none)'}\n\nIf verification fails, the fixer re-runs ONCE with the failure feedback (a second fix credit applies only if the first attempt fails).`;

            try {
                const approval = await fixBroker!.requestApproval(
                    'securecode.agent-scan (fix generation)',
                    fixSummary,
                    [code, language, finding.type, finding.line, finding.lineEnd, finding.evidence, finding.severity, finding.confidence],
                    120_000,
                    'paid-generation',
                    ctx.workspaceRoot,
                    { onUrl: progress ? (url) => progress(0, 1, `⏸ Approval required — open ${url} (expires in 120s)`) : undefined },
                );

                if (!approval.approved) {
                    finding.fixStatus = 'fix-denied';
                    finding.fixDeniedReason = approval.reason;
                    continue;
                }

                // Ground the fixer in everything the scanner proved.
                const verificationEvidenceParts: string[] = [];
                if (finding.provenReason) verificationEvidenceParts.push(`Original verification: ${finding.provenReason}`);
                if (finding.probeEvidence) verificationEvidenceParts.push(`Runtime probe (${finding.probeRule}): ${String(finding.probeEvidence).slice(0, 1200)}`);
                if (finding.proofEvidence) verificationEvidenceParts.push(`Proof evidence: ${JSON.stringify(finding.proofEvidence).slice(0, 1200)}`);
                const verificationEvidence = verificationEvidenceParts.join('\n\n');

                // Generate → apply-check → differential gate → sandbox verify.
                // A failed verification triggers ONE regeneration with the
                // failure feedback appended, under the same approval.
                const MAX_FIX_ATTEMPTS = 2;
                const replaceRange = { start_line: finding.line, end_line: finding.lineEnd || finding.line };
                const sinkLanguage = (['javascript', 'typescript', 'tsx', 'python'] as const).includes(language as any)
                    ? (language as 'javascript' | 'typescript' | 'tsx' | 'python')
                    : null;
                let attempt = 0;
                let lastFeedback = '';

                while (true) {
                    attempt++;
                    const attemptEvidence = attempt > 1 && lastFeedback
                        ? `${verificationEvidence ? verificationEvidence + '\n\n' : ''}PREVIOUS FIX ATTEMPT FAILED: ${lastFeedback}\nProduce a DIFFERENT fix that addresses this exact failure.`
                        : verificationEvidence;

                    const fixResp = await client.postJson<FixResponse>('/fix', {
                        code,
                        language,
                        vulnerability: {
                            type: finding.type,
                            line_start: finding.line,
                            line_end: finding.lineEnd || finding.line,
                            evidence_snippet: finding.evidence,
                            ...(finding.why ? { why: String(finding.why).slice(0, 2000) } : {}),
                            ...(finding.severity ? { severity: String(finding.severity).slice(0, 50) } : {}),
                            ...(attemptEvidence ? { verification_evidence: attemptEvidence.slice(0, 4000) } : {}),
                        },
                        ...(relatedFiles.length > 0
                            ? { relatedFiles: relatedFiles.slice(0, 5).map(rf => ({ filePath: rf.filePath, content: rf.content, relationship: rf.relationship })) }
                            : {}),
                    });

                    if (!fixResp.fixed_code) break;

                    finding.fix = {
                        fixedCode: fixResp.fixed_code,
                        replaceRange: { start_line: finding.line, end_line: finding.lineEnd || finding.line },
                        fixSummary: fixResp.fix_summary || '',
                        importsNeeded: fixResp.imports_needed,
                        confidence: fixResp.confidence,
                    };
                    finding.fixStatus = 'fix-generated';
                    finding.fixApprovalId = approval.requestId;
                    finding.fixAttempts = attempt;

                    // Cheap local differential gate before the expensive
                    // sandbox verify: syntax + sink diff + regressions, all
                    // tree-sitter (no LLM). A hard failure regenerates
                    // immediately instead of burning sandbox rounds.
                    const merge = mergeFixedCode(code, fixResp.fixed_code, replaceRange);
                    if (merge.ok && sinkLanguage) {
                        try {
                            const quality = await testFix(code, merge.mergedCode, sinkLanguage);
                            finding.fixQuality = {
                                passes: quality.passes,
                                newVulnerabilities: quality.newVulnerabilities,
                                regressions: quality.regressions,
                            };
                            if (!quality.syntaxValid || quality.regressions.length > 0) {
                                lastFeedback = !quality.syntaxValid
                                    ? 'the merged code has syntax errors'
                                    : `behavioral regressions detected: ${quality.regressions.join('; ')}`;
                                if (attempt < MAX_FIX_ATTEMPTS) continue;
                                finding.fixStatus = 'fix-syntax-invalid';
                                break;
                            }
                        } catch { /* differential gate is best-effort */ }
                    }

                    // 4c. Re-verify the fix — re-run the exploit against the
                    // merged fixed code to prove the fix actually closed the
                    // vulnerability. Uses a separate, smaller budget so a
                    // single fix verification cannot consume the entire
                    // original scan verification budget. No second approval
                    // needed: the user already approved fix generation, and
                    // this runs inside the existing sandbox without modifying
                    // any workspace files.
                    try {
                        if (scanBudgetExhausted) {
                            finding.fixVerification = {
                                status: 'inconclusive',
                                reason: VERIFY_BUDGET_EXHAUSTED_REASON,
                                originalVerdict: finding.proven as 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'SKIPPED',
                                roundsUsed: 0,
                                fixedCodeHash: require('crypto').createHash('sha256').update(fixResp.fixed_code).digest('hex').slice(0, 16),
                            };
                            finding.fixStatus = 'fix-verification-inconclusive';
                            break;
                        }
                        if (progress) {
                            progress(fixIdx, fixableFindings.length, `Verifying fix for ${finding.type} at line ${finding.line} (attempt ${attempt})...`);
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
                            replaceRange,
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
                            ...runIdField,
                            onProgress: (round, maxR, msg) => {
                                if (progress) progress(fixIdx, fixableFindings.length, `Fix verify round ${round}/${maxR}: ${msg}`);
                            },
                        });

                        if (fixVerifyResult.scanBudgetExhausted) scanBudgetExhausted = true;
                        finding.fixVerification = fixVerifyResult;
                        // Map the fix verification status to the fixStatus field.
                        switch (fixVerifyResult.status) {
                            case 'closed':
                                finding.fixStatus = 'fix-verified-closed';
                                break;
                            case 'still-vulnerable':
                            case 'syntax-invalid': {
                                if (attempt < MAX_FIX_ATTEMPTS) {
                                    lastFeedback = fixVerifyResult.status === 'still-vulnerable'
                                        ? `the exploit still reproduces against the fixed code: ${fixVerifyResult.reason.slice(0, 600)}`
                                        : `the fixed code failed to merge or parse: ${fixVerifyResult.reason.slice(0, 600)}`;
                                    continue;
                                }
                                finding.fixStatus = fixVerifyResult.status === 'still-vulnerable'
                                    ? 'fix-still-vulnerable'
                                    : 'fix-syntax-invalid';
                                break;
                            }
                            case 'inconclusive':
                                finding.fixStatus = 'fix-verification-inconclusive';
                                break;
                            // sandbox-unavailable and cancelled leave fixStatus as 'fix-generated'
                        }
                    } catch (fixVerifyErr: any) {
                        // Fix verification failure must not block the scan — the
                        // fix is still generated, just not re-verified.
                        console.warn(`[Agent Scan] Fix verification failed for ${finding.type} at L${finding.line}: ${fixVerifyErr?.message || fixVerifyErr}`);
                    }
                    break;
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
    } // end else (skipFix)

    // 5. Write to cache before returning — only fully-successful scans:
    // status 'completed' AND terminationReason 'agent_finish'. Failed,
    // degraded, or incomplete runs (llm_degraded, blocked reads, budget
    // stops, crashes) reflect a bad model-server or environment window,
    // not the file's true state, and must not be served for 7 days.
    if (!part && useCache && agentResult.status === 'completed' && agentResult.terminationReason === 'agent_finish') {
        try {
            writeCachedScan(ctx.workspaceRoot, filePath!, code, {
                findings: provenFindings,
                investigationNotes: agentResult.investigationNotes,
                coverageGaps: agentResult.coverageGaps,
                status: agentResult.status,
                terminationReason: agentResult.terminationReason,
                summary: agentResult.summary,
                stepsUsed: agentResult.stepsUsed,
                stepsGranted: agentResult.stepsGranted,
                extensionsGranted: agentResult.extensionsGranted,
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
    if (scanBudgetExhaustedCount > 0) {
        const creditHint = `Exploit verification stopped for ${scanBudgetExhaustedCount} finding(s): this scan's credit budget ran out. Top up credits and re-scan to verify them.`;
        verifyHint = verifyHint ? `${verifyHint}\n${creditHint}` : creditHint;
    }
    if (probeBlockedCount > 0) {
        const probeHint = `${probeBlockedCount} finding(s) could be runtime-probe verified — start your dev server (detected port hints: 3000/5173/8080) and re-scan, or set SECURECODE_DEV_SERVER_PORT.`;
        verifyHint = verifyHint ? `${verifyHint}\n${probeHint}` : probeHint;
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
            stepsGranted: agentResult.stepsGranted,
            extensionsGranted: agentResult.extensionsGranted,
            terminationReason: agentResult.terminationReason,
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

    const settlement = await runCloser.close();
    const baseCredits = agentResult.baseCredits ?? AGENT_SCAN_DEFAULTS.creditsPerRun;
    const creditsUsed = settlement?.creditsUsed ?? agentResult.creditsUsed;
    const creditsRefunded = settlement?.creditsRefunded ?? agentResult.creditsRefunded;
    let creditExtensionsGranted = agentResult.creditExtensionsGranted;
    if (settlement) {
        const drawnExtensions = Math.round((settlement.creditsUsed + settlement.creditsRefunded - baseCredits) / AGENT_SCAN_DEFAULTS.extensionCredits);
        creditExtensionsGranted = Math.max(creditExtensionsGranted ?? 0, drawnExtensions, 0);
    }
    const creditFields = typeof creditsUsed === 'number'
        ? {
            creditsUsed,
            baseCredits,
            creditExtensionsGranted: creditExtensionsGranted ?? 0,
            creditsRefunded: creditsRefunded ?? 0,
            ...(agentResult.maxCredits !== undefined ? { maxCredits: agentResult.maxCredits } : {}),
        }
        : {};
    const creditText = formatCreditUsage(creditFields);
    const approvalText = approvalSkippedCount > 0 ? formatApprovalSkipped(approvalSkippedCount) : '';
    const summary = [agentResult.summary, creditText, approvalText].filter(Boolean).join(' ') || agentResult.summary;

    return {
        agentSummary: agentResult.summary,
        result: {
            status: agentResult.status,
            summary,
            agentFindings: provenFindings,
            verifiedFindings: provenFindings.filter(f => f.proven === 'PROVEN'),
            allFindings: [],
            investigationNotes: agentResult.investigationNotes ?? [],
            coverageGaps: agentResult.coverageGaps ?? [],
            stepsUsed: agentResult.stepsUsed,
            stepsGranted: agentResult.stepsGranted,
            extensionsGranted: agentResult.extensionsGranted,
            terminationReason: agentResult.terminationReason,
            ...(agentResult.capReason ? { capReason: agentResult.capReason } : {}),
            costSpentUsd: agentResult.costSpentUsd,
            ...creditFields,
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
            ...(part ? { segment: part.segment } : {}),
        },
    };
}

const TOP_UP_URL = 'https://usesecurecode.tech';

const PROOF_SKIPPED_NO_APPROVAL_REASON = 'Proof skipped: approval was not given within 120 s — re-run with someone available to approve, or verify manually.';
const PROOF_SKIPPED_DENIED_REASON = 'Proof skipped: approval was denied.';

function formatApprovalSkipped(count: number): string {
    return `${count} finding(s) unproven because approval wasn't given.`;
}

function isApprovalSkipped(finding: ProvenFinding): boolean {
    const reason = finding.provenReason ?? '';
    return reason.startsWith(PROOF_SKIPPED_NO_APPROVAL_REASON) || reason.startsWith(PROOF_SKIPPED_DENIED_REASON);
}

const PROVEN_RANK: Record<string, number> = { PROVEN: 5, INCONCLUSIVE: 4, NOT_REPRODUCIBLE: 3, SKIPPED: 2, UNPROVEN: 1 };

export interface PartRecord {
    segment: PlannedFileSegment;
    result?: Record<string, any>;
    agentSummary?: string;
}

const PRIOR_PARTS_HEADER = 'Earlier parts of this file (already scanned):';
const SEGMENT_CONTEXT_MAX_CHARS = 4000;

function clip(text: unknown, max: number): string {
    const s = String(text ?? '').replace(/\s+/g, ' ').trim();
    return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

function atLine(line: unknown): string {
    return typeof line === 'number' && Number.isFinite(line) ? `@${line}` : '';
}

export function buildPriorPartsContext(parts: PartRecord[], maxChars = 2500): string {
    const rendered: string[] = [];
    for (const p of parts) {
        const r = p.result;
        if (!r) continue;
        const label = partLabel(p.segment);
        if (r.status === 'failed') {
            rendered.push(`${label}: scan failed; treat these lines as unscanned.`);
            continue;
        }
        const findings = [...((r.agentFindings ?? []) as ProvenFinding[])]
            .sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
        const notes = [...((r.investigationNotes ?? []) as any[])]
            .sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
        const leads = ((r.coverageGaps ?? []) as any[])
            .filter(g => typeof g?.title === 'string' && g.title.startsWith(LEAD_GAP_TITLE_PREFIX))
            .sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
        if (findings.length === 0 && notes.length === 0 && leads.length === 0) {
            rendered.push(`${label}: no findings or notes.`);
            continue;
        }
        rendered.push(`${label}:`);
        for (const f of findings) {
            const proven = f.proven ? ` [${f.proven}]` : '';
            const why = clip(f.why, 140);
            rendered.push(`  finding: ${clip(f.type, 60)}${atLine(f.line)}${proven}${why ? ` — ${why}` : ''}`);
        }
        for (const n of notes) {
            const line = typeof n.line === 'number' && Number.isFinite(n.line) ? ` (line ${n.line})` : '';
            rendered.push(`  note: ${clip(n.title, 100)}${line}`);
        }
        for (const g of leads) {
            const line = typeof g.line === 'number' && Number.isFinite(g.line) ? ` (line ${g.line})` : '';
            rendered.push(`  lead: ${clip(g.title.slice(LEAD_GAP_TITLE_PREFIX.length), 120)}${line} [open]`);
        }
    }
    if (rendered.length === 0) return '';

    let out = PRIOR_PARTS_HEADER;
    for (const line of rendered) {
        const next = `${out}\n${line}`;
        if (next.length > maxChars - 2) {
            out += '\n…';
            break;
        }
        out = next;
    }
    return out;
}

function buildSegmentContext(guardMap: string, parts: PartRecord[]): string | undefined {
    const context = [guardMap, buildPriorPartsContext(parts)].filter(Boolean).join('\n\n');
    if (!context) return undefined;
    return context.length > SEGMENT_CONTEXT_MAX_CHARS
        ? `${context.slice(0, SEGMENT_CONTEXT_MAX_CHARS - 1)}…`
        : context;
}

function failedPartResult(
    segment: AgentScanSegment,
    error: string,
    extra: {
        creditsUsed?: number;
        creditsRefunded?: number;
        baseCredits?: number;
        stepsUsed?: number;
        costSpentUsd?: number;
        terminationReason?: string;
        capReason?: string;
    },
): Record<string, any> {
    return {
        status: 'failed',
        error,
        terminationReason: extra.terminationReason ?? 'api_error',
        ...(extra.capReason ? { capReason: extra.capReason } : {}),
        agentFindings: [],
        investigationNotes: [],
        coverageGaps: [],
        transcript: [],
        stepsUsed: extra.stepsUsed ?? 0,
        stepsGranted: 0,
        extensionsGranted: 0,
        costSpentUsd: extra.costSpentUsd ?? 0,
        ...(typeof extra.creditsUsed === 'number'
            ? {
                creditsUsed: extra.creditsUsed,
                creditsRefunded: extra.creditsRefunded ?? 0,
                baseCredits: extra.baseCredits ?? AGENT_SCAN_DEFAULTS.creditsPerRun,
                creditExtensionsGranted: 0,
            }
            : {}),
        reviewQueue: { added: [], pendingCount: 0 },
        segment,
    };
}

function isOutOfCredits(result: Record<string, any> | undefined, err?: unknown): boolean {
    if (err && ((err as any)?.status === 402 || (err as any)?.statusCode === 402) && !isAgentScanBudgetExhausted(err)) return true;
    if (!result) return false;
    if (result.capReason === 'insufficient_credits') return true;
    return result.status === 'failed' && /insufficient credits|top up at/i.test(String(result.error ?? ''));
}

function sinkKey(f: AgentScanFinding): string {
    const sink = f.evidenceChain?.sink;
    if (sink && typeof sink.line === 'number') return `${sink.file ?? ''}:${sink.line}`;
    return '';
}

function evidenceKey(f: AgentScanFinding): string {
    return String(f.evidence ?? '').replace(/\s+/g, ' ').trim().toLowerCase();
}

function isSameFinding(a: AgentScanFinding, b: AgentScanFinding): boolean {
    if (a.type !== b.type) return false;
    if (Math.abs((a.line ?? 0) - (b.line ?? 0)) > 2) return false;
    const sa = sinkKey(a);
    const sb = sinkKey(b);
    if (sa && sb) return sa === sb;
    const ea = evidenceKey(a);
    const eb = evidenceKey(b);
    if (ea && eb) return ea === eb || ea.includes(eb) || eb.includes(ea);
    return true;
}

function isStronger(a: ProvenFinding, b: ProvenFinding): boolean {
    const ra = PROVEN_RANK[a.proven] ?? 0;
    const rb = PROVEN_RANK[b.proven] ?? 0;
    if (ra !== rb) return ra > rb;
    return (a.confidence ?? 0) > (b.confidence ?? 0);
}

export function mergeSegmentFindings(findings: ProvenFinding[]): ProvenFinding[] {
    const out: ProvenFinding[] = [];
    for (const f of findings) {
        const idx = out.findIndex(existing => isSameFinding(existing, f));
        if (idx === -1) {
            out.push(f);
        } else if (isStronger(f, out[idx])) {
            out[idx] = f;
        }
    }
    return out;
}

function sumNumbers(values: unknown[]): number {
    return values.reduce<number>((s, v) => s + (typeof v === 'number' && Number.isFinite(v) ? v : 0), 0);
}

function partLabel(segment: PlannedFileSegment): string {
    return `Part ${segment.index} (lines ${formatSegmentRange(segment)})`;
}

async function runSegmentedScan(
    ctx: ServerContext,
    args: any,
    prep: ScanPrep,
    segments: PlannedFileSegment[],
): Promise<unknown> {
    const progress = args._progress as ((progress: number, total: number, message: string) => void) | undefined;
    const signal = args._signal as AbortSignal | undefined;
    const total = segments.length;
    const groupId = `seg-${require('crypto').randomBytes(4).toString('hex')}`;
    const lineCount = countFileLines(prep.code);

    if (progress) progress(0, total, `${formatSegmentEstimate(lineCount, total)}. Parts run one after another.`);

    const parts: PartRecord[] = [];
    let outOfCreditsAfter: PlannedFileSegment | undefined;
    let cancelled = false;
    let firstError: string | undefined;
    const guardMap = buildGuardMap(prep.code);

    for (const seg of segments) {
        if (outOfCreditsAfter || cancelled) {
            parts.push({ segment: seg });
            continue;
        }
        if (signal?.aborted) {
            cancelled = true;
            parts.push({ segment: seg });
            continue;
        }

        const context = buildSegmentContext(guardMap, parts);
        const segment: AgentScanSegment = {
            groupId,
            index: seg.index,
            total,
            startLine: seg.startLine,
            endLine: seg.endLine,
            ...(context ? { context } : {}),
        };
        const prefix = `file part ${seg.index}/${total}: `;
        const partProgress = progress
            ? (c: number, t: number, m: string) => progress(c, t, `${prefix}${m}`)
            : undefined;
        if (partProgress) partProgress(0, 1, `Scanning lines ${formatSegmentRange(seg)}...`);

        const closer = new AgentScanRunCloser();
        let record: PartRecord;
        let thrown: unknown;
        try {
            const output = await scanTarget(ctx, args, prep, closer, { segment, progress: partProgress });
            record = { segment: seg, result: output.result, agentSummary: output.agentSummary };
        } catch (err: any) {
            thrown = err;
            const settlement = await closer.close();
            record = {
                segment: seg,
                result: failedPartResult(segment, err?.message || String(err), {
                    creditsUsed: settlement?.creditsUsed,
                    creditsRefunded: settlement?.creditsRefunded,
                }),
            };
        } finally {
            await closer.close();
        }
        parts.push(record);

        const result = record.result!;
        if (result.status === 'failed' && !firstError) firstError = String(result.error ?? 'Agent scan failed.');
        if (isOutOfCredits(result, thrown)) {
            outOfCreditsAfter = seg;
        } else if (result.status === 'cancelled' || signal?.aborted) {
            cancelled = true;
        }
    }

    const ran = parts.filter(p => p.result);
    if (!cancelled && ran.length > 0 && ran.every(p => p.result!.status === 'failed')) {
        const msg = firstError || 'Agent scan failed to start.';
        throw new Error(outOfCreditsAfter && !/top up/i.test(msg)
            ? `${msg} — Top up at ${TOP_UP_URL} and retry.`
            : msg);
    }

    return mergeSegmentResults(ctx, prep, parts, { groupId, total, outOfCreditsAfter, cancelled });
}

function mergeSegmentResults(
    ctx: ServerContext,
    prep: ScanPrep,
    parts: PartRecord[],
    info: { groupId: string; total: number; outOfCreditsAfter?: PlannedFileSegment; cancelled: boolean },
): Record<string, any> {
    const ran = parts.filter(p => p.result);
    const notStarted = parts.filter(p => !p.result);
    const results = ran.map(p => p.result!);

    const allFindings: ProvenFinding[] = [];
    const investigationNotes: any[] = [];
    const coverageGaps: any[] = [];
    const transcript: any[] = [];
    const verifyHints: string[] = [];
    const reviewAdded: string[] = [];
    for (const p of ran) {
        const r = p.result!;
        const tag = { index: p.segment.index, total: info.total, startLine: p.segment.startLine, endLine: p.segment.endLine };
        allFindings.push(...((r.agentFindings ?? []) as ProvenFinding[]));
        for (const n of r.investigationNotes ?? []) investigationNotes.push({ ...n, part: tag });
        for (const g of r.coverageGaps ?? []) coverageGaps.push({ ...g, part: tag });
        transcript.push(...(r.transcript ?? []));
        if (r.verifyHint && !verifyHints.includes(r.verifyHint)) verifyHints.push(r.verifyHint);
        reviewAdded.push(...(r.reviewQueue?.added ?? []));
    }
    for (const p of notStarted) {
        coverageGaps.push({
            title: `${partLabel(p.segment)} not scanned`,
            detail: info.outOfCreditsAfter
                ? 'Scan stopped because the account ran out of credits.'
                : 'Scan was cancelled before this part ran.',
            requiredEvidence: [],
            suggestedNextAction: info.outOfCreditsAfter
                ? `Top up at ${TOP_UP_URL} and re-scan this file.`
                : 'Re-scan this file.',
            priority: 'high',
            line: p.segment.startLine,
            lineEnd: p.segment.endLine,
            ...(prep.filePath ? { file: prep.filePath } : {}),
            part: { index: p.segment.index, total: info.total, startLine: p.segment.startLine, endLine: p.segment.endLine },
        });
    }
    const findings = mergeSegmentFindings(allFindings);

    const allCompleted = notStarted.length === 0
        && results.every(r => r.status === 'completed' && r.terminationReason === 'agent_finish');
    let status: string;
    if (info.cancelled) status = 'cancelled';
    else if (allCompleted) status = 'completed';
    else status = 'incomplete';

    let terminationReason: string | undefined;
    if (info.cancelled) terminationReason = 'cancelled';
    else if (allCompleted) terminationReason = 'agent_finish';
    else terminationReason = results.find(r => r.terminationReason && r.terminationReason !== 'agent_finish')?.terminationReason
        ?? (info.outOfCreditsAfter ? 'budget_exhausted' : 'forced_incomplete');

    const creditParts = results.filter(r => typeof r.creditsUsed === 'number');
    const creditsUsed = sumNumbers(creditParts.map(r => r.creditsUsed));
    const creditsRefunded = sumNumbers(creditParts.map(r => r.creditsRefunded));
    const baseCredits = sumNumbers(creditParts.map(r => r.baseCredits ?? AGENT_SCAN_DEFAULTS.creditsPerRun));
    const creditExtensionsGranted = sumNumbers(creditParts.map(r => r.creditExtensionsGranted));
    const maxCredits = sumNumbers(creditParts.map(r => r.maxCredits ?? AGENT_SCAN_DEFAULTS.maxCreditsPerRun));
    const perPartBase = creditParts.length > 0 ? Math.round(baseCredits / creditParts.length) : AGENT_SCAN_DEFAULTS.creditsPerRun;
    const extensionCredits = Math.max(0, creditsUsed - baseCredits);

    const sentences: string[] = [];
    sentences.push(`Scanned in ${info.total} parts (lines ${parts.map(p => formatSegmentRange(p.segment)).join(', ')}).`);
    if (creditParts.length > 0) {
        const breakdown = extensionCredits > 0
            ? `${creditParts.length} part${creditParts.length === 1 ? '' : 's'} × ${perPartBase} + ${extensionCredits} extension credit${extensionCredits === 1 ? '' : 's'}`
            : `${creditParts.length} part${creditParts.length === 1 ? '' : 's'} × ${perPartBase}`;
        sentences.push(`This file used ${creditsUsed} credit${creditsUsed === 1 ? '' : 's'} (${breakdown}).`);
        if (creditsRefunded > 0) sentences.push(`${creditsRefunded} credit${creditsRefunded === 1 ? ' was' : 's were'} refunded.`);
    }
    for (const p of ran) {
        if (p.result!.status === 'failed') {
            sentences.push(`${partLabel(p.segment)} failed: ${p.result!.error ?? 'unknown error'}.`);
        }
    }
    if (info.outOfCreditsAfter && notStarted.length > 0) {
        sentences.push(`Out of credits after part ${info.outOfCreditsAfter.index} of ${info.total}: lines ${notStarted.map(p => formatSegmentRange(p.segment)).join(', ')} were not scanned. Top up at ${TOP_UP_URL} and re-scan this file.`);
    } else if (info.outOfCreditsAfter) {
        sentences.push(`Credits ran out during part ${info.outOfCreditsAfter.index} of ${info.total}. Top up at ${TOP_UP_URL} and re-scan to scan deeper.`);
    } else if (info.cancelled && notStarted.length > 0) {
        sentences.push(`Scan cancelled: lines ${notStarted.map(p => formatSegmentRange(p.segment)).join(', ')} were not scanned.`);
    }
    const approvalSkippedTotal = findings.filter(isApprovalSkipped).length;
    if (approvalSkippedTotal > 0) sentences.push(formatApprovalSkipped(approvalSkippedTotal));
    for (const p of ran) {
        if (p.agentSummary) sentences.push(`${partLabel(p.segment)}: ${p.agentSummary}`);
    }

    const segmentsField = parts.map(p => ({
        index: p.segment.index,
        startLine: p.segment.startLine,
        endLine: p.segment.endLine,
        status: p.result ? p.result.status : 'not-started',
        ...(p.result && typeof p.result.creditsUsed === 'number' ? { creditsUsed: p.result.creditsUsed } : {}),
        ...(p.result?.terminationReason ? { terminationReason: p.result.terminationReason } : {}),
        ...(p.result?.error ? { error: p.result.error } : {}),
    }));

    const summary = sentences.join(' ');
    const stepsUsed = sumNumbers(results.map(r => r.stepsUsed));
    const costSpentUsd = sumNumbers(results.map(r => r.costSpentUsd));
    const capReason = info.outOfCreditsAfter ? 'insufficient_credits' : results.find(r => r.capReason)?.capReason;

    if (prep.useCache && prep.filePath && status === 'completed' && terminationReason === 'agent_finish') {
        try {
            writeCachedScan(ctx.workspaceRoot, prep.filePath, prep.code, {
                findings,
                investigationNotes,
                coverageGaps,
                status,
                terminationReason,
                summary,
                stepsUsed,
                stepsGranted: sumNumbers(results.map(r => r.stepsGranted)),
                extensionsGranted: sumNumbers(results.map(r => r.extensionsGranted)),
                costSpentUsd,
                segments: segmentsField,
            }, prep.memoryFingerprint);
        } catch (err: any) {
            console.warn(`[Agent Scan] Cache write skipped: ${err?.message || err}`);
        }
    }

    const verifyBudgets = results.map(r => r.verifyUsage).filter(Boolean);

    return {
        status,
        summary,
        agentFindings: findings,
        verifiedFindings: findings.filter(f => f.proven === 'PROVEN'),
        allFindings: [],
        investigationNotes,
        coverageGaps,
        stepsUsed,
        stepsGranted: sumNumbers(results.map(r => r.stepsGranted)),
        extensionsGranted: sumNumbers(results.map(r => r.extensionsGranted)),
        terminationReason,
        ...(capReason ? { capReason } : {}),
        costSpentUsd,
        ...(creditParts.length > 0
            ? { creditsUsed, baseCredits, creditExtensionsGranted, creditsRefunded, maxCredits }
            : {}),
        transcript,
        provenCount: findings.filter(f => f.proven === 'PROVEN').length,
        unprovenCount: findings.filter(f => f.proven === 'UNPROVEN').length,
        inconclusiveCount: findings.filter(f => f.proven === 'INCONCLUSIVE').length,
        notReproducibleCount: findings.filter(f => f.proven === 'NOT_REPRODUCIBLE').length,
        skippedCount: findings.filter(f => f.proven === 'SKIPPED').length,
        ...(verifyHints.length > 0 ? { verifyHint: verifyHints.join('\n') } : {}),
        verifyUsage: {
            findingsAttempted: sumNumbers(verifyBudgets.map(v => v.findingsAttempted)),
            roundsUsed: sumNumbers(verifyBudgets.map(v => v.roundsUsed)),
            llmCallsUsed: sumNumbers(verifyBudgets.map(v => v.llmCallsUsed)),
            costSpentUsd: sumNumbers(verifyBudgets.map(v => v.costSpentUsd)),
            wallClockMs: sumNumbers(verifyBudgets.map(v => v.wallClockMs)),
            ...(verifyBudgets[0]?.budget ? { budget: verifyBudgets[0].budget } : {}),
        },
        reviewQueue: {
            added: reviewAdded,
            pendingCount: findings.filter(f => f.reviewStatus === 'pending').length,
        },
        cached: false,
        segmentGroupId: info.groupId,
        segments: segmentsField,
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
        const ceiling = confidenceCeilingForFinding(f.proven, cap.tier, evidenceTools, f.proven === 'PROVEN' && !!f.probeRule);
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
 *   - PROVEN via runtime probe: live HTTP evidence only (no sandbox exploit
 *     run) — cap at 90, above every unverified tier.
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
    viaRuntimeProbe?: boolean,
): number | undefined {
    switch (verdict) {
        case 'PROVEN':
            if (viaRuntimeProbe) return 90;
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
