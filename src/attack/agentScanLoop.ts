/**
 * Scan agent loop driver — the MCP-side loop that drives the scan agent.
 *
 * Mirrors agentLoop.ts (the attack agent) but with scan tools instead of
 * HTTP probes. The API is a stateless per-step brain; this loop owns the
 * transcript, the filesystem, and the tool execution.
 *
 * Flow:
 *   1. POST /agent/scan/start → { runId, budget }
 *   2. while (true):
 *        POST /agent/scan/step { runId, target, transcript, budget }
 *        ← { next: action | null }
 *        if null → done (capped or completed)
 *        if finish → done with findings
 *        execute action locally → observation
 *        push { action, observation } into transcript
 *   3. return result
 */

import { ApiClient } from '../api/client';
import type { ServerContext } from '../mcp/types';
import { executeAction, executeReadFileAction } from './agentScanExecutor';
import { AgentTraceLogger } from './agentTrace';
import { InvestigationState } from './investigationState';
import { selectInvestigationProfile } from './investigationProfiles';
import { createInvestigationTasksFromRisks } from '../project-map/architectureContext';
import { discoverEndpoints } from '../project-map/endpointDiscovery';
import { looksLikeContractOnly, resolveImplementation, formatImplementationResolution } from '../project-map/implementationResolver';
import { isEquivalentSearchIntent, normalizeSearchPattern } from './searchIntent';
import {
    createScanRunState,
    transitionScanPhase,
    terminateScan,
    isScanTerminal,
    canExecuteWork,
    type ScanRunState,
} from './scanState';
import { EvidenceLedger } from './evidenceLedger';
import { WorkItemQueue, createArchitectureRiskWorkItem, createHandlerReviewWorkItem } from './workItem';
import { HandlerInventory } from '../project-map/handlerInventory';
import { CandidateStore } from './candidateStore';
import { schedule as schedulerDecision } from './scanScheduler';
import { evaluateFinishGate } from './finishGate';
import { QualityMetricsTracker } from './qualityMetrics';
import { extractFunctionBoundaries } from './agentScanExecutor';
import {
    validateStartResponse,
    validateStepResponse,
    type ValidationResult,
} from './protocolValidator';
import {
    AGENT_SCAN_DEFAULTS,
    defaultClientCapabilities,
    type AgentActionConstraint,
    type AgentScanAction,
    type AgentScanBudget,
    type AgentScanFinding,
    type AgentScanResult,
    type AgentScanRunStatus,
    type AgentScanStartResponse,
    type AgentScanStepRequest,
    type AgentScanStepResponse,
    type AgentScanTarget,
    type AgentScanTranscriptStep,
} from './agentScanProtocol';

export interface AgentScanOptions {
    budget?: Partial<AgentScanBudget>;
    signal?: AbortSignal;
    onProgress?: (stepsTaken: number, maxSteps: number, message: string) => void;
}

export async function runAgentScan(
    ctx: ServerContext,
    target: AgentScanTarget,
    options: AgentScanOptions = {},
): Promise<AgentScanResult> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const budget: AgentScanBudget = {
        stepsRemaining: options.budget?.stepsRemaining ?? AGENT_SCAN_DEFAULTS.initialSteps,
        costSpentUsd: options.budget?.costSpentUsd ?? 0,
        costCapUsd: options.budget?.costCapUsd ?? AGENT_SCAN_DEFAULTS.costCapUsd,
        stepsGranted: options.budget?.stepsGranted ?? AGENT_SCAN_DEFAULTS.initialSteps,
        hardMaxSteps: options.budget?.hardMaxSteps ?? AGENT_SCAN_DEFAULTS.hardMaxSteps,
        extensionsGranted: options.budget?.extensionsGranted ?? 0,
    };

    const startTime = Date.now();
    const wallClockMs = AGENT_SCAN_DEFAULTS.wallClockMs;
    let stepsTaken = 0;
    let costSpentUsd = 0;
        let stepsGranted = budget.stepsGranted;
        let extensionsGranted = budget.extensionsGranted;
        let meaningfulProgressSinceLastExtension = false;

    try {
        const startRespRaw = await client.postJson<AgentScanStartResponse>('/agent/scan/start', {}, options.signal);
        const startValidation = validateStartResponse(startRespRaw);
        if (!startValidation.ok) {
            return {
                status: 'spawn_failed',
                findings: [],
                transcript: [],
                stepsUsed: 0,
                stepsGranted: AGENT_SCAN_DEFAULTS.initialSteps,
                extensionsGranted: 0,
                costSpentUsd: 0,
                terminationReason: 'api_error',
                error: `API returned an invalid start response: ${startValidation.error}`,
                investigationNotes: [],
                coverageGaps: [],
            };
        }
        const startResp = startValidation.value;

        const trace = new AgentTraceLogger(ctx.workspaceRoot, startResp.runId);
        trace.logRunStarted();

        // Authoritative scan state — the single source of truth for phase,
        // budget, recovery, and lifecycle. Local counters below are kept in
        // sync with this state until they are fully replaced.
        const scanState = createScanRunState(startResp.runId, target, budget);
        scanState.budget.wallClockMs = wallClockMs;
        const qualityTracker = new QualityMetricsTracker();

        const transcript: AgentScanTranscriptStep[] = [];
        const investigationState = new InvestigationState();
        // Select a target-specific investigation profile to set the required
        // checklist steps. This prevents the agent from wasting steps on
        // irrelevant tools (e.g., get_endpoints on a utility file) and ensures
        // required steps for the target type are not skipped.
        const profile = selectInvestigationProfile({
            filePath: target.filePath,
            architectureContext: (target as any).architectureContext,
            endpointContext: (target as any).endpointContext,
        });
        investigationState.setRequiredSteps(profile.requiredSteps);
        scanState.profileId = profile.name;

        // Implementation resolution: if the target file looks like a
        // contract-only file (interface, type declaration, abstract class),
        // resolve the actual implementation so the investigation can follow
        // the real code, not just signatures.
        let implementationResolution: string | null = null;
        try {
            const fs = require('fs');
            const absPath = require('path').resolve(ctx.workspaceRoot, target.filePath);
            const content = fs.existsSync(absPath) ? fs.readFileSync(absPath, 'utf8') : '';
            if (content && looksLikeContractOnly(content)) {
                const symbol = target.filePath.replace(/\.ts$/, '').replace(/.*\//, '');
                const resolution = await resolveImplementation(
                    ctx.workspaceRoot, target.filePath, symbol,
                );
                if (!resolution.unresolved && resolution.implementationLocations.length > 0) {
                    implementationResolution = formatImplementationResolution(resolution);
                    (target as any).implementationHint = implementationResolution;
                }
            }
        } catch { /* best-effort */ }

        // Control plane infrastructure — evidence ledger, work items, handler
        // inventory, candidate store, and scheduler work together to ensure
        // the investigation is complete before finish is accepted.
        const evidenceLedger = new EvidenceLedger();
        evidenceLedger.addRequirements(profile.requirements);
        const workItemQueue = new WorkItemQueue();
        // Note: profile requirements are tracked by the evidence ledger and
        // checklist, not as work items. Work items are for architecture-risk
        // tasks, handler reviews, and implementation reviews — structured
        // work that the scheduler can prioritize and attempt-count.
        const handlerInventory = new HandlerInventory();
        const candidateStore = new CandidateStore();
        // Convert architecture risks relevant to this target into tracked
        // investigation tasks. Unresolved tasks will appear as coverage gaps.
        const archTasks = createInvestigationTasksFromRisks(
            (target as any).architectureContext, target.filePath,
        );
        investigationState.addInvestigationTasks(archTasks);
        // Create work items for architecture-risk tasks so the scheduler
        // can prioritize them and suggest deterministic actions.
        for (const task of archTasks) {
            workItemQueue.add(createArchitectureRiskWorkItem(
                task.claim,
                task.targetFiles,
                task.requiredEvidence.map((req, i) => ({
                    id: `${task.id}-req-${i}`,
                    description: req,
                    acceptedKinds: ['source-range', 'cross-file-flow', 'policy-result'] as any,
                    minimumCount: 1,
                })),
            ));
        }
        const readFiles = new Set<string>();
        const readFileCounts = new Map<string, number>();
        // Pre-compute function boundaries for chunk alignment
        let functionBoundaries: { name: string; startLine: number; endLine: number }[] | undefined;
        try {
            const fb = await extractFunctionBoundaries(target.fileContent, target.filePath);
            if (fb) functionBoundaries = fb;
        } catch { /* best-effort */ }
        // Dynamic read cap based on file size:
        //   < 200 lines  → 5 reads (small file, 5 chunks is enough)
        //   < 1000 lines  → 8 reads (medium file)
        //   < 5000 lines  → 12 reads (large file — use search_code/trace_flow, not brute reading)
        //   >= 5000 lines → 15 reads (very large — still capped; the agent must use
        //                  search_code and trace_flow for pattern discovery, not
        //                  read the entire file section by section)
        function maxReadsForFile(filePath: string): number {
            try {
                const fs = require('fs');
                const abs = require('path').resolve(ctx.workspaceRoot, filePath);
                const stat = fs.statSync(abs);
                if (stat.size > 200_000) return 15;
                const content = fs.readFileSync(abs, 'utf8');
                const lines = content.split('\n').length;
                if (lines < 200) return 5;
                if (lines < 1000) return 8;
                if (lines < 5000) return 12;
                return 15;
            } catch {
                return 8;
            }
        }
        // Track non-read tool calls to prevent the agent from looping on the
        // same search_code/trace_flow call repeatedly. Keyed by (type + args).
        const toolCallCounts = new Map<string, number>();
        const MAX_SAME_TOOL_CALL = 2;
        // Track normalized search patterns to detect equivalent searches
        // (same terms, different order) that the raw toolKey dedup misses.
        const searchedPatterns = new Set<string>();
        let equivalentSearchCount = 0;

        let consecutiveErrors = 0;
        let consecutiveBlockedReads = 0;
        let meaningfulProgressSinceRecovery = true;

        while (true) {
            // Wall clock check
            if (Date.now() - startTime > wallClockMs) {
                terminateScan(scanState, 'wall_clock', `Wall clock limit (${wallClockMs}ms) exceeded.`);
                return {
                    status: 'capped',
                    findings: [],
                    transcript,
                    stepsUsed: stepsTaken,
                    stepsGranted,
                    extensionsGranted,
                    costSpentUsd,
                    terminationReason: 'wall_clock',
                    summary: `Wall clock limit (${wallClockMs}ms) exceeded.`,
                    investigationNotes: [],
                    coverageGaps: [],
                };
            }

            // Abort check
            if (options.signal?.aborted) {
                terminateScan(scanState, 'cancelled', 'Cancelled by user.');
                return {
                    status: 'cancelled',
                    findings: [],
                    transcript,
                    stepsUsed: stepsTaken,
                    stepsGranted,
                    extensionsGranted,
                    costSpentUsd,
                    terminationReason: 'cancelled',
                    summary: 'Cancelled by user.',
                    investigationNotes: [],
                    coverageGaps: [],
                };
            }

            // Build action constraint for blocked-read recovery.
            //   0-1 blocked reads: normal (no constraint)
            //   2 blocked reads: recovery mode — if unread ranges exist,
            //     require the next unread range; if no unread ranges remain,
            //     forbid read_file entirely and require an analysis tool.
            //   3 blocked reads: MCP selects a deterministic recovery action (skip API)
            let actionConstraint: AgentActionConstraint | undefined;
            if (consecutiveBlockedReads >= 2 && consecutiveBlockedReads < 3) {
                const nextRange = target.fileContent
                    ? investigationState.getPrioritizedUnreadRange(target.filePath, target.fileContent)
                    : investigationState.getNextUnreadRange(target.filePath);
                if (nextRange) {
                    actionConstraint = {
                        mode: 'recovery',
                        requiredAction: {
                            type: 'read_file',
                            path: target.filePath,
                            startLine: nextRange.start,
                            endLine: nextRange.end,
                            rationale: `Read next unread range: lines ${nextRange.start}-${nextRange.end}`,
                        } as any,
                        reason: `You have been blocked by duplicate/overlapping reads. Read the next unread range: lines ${nextRange.start}-${nextRange.end}, or use an analysis tool (trace_flow, check_guard, check_policy).`,
                    };
                } else {
                    const recoveryAction = investigationState.getRecommendedRecoveryAction();
                    actionConstraint = {
                        mode: 'recovery',
                        forbiddenActions: ['read_file'],
                        requiredAction: recoveryAction as any || undefined,
                        reason: 'You have been blocked by duplicate/overlapping reads and no unread ranges remain. Switch to an analysis tool.',
                    };
                }
            }

            const stepReq: AgentScanStepRequest = {
                runId: startResp.runId,
                target,
                transcript,
                budget: {
                    stepsRemaining: budget.stepsRemaining,
                    costSpentUsd,
                    costCapUsd: budget.costCapUsd,
                    stepsGranted,
                    hardMaxSteps: budget.hardMaxSteps,
                    extensionsGranted,
                },
                clientCapabilities: defaultClientCapabilities(),
                investigationProgress: {
                    completedSteps: investigationState.getCompletedSteps(),
                    incompleteSteps: investigationState.getIncompleteSteps(),
                    consecutiveBlockedReads,
                    meaningfulProgressSinceLastExtension,
                },
                actionConstraint,
            };

            let stepResp: AgentScanStepResponse;
            try {
                const stepRespRaw = await client.postJson<AgentStepResponse>('/agent/scan/step', stepReq, options.signal);
                const stepValidation = validateStepResponse(stepRespRaw);
                if (!stepValidation.ok) {
                    // Wire-level malformed response. Don't execute the
                    // potentially-dangerous `next` action; treat it as a
                    // controlled error so the agent can retry against a
                    // well-formed response on the next call.
                    const vErr = stepValidation.error;
                    console.warn(`[Agent Scan Loop] Step ${stepsTaken + 1} returned a malformed response: ${vErr}`);
                    consecutiveErrors++;
                    stepsTaken++;
                    budget.stepsRemaining--;
                    const errMsg = `API returned a malformed step response: ${vErr}`;
                    transcript.push({
                        action: {
                            type: 'system_event',
                            eventType: 'error',
                            message: errMsg,
                        } as any,
                        observation: errMsg,
                    });
                    if (consecutiveErrors >= 3 || budget.stepsRemaining <= 0) {
                        return {
                            status: 'capped',
                            findings: [],
                            transcript,
                            stepsUsed: stepsTaken,
                            stepsGranted,
                            extensionsGranted,
                            costSpentUsd,
                            terminationReason: 'api_error',
                            summary: `Step budget exhausted after ${consecutiveErrors} consecutive malformed API responses. Last error: ${vErr}`,
                            investigationNotes: [],
                            coverageGaps: [],
                        };
                    }
                    continue;
                }
                stepResp = stepValidation.value;
            } catch (stepErr: any) {
                const errMsg = stepErr?.message || String(stepErr);
                const apiCode = (stepErr as any)?.apiCode || '';

                // Detect API server restart — the run was lost. Don't waste
                // 3 retry steps on a dead run; return immediately.
                if (apiCode === 'AGENT_RUN_NOT_FOUND' || /AGENT_RUN_NOT_FOUND|Invalid or expired agent run/i.test(errMsg)) {
                    console.warn(`[Agent Scan Loop] Agent run expired (API server restarted?). Stopping scan.`);
                    return {
                        status: 'spawn_failed',
                        findings: [],
                        transcript,
                        stepsUsed: stepsTaken,
                        stepsGranted,
                        extensionsGranted,
                        costSpentUsd,
                        terminationReason: 'api_error',
                        error: 'API server restarted mid-scan — the run was lost. Please retry the scan.',
                        investigationNotes: [],
                        coverageGaps: [],
                    };
                }

                // Detect abort — the user cancelled. Don't treat as error.
                if (options.signal?.aborted || /aborted/i.test(errMsg)) {
                    return {
                        status: 'cancelled',
                        findings: [],
                        transcript,
                        stepsUsed: stepsTaken,
                        stepsGranted,
                        extensionsGranted,
                        costSpentUsd,
                        terminationReason: 'cancelled',
                        summary: 'Cancelled by user.',
                        investigationNotes: [],
                        coverageGaps: [],
                    };
                }

                // The API rejected the action (malformed, missing field, etc).
                // Add a first-class system_event to the transcript so the LLM
                // sees the error on the next step and can correct itself.
                // Previously this piggybacked on `read_file('__ERROR__')`,
                // which the executor would have tried to open and failed.
                console.warn(`[Agent Scan Loop] Step ${stepsTaken + 1} error: ${errMsg}`);
                consecutiveErrors++;
                stepsTaken++;
                budget.stepsRemaining--;

                const errorMsg = `ERROR: Your previous action was rejected: ${errMsg}. Please try a DIFFERENT action with ALL required fields. Set unused fields to null.`;
                transcript.push({
                    action: {
                        type: 'system_event',
                        eventType: 'error',
                        message: errorMsg,
                    } as any,
                    observation: errorMsg,
                });

                if (consecutiveErrors >= 3 || budget.stepsRemaining <= 0) {
                    return {
                        status: 'capped',
                        findings: [],
                        transcript,
                        stepsUsed: stepsTaken,
                        stepsGranted,
                        extensionsGranted,
                        costSpentUsd,
                        terminationReason: 'api_error',
                        summary: `Step budget exhausted after ${consecutiveErrors} consecutive API errors. Last error: ${errMsg}`,
                        investigationNotes: [],
                        coverageGaps: [],
                    };
                }
                continue;
            }
            costSpentUsd += stepResp.costUsd || 0;
            scanState.budget.costSpentUsd = costSpentUsd;
            consecutiveErrors = 0;
            trace.logStepRequested(stepResp.model, stepResp.tokens, stepResp.costUsd, stepResp.latencyMs);

            // Transition from planning to surveying on first successful step
            if (scanState.phase === 'planning') {
                transitionScanPhase(scanState, 'surveying', 'first step received');
            }

            // Budget extension — the API may grant additional steps when the
            // agent demonstrates meaningful progress. Update our local tracking.
            if (stepResp.budgetExtension) {
                const ext = stepResp.budgetExtension;
                stepsGranted = ext.totalGranted;
                extensionsGranted = ext.granted > 0 ? extensionsGranted + 1 : extensionsGranted;
                budget.stepsRemaining = stepResp.stepsRemaining;
                budget.stepsGranted = ext.totalGranted;
                budget.extensionsGranted = extensionsGranted;
                scanState.budget.stepsGranted = ext.totalGranted;
                scanState.budget.extensionsGranted = extensionsGranted;
                scanState.budget.stepsRemaining = stepResp.stepsRemaining;
                meaningfulProgressSinceLastExtension = false;
                if (options.onProgress) {
                    options.onProgress(stepsTaken, ext.hardMaxSteps, `Budget extended +${ext.granted} steps (${ext.totalGranted}/${ext.hardMaxSteps}): ${ext.reason}`);
                }
            }

            // System event (e.g., critique from the senior reviewer) — append
            // to the transcript WITHOUT executing it, then continue the loop
            // so the next step's prompt sees the event and re-plans. This
            // replaces the previous `read_file('__CRITIQUE__')` pattern that
            // lost the critique content over the wire.
            if (stepResp.systemEvent) {
                const ev = stepResp.systemEvent;
                if (ev.eventType === 'critique') qualityTracker.recordCritique();
                if (ev.eventType === 'finish_gate') qualityTracker.recordFinishGate();
                transcript.push({
                    action: ev,
                    observation: ev.message,
                });
                stepsTaken++;
                budget.stepsRemaining = stepResp.stepsRemaining;
                if (options.onProgress) {
                    options.onProgress(stepsTaken, stepsGranted, `Step ${stepsTaken}: system_event(${ev.eventType})`);
                }
                // Re-loop: ask the API for the next action now that the
                // critique is in the transcript. The agent will see the
                // critique in the next step's prompt and either re-investigate
                // or call finish again with an updated selfCritique.
                continue;
            }

            // Null next = done (cost capped or steps exhausted)
            if (!stepResp.next) {
                const status: AgentScanRunStatus = stepResp.costCapped
                    ? 'capped'
                    : (stepResp.degraded ? 'degraded' : 'completed');
                trace.logRunCompleted(status);
                return {
                    status,
                    findings: [],
                    transcript,
                    stepsUsed: stepsTaken,
                    stepsGranted,
                    extensionsGranted,
                    costSpentUsd,
                    terminationReason: stepResp.costCapped ? 'cost_cap' : 'budget_exhausted',
                    summary: stepResp.costCapped
                        ? `Cost cap ($${budget.costCapUsd.toFixed(2)}) reached.`
                        : 'Agent completed without explicit finish.',
                    investigationNotes: [],
                    coverageGaps: [],
                };
            }

            const action: AgentScanAction = stepResp.next;
            stepsTaken++;
            budget.stepsRemaining = stepResp.stepsRemaining;
            scanState.budget.stepsUsed = stepsTaken;
            scanState.budget.stepsRemaining = stepResp.stepsRemaining;
            trace.nextStep();
            trace.logActionSelected(action.type, stepResp.model, stepResp.degraded || stepResp.fallbackFired);

            // Progress callback
            if (options.onProgress) {
                const actionDesc = describeAction(action);
                options.onProgress(stepsTaken, stepsGranted, `Step ${stepsTaken}: ${actionDesc}`);
            }

            // Finish = done with findings
            if (action.type === 'finish') {
                scanState.finishAttempts++;
                qualityTracker.recordFinishAttempt();

                // Register candidates from findings — each finding becomes a
                // tracked candidate. If the candidate is new (discovered), the
                // finish gate will reject and the agent must gather evidence.
                for (const finding of action.findings) {
                    const rootCauseId = finding.rootCause?.rootCauseId || `${finding.type}:${finding.line}`;
                    const existing = candidateStore.getCandidatesByRootCause(rootCauseId);
                    if (existing.length === 0) {
                        const candidateId = candidateStore.register({
                            rootCauseId,
                            type: finding.type,
                            severity: finding.severity as any,
                            locations: [{ filePath: target.filePath, line: finding.line }],
                            claim: finding.why,
                            requiredEvidence: [
                                {
                                    id: `${rootCauseId}-flow`,
                                    description: 'Verify data flow to the vulnerable location',
                                    acceptedKinds: ['cross-file-flow'],
                                    targetFiles: [target.filePath],
                                    requiredTools: ['trace_flow_cross_file', 'trace_flow'],
                                    minimumCount: 1,
                                },
                                {
                                    id: `${rootCauseId}-guard`,
                                    description: 'Check for guards/controls on the vulnerable location',
                                    acceptedKinds: ['guard-result', 'policy-result'],
                                    targetFiles: [target.filePath],
                                    requiredTools: ['check_guard', 'check_policy'],
                                    minimumCount: 1,
                                },
                            ],
                        });
                        // Backfill evidence: scan the transcript for prior
                        // verification actions on this candidate's location.
                        // If the agent already ran trace_flow/check_guard on
                        // the file before calling finish, credit that evidence.
                        const targetFileNorm = target.filePath.replace(/\\/g, '/').toLowerCase();
                        const verificationActions = new Set([
                            'trace_flow', 'trace_flow_cross_file', 'check_guard', 'check_policy',
                        ]);
                        for (const step of transcript) {
                            if (verificationActions.has(step.action.type)) {
                                const stepFile = (step.action as any).filePath || (step.action as any).path || target.filePath;
                                const stepFileNorm = String(stepFile).replace(/\\/g, '/').toLowerCase();
                                if (stepFileNorm === targetFileNorm) {
                                    const cat = step.action.type === 'trace_flow' || step.action.type === 'trace_flow_cross_file' ? 'flow' as const
                                        : step.action.type === 'check_guard' ? 'guard' as const
                                        : step.action.type === 'check_policy' ? 'policy' as const
                                        : undefined;
                                    candidateStore.addEvidence(candidateId, `backfill:${step.action.type}:${stepFileNorm}`, cat);
                                }
                            }
                            if (step.action.type === 'read_file') {
                                const stepFile = (step.action as any).path || target.filePath;
                                const stepFileNorm = String(stepFile).replace(/\\/g, '/').toLowerCase();
                                if (stepFileNorm === targetFileNorm) {
                                    candidateStore.addEvidence(candidateId, `backfill:source:${stepFileNorm}`, 'source');
                                }
                            }
                        }
                    }
                }

                // Evaluate the finish proposal through the hard finish gate
                const schedDecision = schedulerDecision({
                    state: scanState,
                    evidence: evidenceLedger,
                    workItems: workItemQueue,
                    handlers: handlerInventory,
                    candidates: candidateStore,
                    investigation: investigationState,
                    target,
                    functionBoundaries,
                });

                const gateResult = evaluateFinishGate({
                    proposal: action,
                    state: scanState,
                    evidence: evidenceLedger,
                    workItems: workItemQueue,
                    handlers: handlerInventory,
                    candidates: candidateStore,
                    investigation: investigationState,
                    scheduler: schedDecision,
                    target: { filePath: target.filePath, fileContent: target.fileContent },
                });

                if (gateResult.accepted) {
                    trace.logRunCompleted('completed');
                    if (gateResult.mode === 'forced-incomplete') {
                        terminateScan(scanState, 'forced_incomplete', 'Budget exhausted with incomplete investigation');
                        qualityTracker.recordForcedTermination('forced_incomplete');
                    } else {
                        terminateScan(scanState, 'agent_finish', gateResult.normalizedFinish?.summary);
                        qualityTracker.recordTermination('agent_finish');
                    }

                    // Merge gate-generated coverage gaps with model-provided gaps
                    let coverageGaps = action.coverageGaps ?? [];
                    if (gateResult.coverageGaps) {
                        coverageGaps = [...coverageGaps, ...gateResult.coverageGaps];
                    }

                    const covSummary = investigationState.getCoverageSummary(target.filePath);
                    qualityTracker.recordCoverage(covSummary.totalLines, covSummary.coveredLines, covSummary.uncoveredRangeCount, covSummary.largestUncoveredRange);
                    qualityTracker.recordBudget(stepsTaken, stepsGranted, extensionsGranted, costSpentUsd, budget.costCapUsd, wallClockMs, Date.now() - startTime);

                    return {
                        status: 'completed',
                        findings: sanitizeFindings(action.findings),
                        investigationNotes: action.investigationNotes ?? [],
                        coverageGaps,
                        transcript,
                        stepsUsed: stepsTaken,
                        stepsGranted,
                        extensionsGranted,
                        costSpentUsd,
                        terminationReason: gateResult.mode === 'forced-incomplete' ? 'forced_incomplete' : 'agent_finish',
                        summary: action.summary,
                        qualityMetrics: qualityTracker.getMetrics(),
                    };
                }

                // Finish rejected — continue investigation
                trace.logToolBlocked('finish', `Finish rejected: ${gateResult.reasons.map(r => r.description).join('; ')}`);
                qualityTracker.recordFinishRejection();

                // Add a system event so the model sees the rejection
                const rejectionMessage = `FINISH REJECTED — your investigation is incomplete:\n${gateResult.reasons.map(r => `  - ${r.description}`).join('\n')}\n\nYou must complete the remaining investigation steps before calling finish.${gateResult.recoveryAction ? `\n\nYour next action MUST be: ${gateResult.recoveryAction.type}` : ''}`;
                transcript.push({
                    action: {
                        type: 'system_event',
                        eventType: 'finish_rejected',
                        message: rejectionMessage,
                    } as any,
                    observation: rejectionMessage,
                });

                // Execute the recovery action if the scheduler has one
                if (gateResult.recoveryAction) {
                    const recoveryAction = gateResult.recoveryAction;
                    stepsTaken++;
                    budget.stepsRemaining--;
                    scanState.budget.stepsUsed = stepsTaken;
                    scanState.budget.stepsRemaining = budget.stepsRemaining;
                    trace.nextStep();
                    trace.logActionSelected(recoveryAction.type, 'finish-gate-recovery', false);
                    if (options.onProgress) {
                        options.onProgress(stepsTaken, stepsGranted, `Step ${stepsTaken}: finish-gate recovery: ${describeAction(recoveryAction)}`);
                    }

                    let recoveryObservation: string;
                    if (recoveryAction.type === 'read_file') {
                        const readResult = await executeReadFileAction(recoveryAction, ctx);
                        recoveryObservation = readResult.observation;
                        if (readResult.totalLines > 0) {
                            investigationState.recordActualRead(
                                (recoveryAction as any).path,
                                readResult.actualStart,
                                readResult.actualEnd,
                                readResult.totalLines,
                                readResult.truncated,
                            );
                        }
                    } else {
                        recoveryObservation = await executeAction(recoveryAction, ctx, startResp.runId, client, target);
                    }
                    qualityTracker.recordToolUse(recoveryAction.type); investigationState.recordToolUse(recoveryAction.type);
                    trace.logToolCompleted(recoveryAction.type, recoveryObservation);
                    transcript.push({ action: recoveryAction, observation: `[FINISH GATE RECOVERY] ${recoveryObservation}` });
                }

                continue;
            }

            // Sync candidates-verified: when all candidates are ready for the
            // Juror (supported or terminal) or there are none, the
            // candidates-verified step is complete.
            if (candidateStore.allReadyForJuror()) {
                investigationState.markCandidatesVerified();
            }

            // Execute the action locally
            let observation: string;
            let wasBlocked = false;
            // Reset progress flag — only set to true when actual progress is made
            meaningfulProgressSinceRecovery = false;

            if (action.type === 'read_file') {
                const normalizedPath = action.path.replace(/\\/g, '/').toLowerCase();
                let totalLines: number | undefined;
                try {
                    const fs = require('fs');
                    const abs = require('path').resolve(ctx.workspaceRoot, action.path);
                    const content = fs.readFileSync(abs, 'utf8');
                    totalLines = content.split('\n').length;
                } catch { /* best-effort */ }

                const readValue = investigationState.classifyRead(
                    action.path, action.startLine, action.endLine, totalLines,
                );
                const checklist = investigationState.formatChecklistForPrompt();
                const fileMax = maxReadsForFile(action.path);
                const count = investigationState.getReadCount(action.path);

                if (readValue.classification === 'duplicate') {
                    qualityTracker.recordRead('duplicate', false);
                    investigationState.recordBlockedRead(action.path);
                    const nextHint = readValue.nextUnreadRange
                        ? `\nNext unread range: lines ${readValue.nextUnreadRange.start}-${readValue.nextUnreadRange.end}. Use read_file with startLine=${readValue.nextUnreadRange.start} and endLine=${readValue.nextUnreadRange.end}.`
                        : '';
                    observation = `BLOCKED: Lines ${action.startLine || 'all'}-${action.endLine || 'all'} of "${action.path}" were already read. The content is in the transcript above.${nextHint}\n\n${checklist}`;
                    wasBlocked = true;
                } else if (readValue.classification === 'high-overlap') {
                    qualityTracker.recordRead('high-overlap', false);
                    investigationState.recordBlockedRead(action.path);
                    const nextHint = readValue.nextUnreadRange
                        ? `\nNext unread range: lines ${readValue.nextUnreadRange.start}-${readValue.nextUnreadRange.end}. Use read_file with startLine=${readValue.nextUnreadRange.start} and endLine=${readValue.nextUnreadRange.end}.`
                        : '';
                    observation = `BLOCKED: Lines ${action.startLine || 1}-${action.endLine || totalLines || '?'} of "${action.path}" substantially overlap already-read ranges (${readValue.newLines} new lines of ${(action.endLine || 0) - (action.startLine || 1) + 1} requested). The content is in the transcript above. Read a DIFFERENT section or use trace_flow/check_guard/check_policy to analyze what you've already read.${nextHint}\n\n${checklist}`;
                    wasBlocked = true;
                } else if (readValue.classification === 'invalid') {
                    qualityTracker.recordRead('invalid', false);
                    investigationState.recordBlockedRead(action.path);
                    observation = `BLOCKED: Invalid range for "${action.path}" (startLine=${action.startLine}, endLine=${action.endLine}). The requested range is inverted or out of bounds. Use a valid line range.\n\n${checklist}`;
                    wasBlocked = true;
                } else {
                    qualityTracker.recordRead(readValue.classification, false);
                    const readResult = await executeReadFileAction(action, ctx);
                    observation = readResult.observation;
                    qualityTracker.recordRead(readValue.classification, readResult.truncated);

                    if (readResult.totalLines > 0 && !readResult.truncated) {
                        investigationState.recordActualRead(
                            action.path,
                            readResult.actualStart,
                            readResult.actualEnd,
                            readResult.totalLines,
                            readResult.truncated,
                        );
                        const rangeKey = `${normalizedPath}:${readResult.actualStart || 0}:${readResult.actualEnd || 0}`;
                        readFiles.add(rangeKey);
                        qualityTracker.recordToolUse('read_file'); investigationState.recordToolUse('read_file');
                        meaningfulProgressSinceLastExtension = true;
                        meaningfulProgressSinceRecovery = true;

                        if (count >= fileMax) {
                            observation += `\n\nNOTE: You have read "${action.path}" ${count + 1} times. Consider using search_code, trace_flow, check_guard, or check_policy to analyze the code you've read. If you have enough evidence, call finish to report your findings.\n\n${checklist}`;
                        }
                    } else if (readResult.truncated) {
                        investigationState.recordActualRead(
                            action.path,
                            readResult.actualStart,
                            readResult.actualEnd,
                            readResult.totalLines,
                            readResult.truncated,
                        );
                        qualityTracker.recordToolUse('read_file'); investigationState.recordToolUse('read_file');
                        meaningfulProgressSinceLastExtension = false;
                        meaningfulProgressSinceRecovery = false;
                    } else {
                        investigationState.recordBlockedRead(action.path);
                    }
                }
            } else {
                // Dedup non-read tools: prevent the agent from calling the
                // same search_code("foo") or trace_flow("bar.ts") repeatedly.
                // Build a key from the action type + its primary argument.
                let toolKey = '';
                if (action.type === 'search_code') {
                    toolKey = `search_code:${(action as any).pattern || ''}:${(action as any).glob || ''}`;
                } else if (action.type === 'trace_flow' || action.type === 'trace_flow_cross_file') {
                    toolKey = `${action.type}:${(action as any).filePath || ''}`;
                } else if (action.type === 'check_guard') {
                    toolKey = `check_guard:${(action as any).guardName || ''}:${(action as any).attackType || ''}`;
                } else if (action.type === 'check_policy') {
                    toolKey = `check_policy:${(action as any).filePath || ''}`;
                } else if (action.type === 'call_graph') {
                    toolKey = `call_graph:${(action as any).filePath || ''}:${(action as any).functionName || ''}`;
                } else if (action.type === 'git_blame') {
                    toolKey = `git_blame:${(action as any).filePath || ''}:${(action as any).startLine || 0}:${(action as any).endLine || 0}`;
                } else if (action.type === 'git_history') {
                    toolKey = `git_history:${(action as any).filePath || ''}:${(action as any).functionName || ''}`;
                } else if (action.type === 'git_diff') {
                    toolKey = `git_diff:${(action as any).baseRef || ''}:${(action as any).headRef || 'HEAD'}`;
                } else if (action.type === 'check_dependencies') {
                    toolKey = `check_dependencies`;
                } else if (action.type === 'read_config') {
                    toolKey = `read_config:${(action as any).configKind || 'all'}`;
                } else if (action.type === 'find_definition') {
                    toolKey = `find_definition:${(action as any).filePath || ''}:${(action as any).symbol || ''}`;
                } else if (action.type === 'find_references') {
                    toolKey = `find_references:${(action as any).filePath || ''}:${(action as any).symbol || ''}`;
                } else if (action.type === 'find_tests') {
                    toolKey = `find_tests:${(action as any).filePath || ''}:${(action as any).symbol || ''}`;
                } else if (action.type === 'run_tests') {
                    const a = action as any;
                    if (a.mode === 'existing') {
                        toolKey = `run_tests:existing:${(a.testFiles || []).join(',')}:${a.testPattern || ''}:${a.packageManager || ''}`;
                    } else {
                        const crypto = require('crypto');
                        const scriptHash = a.script ? crypto.createHash('sha256').update(a.script).digest('hex').substring(0, 16) : '';
                        toolKey = `run_tests:generated:${a.runner || ''}:${scriptHash}`;
                    }
                }

                if (toolKey) {
                    // Check for equivalent search intent (same terms, different
                    // order) before the raw toolKey dedup.
                    if (action.type === 'search_code') {
                        const pattern = (action as any).pattern || '';
                        const normalized = normalizeSearchPattern(pattern);
                        let isEquivalent = false;
                        for (const prev of searchedPatterns) {
                            if (isEquivalentSearchIntent(prev, pattern)) {
                                isEquivalent = true;
                                break;
                            }
                        }
                        if (isEquivalent) {
                            equivalentSearchCount++;
                            if (equivalentSearchCount >= 2) {
                                observation = `BLOCKED: This search is equivalent to a previous search (same terms, different order). The results are in the transcript above. Use find_definition, find_references, call_graph, a targeted read_file with specific line numbers, or trace_flow_cross_file instead.`;
                                wasBlocked = true;
                                const checklist = investigationState.formatChecklistForPrompt();
                                observation += `\n\n${checklist}`;
                                // Skip execution — jump to the blocked handling
                                transcript.push({ action, observation });
                                trace.logToolBlocked(action.type, observation.slice(0, 200));
                                consecutiveBlockedReads++;
                                continue;
                            }
                        }
                        searchedPatterns.add(normalized);
                    }

                    const count = (toolCallCounts.get(toolKey) || 0) + 1;
                    toolCallCounts.set(toolKey, count);
                    if (count > MAX_SAME_TOOL_CALL) {
                        observation = `You have already called this exact tool with the same arguments ${MAX_SAME_TOOL_CALL} times. The result is in the transcript above. Use a DIFFERENT tool, different arguments, or call finish to report your findings.`;
                        wasBlocked = true;
                    } else {
                        observation = await executeAction(action, ctx, startResp.runId, client, target);
                        qualityTracker.recordToolUse(action.type); investigationState.recordToolUse(action.type);
                        if (action.type === 'search_code') {
                            investigationState.recordSymbolSearch((action as any).pattern || '');
                        }
                        // First call with these args = meaningful progress.
                        // Repeated call (count > 1) does NOT reset recovery state.
                        const isFirstCall = count === 1;
                        meaningfulProgressSinceLastExtension = isFirstCall;
                        if (isFirstCall) {
                            meaningfulProgressSinceRecovery = true;
                        }
                    }
                } else {
                    observation = await executeAction(action, ctx, startResp.runId, client, target);
                    qualityTracker.recordToolUse(action.type); investigationState.recordToolUse(action.type);
                    meaningfulProgressSinceLastExtension = true;
                    meaningfulProgressSinceRecovery = true;
                }
            }

            // Track consecutive blocked reads — quality-first: don't
            // force-finish while unread ranges remain and budget is available.
            // Instead, force a deterministic recovery action.
            if (wasBlocked) {
                trace.logToolBlocked(action.type, observation.slice(0, 200));
                consecutiveBlockedReads++;
                scanState.recovery.consecutiveBlockedActions = consecutiveBlockedReads;
                scanState.recovery.totalBlockedActions++;
                scanState.recovery.lastBlockedAction = action.type;
                scanState.recovery.meaningfulProgressSinceRecovery = false;
                const recoveryLimit = AGENT_SCAN_DEFAULTS.blockedReadRecoveryLimit;

                if (consecutiveBlockedReads >= 2 && consecutiveBlockedReads < 3) {
                    const nextRange = target.fileContent
                        ? investigationState.getPrioritizedUnreadRange(target.filePath, target.fileContent)
                        : investigationState.getNextUnreadRange(target.filePath);
                    if (nextRange) {
                        observation += `\n\nRECOVERY REQUIRED: You have been blocked ${consecutiveBlockedReads} time(s). Read the next unread range: lines ${nextRange.start}-${nextRange.end}, or use an analysis tool (trace_flow, check_guard, check_policy).`;
                    } else {
                        const recommendedTool = investigationState.getRecommendedRecoveryAction();
                        if (recommendedTool) {
                            observation += `\n\nRECOVERY REQUIRED: You have been blocked ${consecutiveBlockedReads} time(s). No unread ranges remain. Your next action MUST be: ${recommendedTool}. If you have enough evidence, call finish.`;
                        }
                    }
                }

                if (consecutiveBlockedReads >= recoveryLimit) {
                    const nextRange = target.fileContent
                        ? investigationState.getPrioritizedUnreadRange(target.filePath, target.fileContent)
                        : investigationState.getNextUnreadRange(target.filePath);
                    const hasBudget = budget.stepsRemaining > 0 && costSpentUsd < budget.costCapUsd;
                    const hasWallClock = Date.now() - startTime < wallClockMs;

                    if (nextRange && hasBudget && hasWallClock) {
                        console.warn(`[Agent Scan Loop] ${consecutiveBlockedReads} consecutive blocked reads — forcing deterministic recovery to unread range ${nextRange.start}-${nextRange.end}.`);
                    } else {
                        console.warn(`[Agent Scan Loop] ${consecutiveBlockedReads} consecutive blocked reads — no recovery available, force-finishing.`);
                        transcript.push({ action, observation });
                        trace.logRunCompleted('completed');
                        const incompleteSteps = investigationState.getIncompleteSteps();
                        const autoGaps = incompleteSteps.map(step => ({
                            title: `Investigation step not completed: ${step}`,
                            detail: `The agent was force-finished after repeated blocked reads without completing this required investigation step: ${step}. The investigation was incomplete and vulnerabilities may have been missed.`,
                            file: target.filePath,
                            requiredEvidence: [`Complete the ${step} step before concluding no vulnerabilities exist`],
                            suggestedNextAction: step === 'config-inspection' ? 'read_config'
                                : step === 'policy-check' ? 'check_policy'
                                : step === 'cross-file-flow' ? 'trace_flow_cross_file'
                                : step === 'route-discovery' ? 'get_endpoints'
                                : step === 'auth-symbol-search' ? 'search_code'
                                : 'continue investigation',
                            priority: 'high' as const,
                        }));
                        const unresolvedTasks = investigationState.getUnresolvedTasks();
                        const taskGaps = unresolvedTasks.map(task => ({
                            title: `Architecture risk unresolved: ${task.claim}`,
                            detail: `This architecture-risk investigation task was not resolved: ${task.claim}. Required evidence: ${task.requiredEvidence.join('; ')}.`,
                            file: task.targetFiles[0] || target.filePath,
                            requiredEvidence: task.requiredEvidence,
                            suggestedNextAction: task.requiredTools[0] || 'continue investigation',
                            priority: 'high' as const,
                        }));
                        const uncoveredRanges = investigationState.getUncoveredRanges(target.filePath);
                        const rangeGaps = uncoveredRanges.map(r => ({
                            title: `Unread range: lines ${r.start}-${r.end} of ${target.filePath}`,
                            detail: `This range was never read during the investigation. Vulnerabilities in this range were not checked.`,
                            file: target.filePath,
                            requiredEvidence: [`Read lines ${r.start}-${r.end} and analyze for vulnerabilities`],
                            suggestedNextAction: 'read_file',
                            priority: 'high' as const,
                        }));
                        const allGaps = [...autoGaps, ...taskGaps, ...rangeGaps];
                        terminateScan(scanState, 'blocked_read_recovery', `Agent stuck re-reading files. ${allGaps.length} coverage gaps.`);
                        qualityTracker.recordForcedTermination('blocked_read_recovery');
                        const covSummary = investigationState.getCoverageSummary(target.filePath);
                        qualityTracker.recordCoverage(covSummary.totalLines, covSummary.coveredLines, covSummary.uncoveredRangeCount, covSummary.largestUncoveredRange);
                        qualityTracker.recordBudget(stepsTaken, stepsGranted, extensionsGranted, costSpentUsd, budget.costCapUsd, wallClockMs, Date.now() - startTime);
                        return {
                            status: 'completed',
                            findings: [],
                            transcript,
                            stepsUsed: stepsTaken,
                            stepsGranted,
                            extensionsGranted,
                            costSpentUsd,
                            terminationReason: 'blocked_read_recovery',
                            summary: `Investigation cut short — agent was stuck re-reading files. ${allGaps.length} coverage gaps identified.`,
                            investigationNotes: [],
                            coverageGaps: allGaps,
                        };
                    }
                }
            } else {
                trace.logToolCompleted(action.type, observation);
                // Only reset the blocked counter when meaningful progress was
                // made. Repeated searches and truncated reads do NOT reset
                // recovery state — only new coverage, new symbols, or new
                // tool calls (first invocation with these args) do.
                if (meaningfulProgressSinceRecovery) {
                    consecutiveBlockedReads = 0;
                    scanState.recovery.consecutiveBlockedActions = 0;
                    scanState.recovery.meaningfulProgressSinceRecovery = true;
                }
            }

            // The agent needs both the action it tried and the block/observation
            // message — the original {action, observation} pair carries both.
            // We don't need a separate system_event for blocked (unlike
            // critique, the blocked case is tied to an action the agent took).
            transcript.push({ action, observation });

            // Link evidence to candidates: when the agent runs a verification
            // action (trace_flow, check_guard, check_policy, trace_flow_cross_file)
            // on a file that matches a candidate's location, add evidence to
            // that candidate. This auto-transitions candidates through
            // discovered → investigating → supported as evidence accumulates.
            if (!wasBlocked && candidateStore.size() > 0) {
                const verificationActions = new Set([
                    'trace_flow', 'trace_flow_cross_file', 'check_guard', 'check_policy',
                ]);
                if (verificationActions.has(action.type)) {
                    const actionFile = (action as any).filePath || (action as any).path || target.filePath;
                    const actionFileNorm = String(actionFile).replace(/\\/g, '/').toLowerCase();
                    for (const candidate of candidateStore.getAll()) {
                        const matchesLocation = candidate.locations.some(
                            loc => loc.filePath.replace(/\\/g, '/').toLowerCase() === actionFileNorm,
                        );
                        if (matchesLocation) {
                            const evidenceId = `${action.type}:${actionFileNorm}:${stepsTaken}`;
                            const category = action.type === 'trace_flow' || action.type === 'trace_flow_cross_file' ? 'flow' as const
                                : action.type === 'check_guard' ? 'guard' as const
                                : action.type === 'check_policy' ? 'policy' as const
                                : undefined;
                            candidateStore.addEvidence(candidate.id, evidenceId, category);
                        }
                    }
                }
                if (action.type === 'read_file' && candidateStore.size() > 0) {
                    const actionFileNorm = String((action as any).path || target.filePath).replace(/\\/g, '/').toLowerCase();
                    for (const candidate of candidateStore.getAll()) {
                        const matchesLocation = candidate.locations.some(
                            loc => loc.filePath.replace(/\\/g, '/').toLowerCase() === actionFileNorm,
                        );
                        if (matchesLocation && candidate.evidenceCategories?.includes('source') !== true) {
                            candidateStore.addEvidence(candidate.id, `source:${actionFileNorm}:${stepsTaken}`, 'source');
                        }
                    }
                }
            }

            // Link evidence to work items: when the agent runs an action on
            // a file that matches a work item's target files, add evidence
            // and resolve the work item if it has enough evidence.
            if (!wasBlocked && workItemQueue.size() > 0) {
                const actionFile = (action as any).filePath || (action as any).path || target.filePath;
                const actionFileNorm = String(actionFile).replace(/\\/g, '/').toLowerCase();
                for (const item of workItemQueue.getExecutable()) {
                    const matchesFile = item.targetFiles.some(
                        f => f.replace(/\\/g, '/').toLowerCase() === actionFileNorm,
                    );
                    if (matchesFile) {
                        const evidenceId = `${action.type}:${actionFileNorm}:${stepsTaken}`;
                        workItemQueue.addEvidence(item.id, evidenceId);
                        // Resolve if enough evidence collected
                        if (item.evidenceRefs.length >= item.requirements.length) {
                            workItemQueue.resolve(item.id);
                        }
                    }
                }
            }

            // Re-sync candidates-verified after evidence linking
            if (candidateStore.allReadyForJuror()) {
                investigationState.markCandidatesVerified();
            }

            // Evidence ledger: record evidence for each action type. This
            // populates the evidence ledger so the scheduler can suggest
            // actions for unsatisfied requirements and the finish gate can
            // verify all evidence requirements are met.
            if (!wasBlocked) {
                const actionFile = String((action as any).filePath || (action as any).path || target.filePath);
                const evidenceKindMap: Record<string, string> = {
                    read_file: 'source-range',
                    search_code: 'symbol-reference',
                    trace_flow: 'cross-file-flow',
                    trace_flow_cross_file: 'cross-file-flow',
                    check_guard: 'guard-result',
                    check_policy: 'policy-result',
                    get_endpoints: 'handler-inventory',
                    list_imports: 'symbol-reference',
                    find_definition: 'symbol-definition',
                    find_references: 'symbol-reference',
                    find_tests: 'test-location',
                    run_tests: 'test-result',
                    read_config: 'config-result',
                    call_graph: 'cross-file-flow',
                };
                const kind = evidenceKindMap[action.type];
                if (kind) {
                    evidenceLedger.recordEvidence({
                        kind: kind as any,
                        tool: action.type as any,
                        filePath: actionFile,
                        range: action.type === 'read_file'
                            ? { start: (action as any).startLine || 1, end: (action as any).endLine || 1 }
                            : undefined,
                        symbol: (action as any).symbol || (action as any).pattern || undefined,
                        outcome: wasBlocked ? 'blocked' : 'positive',
                        transcriptStep: stepsTaken,
                    });
                }
            }

            // Handler discovery: when the agent calls get_endpoints, discover
            // handlers and populate the handler inventory. Create handler
            // review work items for security-sensitive handlers.
            if (!wasBlocked && action.type === 'get_endpoints') {
                try {
                    const endpoints = await discoverEndpoints(
                        ctx.workspaceRoot,
                        (action as any).glob,
                    );
                    if (endpoints.length > 0) {
                        handlerInventory.addFromEndpoints(endpoints, target.filePath);
                        // Create work items for newly discovered handlers
                        for (const handler of handlerInventory.getAll()) {
                            if (!workItemQueue.all().some(w => w.title === `Review handler: ${handler.symbol || 'unknown'}`)) {
                                workItemQueue.add(createHandlerReviewWorkItem(
                                    handler.filePath,
                                    handler.symbol || 'unknown',
                                ));
                            }
                        }
                    } else {
                        // No handlers found — auto-complete all-handlers-reviewed
                        investigationState.markAllHandlersReviewed();
                    }
                } catch { /* best-effort */ }
            }

            // Auto-complete all-handlers-reviewed if handler inventory is
            // empty (no handlers to review for this file type)
            if (handlerInventory.size() === 0 && !investigationState.getCompletedSteps().includes('all-handlers-reviewed' as any)) {
                investigationState.markAllHandlersReviewed();
            }

            // Handler review tracking: when the agent reads a file range that
            // covers a handler's range, mark that handler as reviewed.
            if (!wasBlocked && action.type === 'read_file' && handlerInventory.size() > 0) {
                const readStart = (action as any).startLine || 1;
                const readEnd = (action as any).endLine || 9999;
                const readFileNorm = String((action as any).path || target.filePath).replace(/\\/g, '/').toLowerCase();
                for (const handler of handlerInventory.getAll()) {
                    if (!handler.reviewed) {
                        const handlerFileNorm = handler.filePath.replace(/\\/g, '/').toLowerCase();
                        if (handlerFileNorm === readFileNorm) {
                            if (handler.range.start >= readStart && handler.range.end <= readEnd) {
                                handlerInventory.markReviewed(handler.id);
                            }
                        }
                    }
                }
            }

            // Deterministic recovery: on the third consecutive blocked read,
            // skip the API and directly execute a recovery action selected by
            // the MCP. This prevents wasting API calls on an agent that is
            // stuck re-reading files.
            if (wasBlocked && consecutiveBlockedReads >= 3) {
                const recoveryAction = selectDeterministicRecoveryAction(
                    investigationState, target, ctx,
                );
                if (recoveryAction) {
                    stepsTaken++;
                    budget.stepsRemaining--;
                    trace.nextStep();
                    trace.logActionSelected(recoveryAction.type, 'deterministic-recovery', false);
                    if (options.onProgress) {
                        options.onProgress(stepsTaken, stepsGranted, `Step ${stepsTaken}: deterministic recovery: ${describeAction(recoveryAction)}`);
                    }

                    let recoveryObservation: string;
                    if (recoveryAction.type === 'read_file') {
                        const readResult = await executeReadFileAction(recoveryAction, ctx);
                        recoveryObservation = readResult.observation;
                        if (readResult.totalLines > 0) {
                            investigationState.recordActualRead(
                                (recoveryAction as any).path,
                                readResult.actualStart,
                                readResult.actualEnd,
                                readResult.totalLines,
                                readResult.truncated,
                            );
                        }
                    } else {
                        recoveryObservation = await executeAction(recoveryAction, ctx, startResp.runId, client, target);
                    }
                    qualityTracker.recordToolUse(recoveryAction.type); investigationState.recordToolUse(recoveryAction.type);
                    consecutiveBlockedReads = 0; // recovery resets the counter
                    meaningfulProgressSinceRecovery = true; // recovery is meaningful progress
                    trace.logToolCompleted(recoveryAction.type, recoveryObservation);
                    transcript.push({ action: recoveryAction, observation: `[DETERMINISTIC RECOVERY] ${recoveryObservation}` });
                }
            }
        }
    } catch (err: any) {
        return {
            status: 'spawn_failed',
            findings: [],
            transcript: [],
            stepsUsed: stepsTaken,
            stepsGranted,
            extensionsGranted,
            costSpentUsd,
            terminationReason: 'api_error',
            error: err.message || String(err),
            investigationNotes: [],
            coverageGaps: [],
        };
    }
}

function isCoherentText(text: string): boolean {
    if (!text || text.length < 5) return false;
    const asciiLetters = (text.match(/[a-zA-Z]/g) || []).length;
    const totalChars = text.length;
    if (totalChars > 0 && asciiLetters / totalChars < 0.3) return false;
    const controlChars = (text.match(/[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFD]/g) || []).length;
    if (controlChars > 0) return false;
    const words = text.split(/\s+/).filter(w => w.length > 1);
    if (words.length < 3) return false;
    return true;
}

function sanitizeFindingText(text: string): string {
    if (!text) return text;
    return text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFD]/g, '').trim();
}

function sanitizeFindings(findings: any[]): any[] {
    return findings.map(f => {
        const sanitized = { ...f };
        if (sanitized.why) {
            sanitized.why = sanitizeFindingText(sanitized.why);
            if (!isCoherentText(sanitized.why)) {
                sanitized.why = `[Quality warning: model produced incoherent explanation] ${sanitized.why || '(empty)'}`;
                if (sanitized.severity === 'high' || sanitized.severity === 'critical') {
                    sanitized.severity = 'medium';
                }
            }
        }
        if (sanitized.evidence) {
            sanitized.evidence = sanitizeFindingText(sanitized.evidence);
        }
        return sanitized;
    });
}

function describeAction(action: AgentScanAction): string {
    switch (action.type) {
        case 'read_file': return `read_file(${action.path})`;
        case 'search_code': return `search_code("${action.pattern}")`;
        case 'trace_flow': return `trace_flow(${action.filePath})`;
        case 'trace_flow_cross_file': return `trace_flow_cross_file(${action.filePath})`;
        case 'check_guard': return `check_guard(${action.guardName})`;
        case 'check_policy': return `check_policy(${action.filePath})`;
        case 'get_endpoints': return `get_endpoints(${(action as any).glob || 'all'})`;
        case 'list_imports': return `list_imports(${action.filePath})`;
        case 'list_files': return `list_files(${(action as any).path || 'root'})`;
        case 'call_graph': return `call_graph(${(action as any).filePath})`;
        case 'git_blame': return `git_blame(${(action as any).filePath})`;
        case 'git_history': return `git_history(${(action as any).filePath || 'repo'})`;
        case 'git_diff': return `git_diff(${(action as any).baseRef}..${(action as any).headRef || 'HEAD'})`;
        case 'check_dependencies': return 'check_dependencies';
        case 'read_config': return `read_config(${(action as any).configKind || 'all'})`;
        case 'find_definition': return `find_definition(${(action as any).symbol})`;
        case 'find_references': return `find_references(${(action as any).symbol})`;
        case 'find_tests': return `find_tests(${(action as any).filePath}${(action as any).symbol ? ':' + (action as any).symbol : ''})`;
        case 'run_tests': return `run_tests(${(action as any).mode}${(action as any).testFiles?.length ? ':' + (action as any).testFiles.length + ' files' : ''})`;
        case 'finish': return 'finish';
        case 'system_event': return `system_event(${(action as any).eventType})`;
    }
}

// Local type alias to avoid importing from api/types (which uses a different
// AgentScanStepResponse shape — the one here is the same as agentScanProtocol).
type AgentStepResponse = AgentScanStepResponse;

/**
 * Select a deterministic recovery action based on investigation state.
 *
 * Priority:
 *   1. Unread range exists on the target file → read_file(next unread range)
 *   2. route-discovery missing → get_endpoints
 *   3. policy-check missing → check_policy
 *   4. auth-symbol-search missing → search_code
 *   5. cross-file-flow missing → trace_flow_cross_file
 *   6. config-inspection missing → read_config
 *   7. tests-found missing → find_tests
 *   8. otherwise → null (force-finish will handle it)
 */
function selectDeterministicRecoveryAction(
    state: InvestigationState,
    target: AgentScanTarget,
    ctx: ServerContext,
): AgentScanAction | null {
    // Priority 1: unread range on the target file
    const nextRange = state.getNextUnreadRange(target.filePath);
    if (nextRange) {
        return {
            type: 'read_file',
            path: target.filePath,
            startLine: nextRange.start,
            endLine: nextRange.end,
            rationale: 'Deterministic recovery: reading next unread range',
        } as AgentScanAction;
    }

    // Priority 2-7: incomplete investigation steps
    const incomplete = state.getIncompleteSteps();
    for (const step of incomplete) {
        switch (step) {
            case 'route-discovery':
                return { type: 'get_endpoints', rationale: 'Deterministic recovery: route discovery' } as AgentScanAction;
            case 'policy-check':
                return { type: 'check_policy', filePath: target.filePath, rationale: 'Deterministic recovery: policy check' } as AgentScanAction;
            case 'auth-symbol-search':
                return { type: 'search_code', pattern: 'auth|require|guard|permission|owner', rationale: 'Deterministic recovery: auth symbol search' } as AgentScanAction;
            case 'cross-file-flow':
                return { type: 'trace_flow_cross_file', filePath: target.filePath, rationale: 'Deterministic recovery: cross-file flow' } as AgentScanAction;
            case 'config-inspection':
                return { type: 'read_config', configKind: 'all', rationale: 'Deterministic recovery: config inspection' } as AgentScanAction;
            case 'tests-found':
                return { type: 'find_tests', filePath: target.filePath, rationale: 'Deterministic recovery: find tests' } as AgentScanAction;
        }
    }

    return null;
}
