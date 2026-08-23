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
        const readFiles = new Set<string>();
        const readFileCounts = new Map<string, number>();
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

        let consecutiveErrors = 0;
        let consecutiveBlockedReads = 0;
        let meaningfulProgressSinceRecovery = true;

        while (true) {
            // Wall clock check
            if (Date.now() - startTime > wallClockMs) {
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

            // Build action constraint for deterministic blocked-read recovery.
            //   0-1 blocked reads: normal (no constraint)
            //   2 blocked reads: recovery mode, forbid read_file
            //   3 blocked reads: MCP selects a deterministic recovery action (skip API)
            //   5 blocked reads: force-finish
            let actionConstraint: AgentActionConstraint | undefined;
            if (consecutiveBlockedReads >= 2 && consecutiveBlockedReads < 3) {
                const recoveryAction = investigationState.getRecommendedRecoveryAction();
                actionConstraint = {
                    mode: 'recovery',
                    forbiddenActions: ['read_file'],
                    requiredAction: recoveryAction as any || undefined,
                    reason: 'You have been blocked by duplicate/overlapping reads. Switch to a different tool.',
                };
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
            consecutiveErrors = 0;
            trace.logStepRequested(undefined, stepResp.tokens, stepResp.costUsd, undefined);

            // Budget extension — the API may grant additional steps when the
            // agent demonstrates meaningful progress. Update our local tracking.
            if (stepResp.budgetExtension) {
                const ext = stepResp.budgetExtension;
                stepsGranted = ext.totalGranted;
                extensionsGranted = ext.granted > 0 ? extensionsGranted + 1 : extensionsGranted;
                budget.stepsRemaining = stepResp.stepsRemaining;
                budget.stepsGranted = ext.totalGranted;
                budget.extensionsGranted = extensionsGranted;
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
            trace.nextStep();
            trace.logActionSelected(action.type, undefined, stepResp.degraded);

            // Progress callback
            if (options.onProgress) {
                const actionDesc = describeAction(action);
                options.onProgress(stepsTaken, stepsGranted, `Step ${stepsTaken}: ${actionDesc}`);
            }

            // Finish = done with findings
            if (action.type === 'finish') {
                trace.logRunCompleted('completed');
                // Auto-generate coverage gaps for incomplete investigation steps
                // when the agent finishes with 0 findings
                let coverageGaps = action.coverageGaps ?? [];
                if (action.findings.length === 0) {
                    const incompleteSteps = investigationState.getIncompleteSteps();
                    if (incompleteSteps.length > 0) {
                        const autoGaps = incompleteSteps.map(step => ({
                            title: `Investigation step not completed: ${step}`,
                            detail: `The agent finished without completing this required investigation step: ${step}. This means the investigation was incomplete and vulnerabilities may have been missed.`,
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
                        coverageGaps = [...coverageGaps, ...autoGaps];
                    }
                }
                return {
                    status: 'completed',
                    findings: action.findings,
                    investigationNotes: action.investigationNotes ?? [],
                    coverageGaps,
                    transcript,
                    stepsUsed: stepsTaken,
                    stepsGranted,
                    extensionsGranted,
                    costSpentUsd,
                    terminationReason: 'agent_finish',
                    summary: action.summary,
                };
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

                const checkResult = investigationState.checkRead(
                    action.path, action.startLine, action.endLine, totalLines,
                );
                const rangeKey = `${normalizedPath}:${action.startLine || 0}:${action.endLine || 0}`;
                const checklist = investigationState.formatChecklistForPrompt();

                if (checkResult.isExactDuplicate) {
                    investigationState.recordBlockedRead(action.path);
                    observation = `File "${action.path}" (lines ${action.startLine || 'all'}-${action.endLine || 'all'}) was already read. The content is in the transcript above. Use a DIFFERENT line range or a different tool.\n\n${checklist}`;
                    wasBlocked = true;
                } else if (checkResult.overlapping && checkResult.overlapFraction > 0.5) {
                    investigationState.recordBlockedRead(action.path);
                    const coveredRanges = checkResult.coverageAfter
                        .filter(r => InvestigationState.rangesOverlap(
                            r,
                            InvestigationState.parseRange(action.startLine, action.endLine, totalLines),
                        ))
                        .map(r => `L${r.start}-${r.end}`)
                        .join(', ');
                    const nextRange = investigationState.getNextUnreadRange(action.path);
                    const nextHint = nextRange
                        ? `\nNext unread range: lines ${nextRange.start}-${nextRange.end}. Use read_file with startLine=${nextRange.start} and endLine=${nextRange.end}.`
                        : '';
                    observation = `BLOCKED: Lines ${action.startLine || 1}-${action.endLine || totalLines || '?'} of "${action.path}" substantially overlap already-read ranges (${coveredRanges}). The content is in the transcript above. Read a DIFFERENT section, use search_code to find specific patterns, or use trace_flow/check_guard/check_policy to analyze what you've already read.${nextHint}\n\n${checklist}`;
                    wasBlocked = true;
                } else {
                    const fileMax = maxReadsForFile(action.path);
                    const count = investigationState.getReadCount(action.path);
                    const stepFraction = count / Math.max(stepsTaken, 1);
                    if (count > fileMax) {
                        investigationState.recordBlockedRead(action.path);
                        observation = `BLOCKED: You have already read "${action.path}" ${fileMax} times. Further read_file calls on this file will also be blocked. You MUST use a different tool (search_code, trace_flow, check_guard, check_policy, list_imports, or finish) to proceed.\n\n${checklist}`;
                        wasBlocked = true;
                    } else if (stepFraction > 0.4 && count > 5) {
                        investigationState.recordBlockedRead(action.path);
                        observation = `BLOCKED: You have spent ${count} of ${stepsTaken} steps reading "${action.path}". That's too much — switch to search_code, trace_flow, check_guard, or check_policy to analyze the code you've already read. If you have enough evidence, call finish to report your findings.\n\n${checklist}`;
                        wasBlocked = true;
                    } else {
                        // Execute the read and get structured metadata about the
                        // ACTUAL delivered range (not the requested range).
                        const readResult = await executeReadFileAction(action, ctx);
                        observation = readResult.observation;

                        if (readResult.totalLines > 0) {
                            // Record the actual delivered range, not the requested range.
                            // A truncated read (function map) records no content coverage.
                            investigationState.recordActualRead(
                                action.path,
                                readResult.actualStart,
                                readResult.actualEnd,
                                readResult.totalLines,
                                readResult.truncated,
                            );
                        } else {
                            // File read failed (error) — record as blocked, not covered.
                            investigationState.recordBlockedRead(action.path);
                        }
                        const rangeKey = `${normalizedPath}:${readResult.actualStart || 0}:${readResult.actualEnd || 0}`;
                        readFiles.add(rangeKey);
                        investigationState.recordToolUse('read_file');
                        // Meaningful progress = actual content lines delivered
                        // (not a truncated function map). Truncated reads don't
                        // earn extension credit or reset recovery state.
                        meaningfulProgressSinceLastExtension = !readResult.truncated;
                        meaningfulProgressSinceRecovery = !readResult.truncated;
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
                    const count = (toolCallCounts.get(toolKey) || 0) + 1;
                    toolCallCounts.set(toolKey, count);
                    if (count > MAX_SAME_TOOL_CALL) {
                        observation = `You have already called this exact tool with the same arguments ${MAX_SAME_TOOL_CALL} times. The result is in the transcript above. Use a DIFFERENT tool, different arguments, or call finish to report your findings.`;
                        wasBlocked = true;
                    } else {
                        observation = await executeAction(action, ctx, startResp.runId, client, target);
                        investigationState.recordToolUse(action.type);
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
                    investigationState.recordToolUse(action.type);
                    meaningfulProgressSinceLastExtension = true;
                    meaningfulProgressSinceRecovery = true;
                }
            }

            // Track consecutive blocked reads — if the agent keeps requesting
            // read_file on blocked files, force-finish to stop wasting steps.
            if (wasBlocked) {
                trace.logToolBlocked(action.type, observation.slice(0, 200));
                consecutiveBlockedReads++;
                const recoveryLimit = AGENT_SCAN_DEFAULTS.blockedReadRecoveryLimit;

                if (consecutiveBlockedReads >= 2 && consecutiveBlockedReads < 3) {
                    const recommendedTool = investigationState.getRecommendedRecoveryAction();
                    if (recommendedTool) {
                        observation += `\n\nRECOVERY REQUIRED: You have been blocked ${consecutiveBlockedReads} time(s). Do NOT call read_file again. Your next action MUST be: ${recommendedTool}. If you have enough evidence, call finish.`;
                    }
                }

                if (consecutiveBlockedReads >= recoveryLimit) {
                    console.warn(`[Agent Scan Loop] ${consecutiveBlockedReads} consecutive blocked reads — force-finishing to stop wasting steps.`);
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
                    return {
                        status: 'completed',
                        findings: [],
                        transcript,
                        stepsUsed: stepsTaken,
                        stepsGranted,
                        extensionsGranted,
                        costSpentUsd,
                        terminationReason: 'blocked_read_recovery',
                        summary: `Investigation cut short — agent was stuck re-reading files. ${autoGaps.length} coverage gaps identified.`,
                        investigationNotes: [],
                        coverageGaps: autoGaps,
                    };
                }
            } else {
                trace.logToolCompleted(action.type, observation);
                // Only reset the blocked counter when meaningful progress was
                // made. Repeated searches and truncated reads do NOT reset
                // recovery state — only new coverage, new symbols, or new
                // tool calls (first invocation with these args) do.
                if (meaningfulProgressSinceRecovery) {
                    consecutiveBlockedReads = 0;
                }
            }

            // The agent needs both the action it tried and the block/observation
            // message — the original {action, observation} pair carries both.
            // We don't need a separate system_event for blocked (unlike
            // critique, the blocked case is tied to an action the agent took).
            transcript.push({ action, observation });

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
                    investigationState.recordToolUse(recoveryAction.type);
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
