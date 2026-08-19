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
import { executeAction } from './agentScanExecutor';
import {
    validateStartResponse,
    validateStepResponse,
    type ValidationResult,
} from './protocolValidator';
import {
    AGENT_SCAN_DEFAULTS,
    defaultClientCapabilities,
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
        stepsRemaining: options.budget?.stepsRemaining ?? AGENT_SCAN_DEFAULTS.maxSteps,
        costSpentUsd: options.budget?.costSpentUsd ?? 0,
        costCapUsd: options.budget?.costCapUsd ?? AGENT_SCAN_DEFAULTS.costCapUsd,
    };

    const startTime = Date.now();
    const wallClockMs = AGENT_SCAN_DEFAULTS.wallClockMs;
    let stepsTaken = 0;
    let costSpentUsd = 0;

    try {
        const startRespRaw = await client.postJson<AgentScanStartResponse>('/agent/scan/start', {}, options.signal);
        const startValidation = validateStartResponse(startRespRaw);
        if (!startValidation.ok) {
            return {
                status: 'spawn_failed',
                findings: [],
                transcript: [],
                stepsUsed: 0,
                costSpentUsd: 0,
                error: `API returned an invalid start response: ${startValidation.error}`,
            };
        }
        const startResp = startValidation.value;

        const transcript: AgentScanTranscriptStep[] = [];
        const readFiles = new Set<string>();
        const readFileCounts = new Map<string, number>();
        // Dynamic read cap based on file size:
        //   < 200 lines  → 5 reads (small file, 5 chunks is enough)
        //   < 1000 lines  → 10 reads (medium file)
        //   < 5000 lines  → 20 reads (large file, needs many sections)
        //   >= 5000 lines → 30 reads (very large, allow thorough coverage)
        function maxReadsForFile(filePath: string): number {
            try {
                const fs = require('fs');
                const abs = require('path').resolve(ctx.workspaceRoot, filePath);
                const stat = fs.statSync(abs);
                if (stat.size > 200_000) return 30;
                const content = fs.readFileSync(abs, 'utf8');
                const lines = content.split('\n').length;
                if (lines < 200) return 5;
                if (lines < 1000) return 10;
                if (lines < 5000) return 20;
                return 30;
            } catch {
                return 10;
            }
        }
        // Track non-read tool calls to prevent the agent from looping on the
        // same search_code/trace_flow call repeatedly. Keyed by (type + args).
        const toolCallCounts = new Map<string, number>();
        const MAX_SAME_TOOL_CALL = 2;

        let consecutiveErrors = 0;
        let consecutiveBlockedReads = 0;

        while (true) {
            // Wall clock check
            if (Date.now() - startTime > wallClockMs) {
                return {
                    status: 'capped',
                    findings: [],
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: `Wall clock limit (${wallClockMs}ms) exceeded.`,
                };
            }

            // Abort check
            if (options.signal?.aborted) {
                return {
                    status: 'cancelled',
                    findings: [],
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: 'Cancelled by user.',
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
                },
                clientCapabilities: defaultClientCapabilities(),
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
                            costSpentUsd,
                            summary: `Step budget exhausted after ${consecutiveErrors} consecutive malformed API responses. Last error: ${vErr}`,
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
                        costSpentUsd,
                        error: 'API server restarted mid-scan — the run was lost. Please retry the scan.',
                    };
                }

                // Detect abort — the user cancelled. Don't treat as error.
                if (options.signal?.aborted || /aborted/i.test(errMsg)) {
                    return {
                        status: 'cancelled',
                        findings: [],
                        transcript,
                        stepsUsed: stepsTaken,
                        costSpentUsd,
                        summary: 'Cancelled by user.',
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
                        costSpentUsd,
                        summary: `Step budget exhausted after ${consecutiveErrors} consecutive API errors. Last error: ${errMsg}`,
                    };
                }
                continue;
            }
            costSpentUsd += stepResp.costUsd || 0;
            consecutiveErrors = 0;

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
                    options.onProgress(stepsTaken, AGENT_SCAN_DEFAULTS.maxSteps, `Step ${stepsTaken}: system_event(${ev.eventType})`);
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
                return {
                    status,
                    findings: [],
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: stepResp.costCapped
                        ? `Cost cap ($${budget.costCapUsd.toFixed(2)}) reached.`
                        : 'Agent completed without explicit finish.',
                };
            }

            const action: AgentScanAction = stepResp.next;
            stepsTaken++;
            budget.stepsRemaining = stepResp.stepsRemaining;

            // Progress callback
            if (options.onProgress) {
                const actionDesc = describeAction(action);
                options.onProgress(stepsTaken, AGENT_SCAN_DEFAULTS.maxSteps, `Step ${stepsTaken}: ${actionDesc}`);
            }

            // Finish = done with findings
            if (action.type === 'finish') {
                return {
                    status: 'completed',
                    findings: action.findings,
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: action.summary,
                };
            }

            // Execute the action locally
            let observation: string;
            let wasBlocked = false;

            if (action.type === 'read_file') {
                const normalizedPath = action.path.replace(/\\/g, '/').toLowerCase();
                // Track by (path, startLine, endLine) — allow re-reading with different ranges
                const rangeKey = `${normalizedPath}:${action.startLine || 0}:${action.endLine || 0}`;
                if (readFiles.has(rangeKey)) {
                    observation = `File "${action.path}" (lines ${action.startLine || 'all'}-${action.endLine || 'all'}) was already read. The content is in the transcript above. Use a DIFFERENT line range or a different tool.`;
                    wasBlocked = true;
                } else {
                    // Per-file read cap: dynamic based on file size.
                    // Small files (7 lines) get 5 reads; large files (5000 lines)
                    // get up to 30 reads so the agent can cover the whole file.
                    const fileMax = maxReadsForFile(action.path);
                    const count = (readFileCounts.get(normalizedPath) || 0) + 1;
                    if (count > fileMax) {
                        observation = `BLOCKED: You have already read "${action.path}" ${fileMax} times. Further read_file calls on this file will also be blocked. You MUST use a different tool (search_code, trace_flow, check_guard, check_policy, list_imports, or finish) to proceed.`;
                        wasBlocked = true;
                    } else {
                        readFileCounts.set(normalizedPath, count);
                        readFiles.add(rangeKey);
                        observation = await executeAction(action, ctx, startResp.runId, client, target);
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
                } else if (action.type === 'check_dependencies') {
                    toolKey = `check_dependencies`;
                } else if (action.type === 'read_config') {
                    toolKey = `read_config:${(action as any).configKind || 'all'}`;
                }

                if (toolKey) {
                    const count = (toolCallCounts.get(toolKey) || 0) + 1;
                    toolCallCounts.set(toolKey, count);
                    if (count > MAX_SAME_TOOL_CALL) {
                        observation = `You have already called this exact tool with the same arguments ${MAX_SAME_TOOL_CALL} times. The result is in the transcript above. Use a DIFFERENT tool, different arguments, or call finish to report your findings.`;
                        wasBlocked = true;
                    } else {
                        observation = await executeAction(action, ctx, startResp.runId, client, target);
                    }
                } else {
                    observation = await executeAction(action, ctx, startResp.runId, client, target);
                }
            }

            // Track consecutive blocked reads — if the agent keeps requesting
            // read_file on blocked files, force-finish to stop wasting steps.
            if (wasBlocked) {
                consecutiveBlockedReads++;
                if (consecutiveBlockedReads >= 8) {
                    console.warn(`[Agent Scan Loop] ${consecutiveBlockedReads} consecutive blocked reads — force-finishing to stop wasting steps.`);
                    transcript.push({ action, observation });
                    return {
                        status: 'completed',
                        findings: [],
                        transcript,
                        stepsUsed: stepsTaken,
                        costSpentUsd,
                        summary: `Investigation cut short — agent was stuck re-reading files. No findings reported.`,
                    };
                }
            } else {
                consecutiveBlockedReads = 0;
            }

            // The agent needs both the action it tried and the block/observation
            // message — the original {action, observation} pair carries both.
            // We don't need a separate system_event for blocked (unlike
            // critique, the blocked case is tied to an action the agent took).
            transcript.push({ action, observation });
        }
    } catch (err: any) {
        return {
            status: 'spawn_failed',
            findings: [],
            transcript: [],
            stepsUsed: stepsTaken,
            costSpentUsd,
            error: err.message || String(err),
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
        case 'check_dependencies': return 'check_dependencies';
        case 'read_config': return `read_config(${(action as any).configKind || 'all'})`;
        case 'finish': return 'finish';
        case 'system_event': return `system_event(${(action as any).eventType})`;
    }
}

// Local type alias to avoid importing from api/types (which uses a different
// AgentScanStepResponse shape — the one here is the same as agentScanProtocol).
type AgentStepResponse = AgentScanStepResponse;
