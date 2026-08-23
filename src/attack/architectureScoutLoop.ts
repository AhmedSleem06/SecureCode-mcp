/**
 * Architecture scout loop driver — the MCP-side loop that drives the
 * architecture-scout subagent.
 *
 * Mirrors agentScanLoop.ts but with architecture-scout tools and a finish
 * action that returns an ArchitectureContext instead of vulnerability
 * findings.
 *
 * Flow:
 *   1. POST /agent/architecture/start → { runId, budget }
 *   2. while (true):
 *        POST /agent/architecture/step { runId, target, transcript, budget }
 *        ← { next: action | null }
 *        if null → done (capped or completed)
 *        if finish → done with ArchitectureContext
 *        execute action locally → observation
 *        push { action, observation } into transcript
 *   3. return result
 *
 * The loop inherits the system_event + protocolValidator hardening from
 * agentScanLoop: malformed API responses are rejected, errors are surfaced
 * as system_event(error) instead of fake read_file('__ERROR__').
 */

import { ApiClient } from '../api/client';
import type { ServerContext } from '../mcp/types';
import { executeScoutAction } from './architectureScoutExecutor';
import {
    ARCHITECTURE_SCOUT_DEFAULTS,
    scoutDefaultsForDepth,
    isScoutFinishAction,
    type ArchitectureDepth,
    type ArchitectureScoutAction,
    type ArchitectureScoutBudget,
    type ArchitectureScoutResult,
    type ArchitectureScoutRunStatus,
    type ArchitectureScoutStartResponse,
    type ArchitectureScoutStepRequest,
    type ArchitectureScoutStepResponse,
    type ArchitectureScoutTarget,
    type ArchitectureScoutTranscriptStep,
} from './architectureScoutProtocol';
import type { ArchitectureContext } from '../project-map/architectureContext';
import { ARCHITECTURE_CONTEXT_VERSION } from '../project-map/architectureContext';

// Re-use the agent-scan response validator shape. The architecture scout
// step response has the same fields as AgentScanStepResponse (minus
// systemEvent, which the scout doesn't use in v1). We validate inline
// rather than importing the agent-scan validator (which checks agent-scan
// action types the scout doesn't have).
import {
    validateStartResponse as validateAgentStartResponse,
} from './protocolValidator';

export interface ArchitectureScoutOptions {
    depth?: ArchitectureDepth;
    signal?: AbortSignal;
    onProgress?: (stepsTaken: number, maxSteps: number, message: string) => void;
    /** Project map builtAt — stamped on the result context for cache invalidation. */
    projectMapBuiltAt?: number;
    /** Project map schema version — stamped on the result context. */
    projectMapVersion?: number;
}

// ── Inline validators (scout-specific) ──────────────────────────────────────
//
// The scout action types are a subset of agent-scan's, but the validator in
// protocolValidator.ts checks the full agent-scan action union (including
// trace_flow, check_guard, etc.). Rather than weaken that validator, we
// validate the scout actions inline here. The start-response validator is
// shape-compatible, so we reuse it.

const VALID_SCOUT_ACTION_TYPES = new Set([
    'read_file', 'search_code', 'list_files', 'list_imports',
    'get_endpoints', 'call_graph', 'read_config', 'check_dependencies',
    'find_definition', 'find_references', 'finish',
]);

interface ScoutValidationOk { ok: true; value: ArchitectureScoutAction; }
interface ScoutValidationErr { ok: false; error: string; }
type ScoutValidationResult = ScoutValidationOk | ScoutValidationErr;

function validateScoutAction(raw: unknown): ScoutValidationResult {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        return { ok: false, error: 'action is not an object' };
    }
    const a = raw as Record<string, unknown>;
    const type = a.type;
    if (typeof type !== 'string' || !VALID_SCOUT_ACTION_TYPES.has(type)) {
        return { ok: false, error: `action.type is missing or unknown: ${String(type)}` };
    }
    // Light field checks for the primary tool args. The API controller does
    // deeper validation; here we just block obviously malformed actions
    // from reaching the executor.
    if (type === 'read_file' && (typeof a.path !== 'string' || a.path.length === 0)) {
        return { ok: false, error: 'read_file requires non-empty "path"' };
    }
    if (type === 'search_code' && (typeof a.pattern !== 'string' || a.pattern.length === 0)) {
        return { ok: false, error: 'search_code requires non-empty "pattern"' };
    }
    if (type === 'list_imports' && (typeof a.filePath !== 'string' || a.filePath.length === 0)) {
        return { ok: false, error: 'list_imports requires non-empty "filePath"' };
    }
    if (type === 'call_graph' && (typeof a.filePath !== 'string' || a.filePath.length === 0)) {
        return { ok: false, error: 'call_graph requires non-empty "filePath"' };
    }
    if (type === 'read_config') {
        const validKinds = new Set(['auth', 'cors', 'rate_limit', 'headers', 'env', 'all']);
        if (typeof a.configKind !== 'string' || !validKinds.has(a.configKind)) {
            return { ok: false, error: 'read_config requires valid "configKind"' };
        }
    }
    if (type === 'find_definition' || type === 'find_references') {
        if (typeof a.filePath !== 'string' || a.filePath.length === 0) {
            return { ok: false, error: `${type} requires non-empty "filePath"` };
        }
        if (typeof a.symbol !== 'string' || a.symbol.length === 0) {
            return { ok: false, error: `${type} requires non-empty "symbol"` };
        }
    }
    if (type === 'finish') {
        if (typeof a.summary !== 'string' || a.summary.length === 0) {
            return { ok: false, error: 'finish requires "summary"' };
        }
        if (typeof a.selfCritique !== 'string' || a.selfCritique.length === 0) {
            return { ok: false, error: 'finish requires "selfCritique"' };
        }
        if (typeof a.architecture !== 'object' || a.architecture === null) {
            return { ok: false, error: 'finish requires "architecture" object' };
        }
    }
    return { ok: true, value: raw as ArchitectureScoutAction };
}

function validateScoutStepResponse(raw: unknown): { ok: true; value: ArchitectureScoutStepResponse } | { ok: false; error: string } {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
        return { ok: false, error: 'step response is not an object' };
    }
    const r = raw as Record<string, unknown>;
    if (r.next !== null && r.next !== undefined) {
        const actionResult = validateScoutAction(r.next);
        if (!actionResult.ok) return { ok: false, error: `step response next: ${actionResult.error}` };
    }
    if (typeof r.costUsd !== 'number') return { ok: false, error: 'costUsd must be a number' };
    if (typeof r.tokens !== 'number') return { ok: false, error: 'tokens must be a number' };
    if (typeof r.degraded !== 'boolean') return { ok: false, error: 'degraded must be a boolean' };
    if (typeof r.costCapped !== 'boolean') return { ok: false, error: 'costCapped must be a boolean' };
    if (typeof r.stepsRemaining !== 'number') return { ok: false, error: 'stepsRemaining must be a number' };
    return { ok: true, value: raw as ArchitectureScoutStepResponse };
}

// ── Main loop ───────────────────────────────────────────────────────────────

export async function runArchitectureScout(
    ctx: ServerContext,
    target: ArchitectureScoutTarget,
    options: ArchitectureScoutOptions = {},
): Promise<ArchitectureScoutResult> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const depth = options.depth ?? 'standard';
    const defaults = scoutDefaultsForDepth(depth);
    const budget: ArchitectureScoutBudget = {
        stepsRemaining: defaults.maxSteps,
        costSpentUsd: 0,
        costCapUsd: defaults.costCapUsd,
    };

    const startTime = Date.now();
    const wallClockMs = defaults.wallClockMs;
    let stepsTaken = 0;
    let costSpentUsd = 0;

    try {
        const startRespRaw = await client.postJson<ArchitectureScoutStartResponse>(
            '/agent/architecture/start', { depth }, options.signal,
        );
        // Re-use the agent-scan start response validator — the shape is
        // identical (runId, budget, scanCredits, refundId).
        const startValidation = validateAgentStartResponse(startRespRaw);
        if (!startValidation.ok) {
            return {
                status: 'spawn_failed',
                architecture: null,
                transcript: [],
                stepsUsed: 0,
                costSpentUsd: 0,
                error: `API returned an invalid start response: ${startValidation.error}`,
            };
        }
        const startResp = startValidation.value;

        const transcript: ArchitectureScoutTranscriptStep[] = [];
        const readFiles = new Set<string>();
        const readFileCounts = new Map<string, number>();
        const toolCallCounts = new Map<string, number>();
        const MAX_SAME_TOOL_CALL = 2;
        let consecutiveErrors = 0;

        while (true) {
            if (Date.now() - startTime > wallClockMs) {
                return {
                    status: 'capped',
                    architecture: null,
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: `Wall clock limit (${wallClockMs}ms) exceeded.`,
                };
            }
            if (options.signal?.aborted) {
                return {
                    status: 'cancelled',
                    architecture: null,
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: 'Cancelled by user.',
                };
            }

            const stepReq: ArchitectureScoutStepRequest = {
                runId: startResp.runId,
                target,
                transcript,
                budget: {
                    stepsRemaining: budget.stepsRemaining,
                    costSpentUsd,
                    costCapUsd: budget.costCapUsd,
                },
            };

            let stepResp: ArchitectureScoutStepResponse;
            try {
                const stepRespRaw = await client.postJson<ArchitectureScoutStepResponse>(
                    '/agent/architecture/step', stepReq, options.signal,
                );
                const stepValidation = validateScoutStepResponse(stepRespRaw);
                if (!stepValidation.ok) {
                    const vErr = stepValidation.error;
                    console.warn(`[Architecture Scout] Step ${stepsTaken + 1} returned a malformed response: ${vErr}`);
                    consecutiveErrors++;
                    stepsTaken++;
                    budget.stepsRemaining--;
                    const errMsg = `API returned a malformed step response: ${vErr}`;
                    transcript.push({
                        action: { type: 'finish', architecture: {} as any, summary: '', selfCritique: errMsg } as any,
                        observation: errMsg,
                    });
                    if (consecutiveErrors >= 3 || budget.stepsRemaining <= 0) {
                        return {
                            status: 'capped',
                            architecture: null,
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

                if (apiCode === 'AGENT_RUN_NOT_FOUND' || /AGENT_RUN_NOT_FOUND|Invalid or expired agent run/i.test(errMsg)) {
                    return {
                        status: 'spawn_failed',
                        architecture: null,
                        transcript,
                        stepsUsed: stepsTaken,
                        costSpentUsd,
                        error: 'API server restarted mid-scout — the run was lost. Please retry.',
                    };
                }
                if (options.signal?.aborted || /aborted/i.test(errMsg)) {
                    return {
                        status: 'cancelled',
                        architecture: null,
                        transcript,
                        stepsUsed: stepsTaken,
                        costSpentUsd,
                        summary: 'Cancelled by user.',
                    };
                }

                console.warn(`[Architecture Scout] Step ${stepsTaken + 1} error: ${errMsg}`);
                consecutiveErrors++;
                stepsTaken++;
                budget.stepsRemaining--;

                const errorMsg = `ERROR: Your previous action was rejected: ${errMsg}. Please try a DIFFERENT action with ALL required fields.`;
                transcript.push({
                    action: { type: 'finish', architecture: {} as any, summary: '', selfCritique: errorMsg } as any,
                    observation: errorMsg,
                });

                if (consecutiveErrors >= 3 || budget.stepsRemaining <= 0) {
                    return {
                        status: 'capped',
                        architecture: null,
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

            if (!stepResp.next) {
                const status: ArchitectureScoutRunStatus = stepResp.costCapped
                    ? 'capped'
                    : (stepResp.degraded ? 'degraded' : 'completed');
                return {
                    status,
                    architecture: null,
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: stepResp.costCapped
                        ? `Cost cap ($${budget.costCapUsd.toFixed(2)}) reached.`
                        : 'Scout completed without explicit finish.',
                };
            }

            const action: ArchitectureScoutAction = stepResp.next;
            stepsTaken++;
            budget.stepsRemaining = stepResp.stepsRemaining;

            if (options.onProgress) {
                options.onProgress(stepsTaken, defaults.maxSteps, `Step ${stepsTaken}: ${describeScoutAction(action)}`);
            }

            if (action.type === 'finish') {
                if (!isScoutFinishAction(action)) {
                    // Validator should have caught this, but double-check.
                    return {
                        status: 'spawn_failed',
                        architecture: null,
                        transcript,
                        stepsUsed: stepsTaken,
                        costSpentUsd,
                        error: 'Finish action did not pass type guard.',
                    };
                }
                // Stamp the context with cache/derivation metadata before
                // returning — the LLM doesn't know these fields.
                const ctx2 = action.architecture as ArchitectureContext;
                ctx2.version = ARCHITECTURE_CONTEXT_VERSION;
                ctx2.depth = depth;
                ctx2.derivedAt = Date.now();
                ctx2.projectMapBuiltAt = options.projectMapBuiltAt ?? 0;
                ctx2.projectMapVersion = options.projectMapVersion ?? 0;
                if (!ctx2.completeness) ctx2.completeness = 'partial';
                // Cap importantFiles at maxImportantFiles — the LLM may
                // exceed the cap despite the prompt instruction.
                if (ctx2.importantFiles && ctx2.importantFiles.length > target.maxImportantFiles) {
                    ctx2.importantFiles = ctx2.importantFiles
                        .sort((a, b) => b.importance - a.importance)
                        .slice(0, target.maxImportantFiles);
                }
                return {
                    status: 'completed',
                    architecture: ctx2,
                    transcript,
                    stepsUsed: stepsTaken,
                    costSpentUsd,
                    summary: action.summary,
                };
            }

            // Dedup: prevent the scout from re-reading the same file range
            // or calling the same tool with identical args repeatedly.
            let observation: string;
            let wasBlocked = false;

            if (action.type === 'read_file') {
                const normalizedPath = action.path.replace(/\\/g, '/').toLowerCase();
                const rangeKey = `${normalizedPath}:${action.startLine || 0}:${action.endLine || 0}`;
                if (readFiles.has(rangeKey)) {
                    observation = `File "${action.path}" (lines ${action.startLine || 'all'}-${action.endLine || 'all'}) was already read. The content is in the transcript above. Use a DIFFERENT line range or a different tool.`;
                    wasBlocked = true;
                } else {
                    const count = (readFileCounts.get(normalizedPath) || 0) + 1;
                    readFileCounts.set(normalizedPath, count);
                    readFiles.add(rangeKey);
                    observation = await executeScoutAction(action, ctx);
                    if (count >= 5) {
                        observation += `\n\nNOTE: You have read "${action.path}" ${count} times. Consider using search_code, call_graph, find_references, or finish to proceed.`;
                    }
                }
            } else {
                let toolKey = '';
                if (action.type === 'search_code') toolKey = `search_code:${action.pattern}:${action.glob || ''}`;
                else if (action.type === 'call_graph') toolKey = `call_graph:${action.filePath}:${action.functionName || ''}`;
                else if (action.type === 'list_imports') toolKey = `list_imports:${action.filePath}`;
                else if (action.type === 'find_definition') toolKey = `find_definition:${action.filePath}:${action.symbol}`;
                else if (action.type === 'find_references') toolKey = `find_references:${action.filePath}:${action.symbol}`;

                if (toolKey) {
                    const count = (toolCallCounts.get(toolKey) || 0) + 1;
                    toolCallCounts.set(toolKey, count);
                    if (count > MAX_SAME_TOOL_CALL) {
                        observation = `You have already called this exact tool with the same arguments ${MAX_SAME_TOOL_CALL} times. Use a DIFFERENT tool, different arguments, or call finish to report your architecture context.`;
                        wasBlocked = true;
                    } else {
                        observation = await executeScoutAction(action, ctx);
                    }
                } else {
                    observation = await executeScoutAction(action, ctx);
                }
            }

            transcript.push({ action, observation });
        }
    } catch (err: any) {
        return {
            status: 'spawn_failed',
            architecture: null,
            transcript: [],
            stepsUsed: stepsTaken,
            costSpentUsd,
            error: err.message || String(err),
        };
    }
}

function describeScoutAction(action: ArchitectureScoutAction): string {
    switch (action.type) {
        case 'read_file': return `read_file(${action.path})`;
        case 'search_code': return `search_code("${action.pattern}")`;
        case 'list_files': return `list_files(${(action as any).path || 'root'})`;
        case 'list_imports': return `list_imports(${action.filePath})`;
        case 'get_endpoints': return `get_endpoints(${(action as any).glob || 'all'})`;
        case 'call_graph': return `call_graph(${action.filePath}${action.functionName ? `, fn=${action.functionName}` : ''})`;
        case 'read_config': return `read_config(${action.configKind})`;
        case 'check_dependencies': return 'check_dependencies';
        case 'find_definition': return `find_definition(${action.symbol})`;
        case 'find_references': return `find_references(${action.symbol})`;
        case 'finish': return 'finish';
    }
    return 'unknown';
}

export { ARCHITECTURE_SCOUT_DEFAULTS };
