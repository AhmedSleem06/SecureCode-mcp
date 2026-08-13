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
    AGENT_SCAN_DEFAULTS,
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
        const startResp = await client.postJson<AgentScanStartResponse>('/agent/scan/start', {});

        const transcript: AgentScanTranscriptStep[] = [];

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
            };

            const stepResp = await client.postJson<AgentStepResponse>('/agent/scan/step', stepReq);
            costSpentUsd += stepResp.costUsd || 0;

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
            const observation = await executeAction(action, ctx, startResp.runId, client, target);

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
        case 'check_guard': return `check_guard(${action.guardName})`;
        case 'check_policy': return `check_policy(${action.filePath})`;
        case 'finish': return 'finish';
    }
}

// Local type alias to avoid importing from api/types (which uses a different
// AgentScanStepResponse shape — the one here is the same as agentScanProtocol).
type AgentStepResponse = AgentScanStepResponse;
