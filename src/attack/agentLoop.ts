import { ApiClient } from '../api/client';
import type { ScanResponse, FixResponse, EndpointContext, ProjectMap } from '../api/types';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace } from '../utils/files';
import { executeHttpRequest } from './executor';
import { DEFAULT_BUDGET, validateTarget, checkBudget, type AttackBudget } from './policy';
import { redactText, buildReport, type AttackReport } from './report';
import type { AgentTranscriptStep, AgentAction, AgentStartResponse, AgentStepResponse, AgentRunStatus } from './protocol';

export interface AttackOptions {
    targetPort: number;
    targetHost?: string;
    budget?: Partial<AttackBudget>;
    signal?: AbortSignal;
}

export interface AttackResult {
    status: AgentRunStatus;
    report?: AttackReport;
    error?: string;
}

export async function runAttack(
    ctx: ServerContext,
    endpoint: { method: string; path: string; sourceFile: string; handlerName: string },
    code: string,
    language: string,
    options: AttackOptions,
): Promise<AttackResult> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
    const budget = { ...DEFAULT_BUDGET, ...options.budget };
    const target = {
        host: options.targetHost || '127.0.0.1',
        port: options.targetPort,
        path: endpoint.path,
    };

    validateTarget(target);

    const startTime = Date.now();
    let stepsTaken = 0;
    let requestsMade = 0;

    const state = { stepsTaken, requestsMade, startTime };

    try {
        const scanResp = await client.postJson<ScanResponse>('/scan', {
            code,
            language,
            filePath: endpoint.sourceFile,
            scanDepth: 'auto',
        });

        const findings = (scanResp.scanType === 'advanced' && scanResp.finalFindings)
            ? scanResp.finalFindings
            : (scanResp.findings || []);

        const attackable = (findings as any[]).filter((f: any) => {
            const type = f.type || f.check_id;
            return type && f.source !== 'dependency';
        });

        if (attackable.length === 0) {
            return { status: 'completed', error: 'No attackable vulnerability found in scan results.' };
        }

        const finding = attackable[0] as any;
        const loc = finding.location || {
            line_start: finding.start?.line,
            line_end: finding.end?.line ?? finding.start?.line,
        };

        const fixResp = await client.postJson<FixResponse>('/fix', {
            code,
            language,
            vulnerability: {
                type: finding.type || finding.check_id,
                line_start: loc.line_start ?? 1,
                line_end: loc.line_end ?? loc.line_start ?? 1,
                evidence_snippet: finding.evidence_snippet || '',
            },
        });

        if (!fixResp.fixed_code || fixResp.fixed_code.length === 0) {
            return { status: 'completed', error: 'Fixer returned no patch — nothing to attack.' };
        }

        const startResp = await client.postJson<AgentStartResponse>('/attack/agent/start', {});
        const runId = startResp.runId;

        const endpointContext: EndpointContext = {
            method: endpoint.method,
            path: endpoint.path,
            handlerName: endpoint.handlerName,
            sourceFile: endpoint.sourceFile,
            line: 0,
            middleware: [],
            params: [],
            authScheme: 'unknown',
            dataLayer: 'unknown',
            validatorLibrary: 'unknown',
            callGraph: [],
            responseShape: 'unknown',
            confidence: 0,
            runtimeConfirmed: false,
        };

        const transcript: AgentTranscriptStep[] = [];

        while (true) {
            const budgetCheck = checkBudget(budget, state);
            if (budgetCheck.exhausted) {
                return {
                    status: 'capped',
                    report: buildReport('capped', [], transcript, stepsTaken, 0, budgetCheck.reason),
                };
            }

            if (options.signal?.aborted) {
                return {
                    status: 'cancelled',
                    report: buildReport('cancelled', [], transcript, stepsTaken, 0, 'Cancelled by user'),
                };
            }

            const stepResp = await client.postJson<AgentStepResponse>('/attack/agent/step', {
                runId,
                endpointContext,
                language,
                handlerSource: code,
                transcript,
                budget: {
                    stepsRemaining: budget.maxSteps - stepsTaken,
                    costSpentUsd: 0,
                    costCapUsd: 0,
                },
            });

            if (!stepResp.next) {
                return {
                    status: stepResp.costCapped ? 'capped' : (stepResp.degraded ? 'degraded' : 'completed'),
                    report: buildReport(
                        stepResp.costCapped ? 'capped' : 'completed',
                        [],
                        transcript,
                        stepsTaken,
                        stepResp.costUsd || 0,
                    ),
                };
            }

            const action = stepResp.next;
            stepsTaken++;
            state.stepsTaken = stepsTaken;

            if (action.type === 'finish') {
                return {
                    status: 'completed',
                    report: buildReport('completed', action.findings || [], transcript, stepsTaken, stepResp.costUsd || 0, action.summary),
                };
            }

            if (action.type === 'http_request') {
                requestsMade++;
                state.requestsMade = requestsMade;

                const execResp = await executeHttpRequest(
                    {
                        method: action.method,
                        path: action.path,
                        host: target.host,
                        port: target.port,
                        headers: action.headers,
                        body: action.body,
                    },
                    budget,
                    options.signal,
                );

                transcript.push({
                    action,
                    observation: {
                        statusCode: execResp.statusCode,
                        headers: execResp.headers,
                        body: redactText(execResp.body).slice(0, 10_000),
                        latencyMs: execResp.latencyMs,
                        error: execResp.error,
                    },
                });
            }
        }
    } catch (err: any) {
        return {
            status: 'spawn_failed',
            error: err.message || String(err),
            report: buildReport('spawn_failed', [], [], stepsTaken, 0, err.message),
        };
    }
}
