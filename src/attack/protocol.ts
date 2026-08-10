export type AgentHttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

export interface AgentHttpRequestAction {
    type: 'http_request';
    method: AgentHttpMethod;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
    rationale: string;
}

export interface AgentFinding {
    category: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    evidenceStepIndex: number;
}

export interface AgentFinishAction {
    type: 'finish';
    findings: AgentFinding[];
    summary: string;
}

export type AgentAction = AgentHttpRequestAction | AgentFinishAction;

export interface AgentObservation {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    latencyMs: number;
    error?: string;
}

export interface AgentTranscriptStep {
    action: AgentHttpRequestAction;
    observation: AgentObservation;
}

export interface AgentStartResponse {
    runId: string;
    budget: { stepsRemaining: number; costSpentUsd: number; costCapUsd: number };
    attackerCredits: number;
}

export interface AgentStepRequest {
    runId: string;
    endpointContext: unknown;
    language: string;
    framework?: string;
    handlerSource?: string;
    transcript: AgentTranscriptStep[];
    budget: { stepsRemaining: number; costSpentUsd: number; costCapUsd: number };
}

export interface AgentStepResponse {
    next: AgentAction | null;
    costUsd: number;
    tokens: number;
    degraded: boolean;
    costCapped: boolean;
    stepsRemaining: number;
}

export type AgentRunStatus = 'completed' | 'capped' | 'degraded' | 'spawn_failed' | 'cancelled';
