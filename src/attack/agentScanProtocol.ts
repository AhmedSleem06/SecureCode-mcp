/**
 * Scan-side agent — wire contract mirror.
 *
 * Mirror: api/src/attacker/agentScanProtocol.ts — keep string values in step.
 * Types are duplicated (not shared) between the API and MCP repos.
 */

export const AGENT_SCAN_DEFAULTS = {
    maxSteps: 20,
    costCapUsd: 0.40,
    wallClockMs: 180_000,
    perStepEstimateUsd: 0.08,
    creditsPerRun: 5,
    dailyRunLimit: 20,
} as const;

// ── Actions ─────────────────────────────────────────────────────────────────

export interface AgentScanReadFileAction {
    type: 'read_file';
    path: string;
    rationale: string;
}

export interface AgentScanSearchCodeAction {
    type: 'search_code';
    pattern: string;
    glob?: string;
    rationale: string;
}

export interface AgentScanTraceFlowAction {
    type: 'trace_flow';
    filePath: string;
    rationale: string;
}

export interface AgentScanCheckGuardAction {
    type: 'check_guard';
    filePath: string;
    guardName: string;
    attackType: AttackType;
    rationale: string;
}

export interface AgentScanCheckPolicyAction {
    type: 'check_policy';
    filePath: string;
    rationale: string;
}

export interface AgentScanFinding {
    line: number;
    lineEnd?: number;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    confidence: number;
    evidence: string;
    why: string;
    fixStrategy?: string;
}

export interface AgentScanFinishAction {
    type: 'finish';
    findings: AgentScanFinding[];
    summary: string;
}

export type AgentScanAction =
    | AgentScanReadFileAction
    | AgentScanSearchCodeAction
    | AgentScanTraceFlowAction
    | AgentScanCheckGuardAction
    | AgentScanCheckPolicyAction
    | AgentScanFinishAction;

export type AgentScanActionType =
    | 'read_file'
    | 'search_code'
    | 'trace_flow'
    | 'check_guard'
    | 'check_policy'
    | 'finish';

export type AttackType =
    | 'sql_injection'
    | 'nosql_injection'
    | 'command_injection'
    | 'xss'
    | 'ssrf'
    | 'path_traversal'
    | 'open_redirect'
    | 'prototype_pollution'
    | 'insecure_deserialization'
    | 'broken_access_control';

// ── Transcript ──────────────────────────────────────────────────────────────

export interface AgentScanTranscriptStep {
    action: AgentScanAction;
    observation: string;
}

// ── Budget ───────────────────────────────────────────────────────────────────

export interface AgentScanBudget {
    stepsRemaining: number;
    costSpentUsd: number;
    costCapUsd: number;
}

// ── Request / Response ──────────────────────────────────────────────────────

export interface AgentScanTarget {
    filePath: string;
    language: string;
    fileContent: string;
    endpointContext?: unknown;
}

export interface AgentScanStartResponse {
    runId: string;
    budget: AgentScanBudget;
    scanCredits: number;
    refundId: string;
}

export interface AgentScanStepRequest {
    runId: string;
    target: AgentScanTarget;
    transcript: AgentScanTranscriptStep[];
    budget: AgentScanBudget;
}

export interface AgentScanStepResponse {
    next: AgentScanAction | null;
    costUsd: number;
    tokens: number;
    degraded: boolean;
    costCapped: boolean;
    stepsRemaining: number;
}

export interface AgentScanToolRequest {
    runId: string;
    action: AgentScanCheckPolicyAction;
    target: AgentScanTarget;
}

export interface AgentScanToolResponse {
    observation: string;
}

export type AgentScanRunStatus =
    | 'completed'
    | 'capped'
    | 'degraded'
    | 'spawn_failed'
    | 'cancelled';

// ── Result ───────────────────────────────────────────────────────────────────

export interface AgentScanResult {
    status: AgentScanRunStatus;
    findings: AgentScanFinding[];
    summary?: string;
    transcript: AgentScanTranscriptStep[];
    stepsUsed: number;
    costSpentUsd: number;
    error?: string;
}
