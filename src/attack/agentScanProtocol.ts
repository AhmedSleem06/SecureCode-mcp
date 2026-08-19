/**
 * Scan-side agent — wire contract mirror.
 *
 * Mirror: api/src/attacker/agentScanProtocol.ts — keep string values in step.
 * Types are duplicated (not shared) between the API and MCP repos.
 */

export const AGENT_SCAN_DEFAULTS = {
    maxSteps: 30,
    costCapUsd: 0.50,
    wallClockMs: 300_000,
    perStepEstimateUsd: 0.08,
    creditsPerRun: 5,
    dailyRunLimit: 20,
} as const;

// ── Actions ─────────────────────────────────────────────────────────────────

export interface AgentScanReadFileAction {
    type: 'read_file';
    path: string;
    startLine?: number;
    endLine?: number;
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

export interface AgentScanTraceFlowCrossFileAction {
    type: 'trace_flow_cross_file';
    filePath: string;
    /** How many import hops to follow (default 3). */
    maxDepth?: number;
    rationale: string;
}

export interface AgentScanGetEndpointsAction {
    type: 'get_endpoints';
    /** Optional glob filter (e.g. "*.ts"). */
    glob?: string;
    rationale: string;
}

export interface AgentScanListImportsAction {
    type: 'list_imports';
    filePath: string;
    rationale: string;
}

export interface AgentScanListFilesAction {
    type: 'list_files';
    /** Directory to list (relative to workspace root). Defaults to root. */
    path?: string;
    /** Optional glob filter (e.g. "*.ts"). */
    glob?: string;
    rationale: string;
}

export interface AgentScanCallGraphAction {
    type: 'call_graph';
    /** Workspace-relative path to the file to analyze. */
    filePath: string;
    /** Optional function name — if given, returns forward + reverse call graph for that function. */
    functionName?: string;
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
    fix?: {
        fixedCode: string;
        replaceRange: { start_line: number; end_line: number };
        fixSummary: string;
        importsNeeded?: string[];
        confidence?: number;
    };
}

export interface AgentScanFinishAction {
    type: 'finish';
    findings: AgentScanFinding[];
    summary: string;
    /** Self-critique the agent writes before reporting — visible to the user. */
    selfCritique?: string | null;
}

export type AgentScanAction =
    | AgentScanReadFileAction
    | AgentScanSearchCodeAction
    | AgentScanTraceFlowAction
    | AgentScanTraceFlowCrossFileAction
    | AgentScanCheckGuardAction
    | AgentScanCheckPolicyAction
    | AgentScanGetEndpointsAction
    | AgentScanListImportsAction
    | AgentScanListFilesAction
    | AgentScanCallGraphAction
    | AgentScanFinishAction;

export type AgentScanActionType =
    | 'read_file'
    | 'search_code'
    | 'trace_flow'
    | 'trace_flow_cross_file'
    | 'check_guard'
    | 'check_policy'
    | 'get_endpoints'
    | 'list_imports'
    | 'list_files'
    | 'call_graph'
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
    /** Formatted workspace memory string (false positives + known facts). */
    workspaceMemory?: string;
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
