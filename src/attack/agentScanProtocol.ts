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

// ── Protocol versioning + capability negotiation ─────────────────────────────
//
// When the API adds a new agent action, old MCPs that don't know about it
// would crash trying to execute it. Capability negotiation lets the API
// filter the LLM's action enum to only include actions the connected MCP
// actually supports, preventing the mismatch.
//
// PROTOCOL_VERSION is bumped when the wire contract changes in a way that
// is not backward-compatible (e.g., a required field is added). Adding a
// new optional action type only requires adding it to SUPPORTED_ACTIONS
// and bumping the MCP version — the API filters its schema accordingly.

export const AGENT_SCAN_PROTOCOL_VERSION = 2;

export const AGENT_SCAN_SUPPORTED_ACTIONS: AgentScanActionType[] = [
    'read_file', 'search_code', 'trace_flow', 'trace_flow_cross_file',
    'check_guard', 'check_policy', 'get_endpoints', 'list_imports',
    'list_files', 'call_graph', 'git_blame', 'git_history',
    'check_dependencies', 'read_config', 'find_definition', 'find_references', 'find_tests', 'run_tests',
    'finish',
];

export interface AgentScanClientCapabilities {
    /** Protocol version the MCP implements. */
    protocolVersion: number;
    /** Action types the MCP can execute locally. */
    supportedActions: AgentScanActionType[];
}

export function defaultClientCapabilities(): AgentScanClientCapabilities {
    return {
        protocolVersion: AGENT_SCAN_PROTOCOL_VERSION,
        supportedActions: AGENT_SCAN_SUPPORTED_ACTIONS,
    };
}

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
    /** Optional function name — if given, returns forward + reverse call graph. */
    functionName?: string;
    rationale: string;
}

export interface AgentScanGitBlameAction {
    type: 'git_blame';
    /** Workspace-relative path to the file. */
    filePath: string;
    /** Optional 1-indexed start line. */
    startLine?: number;
    /** Optional 1-indexed end line (inclusive). */
    endLine?: number;
    rationale: string;
}

export interface AgentScanGitHistoryAction {
    type: 'git_history';
    /** Optional workspace-relative path — if omitted, returns repo history. */
    filePath?: string;
    /** Optional function name to search for in history (git log -S). */
    functionName?: string;
    /** Max commits to return (hard cap 20, default 10). */
    limit?: number;
    rationale: string;
}

export interface AgentScanCheckDependenciesAction {
    type: 'check_dependencies';
    rationale: string;
}

export interface AgentScanReadConfigAction {
    type: 'read_config';
    /** What kind of config to look for. */
    configKind: 'auth' | 'cors' | 'rate_limit' | 'headers' | 'env' | 'all';
    rationale: string;
}

export interface AgentScanFindDefinitionAction {
    type: 'find_definition';
    /** Workspace-relative path to the file where the symbol is referenced. */
    filePath: string;
    /** The symbol name to find the definition of. */
    symbol: string;
    /** Optional 1-indexed line (for disambiguation). */
    line?: number;
    rationale: string;
}

export interface AgentScanFindReferencesAction {
    type: 'find_references';
    /** Workspace-relative path to the file where the symbol is defined. */
    filePath: string;
    /** The symbol name to find references to. */
    symbol: string;
    /** Optional 1-indexed line (for disambiguation). */
    line?: number;
    rationale: string;
}

export interface AgentScanFindTestsAction {
    type: 'find_tests';
    /** Workspace-relative path to the source file to find tests for. */
    filePath: string;
    /** Optional symbol name — if provided, also search test files for references. */
    symbol?: string;
    rationale: string;
}

export interface AgentScanRunTestsAction {
    type: 'run_tests';
    /** Execution mode: "existing" runs the workspace test suite; "generated" runs an inline script. */
    mode: 'existing' | 'generated';

    /** Existing mode: workspace-relative test file paths to run. */
    testFiles?: string[];
    /** Existing mode: test name pattern passed to the runner. */
    testPattern?: string;
    /** Existing mode: package manager to use. Auto-detected if omitted. */
    packageManager?: 'npm' | 'pnpm' | 'yarn' | 'bun' | 'pytest';

    /** Generated mode: inline test script source code. */
    script?: string;
    /** Generated mode: optional setup script run before the test. */
    setupScript?: string;
    /** Generated mode: runner to execute the script. */
    runner?: string;

    /** Hard timeout in ms. Default: 60000 (existing), 30000 (generated). */
    timeoutMs?: number;
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

// ── System events ───────────────────────────────────────────────────────────
//
// First-class protocol events for things that are NOT tool calls:
//   - critique: the senior-reviewer LLM rejected the agent's finish; the
//     agent must address the issues before calling finish again.
//   - error: the API rejected the agent's previous action; the agent must
//     try a different action with all required fields.
//   - blocked: the MCP loop blocked the action (read cap, dedup cap);
//     the agent must use a different tool.
//
// These were previously piggybacked on `read_file` via magic paths like
// `__CRITIQUE__` and `__ERROR__` — a design gap that caused the critique
// delivery bug (the API mutated its local transcript copy but never sent
// the critique content over the wire). A real action type fixes the bug
// and prevents the next synthetic event from reintroducing the same class.

export type AgentScanSystemEventType = 'critique' | 'error' | 'blocked' | 'budget';

export interface AgentScanSystemEventAction {
    type: 'system_event';
    eventType: AgentScanSystemEventType;
    /** Human-readable event payload — shown to the agent in the transcript. */
    message: string;
    /** Optional structured issues (used by critique). */
    issues?: Array<{ findingIndex: number; reason: string; severity: 'high' | 'medium' | 'low' }>;
    /** Optional missed concerns (used by critique). */
    missedConcerns?: string | null;
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
    | AgentScanGitBlameAction
    | AgentScanGitHistoryAction
    | AgentScanCheckDependenciesAction
    | AgentScanReadConfigAction
    | AgentScanFindDefinitionAction
    | AgentScanFindReferencesAction
    | AgentScanFindTestsAction
    | AgentScanRunTestsAction
    | AgentScanFinishAction
    | AgentScanSystemEventAction;

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
    | 'git_blame'
    | 'git_history'
    | 'check_dependencies'
    | 'read_config'
    | 'find_definition'
    | 'find_references'
    | 'find_tests'
    | 'run_tests'
    | 'finish'
    | 'system_event';

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
    /**
     * Client capability advertisement. The API uses this to filter the
     * action enum in the LLM schema so it never emits an action the MCP
     * can't execute. Old MCPs that omit this field get the default action
     * set (all actions the current API version knows about).
     */
    clientCapabilities?: AgentScanClientCapabilities;
}

export interface AgentScanStepResponse {
    next: AgentScanAction | null;
    costUsd: number;
    tokens: number;
    degraded: boolean;
    costCapped: boolean;
    stepsRemaining: number;
    /**
     * Optional system event the MCP loop must append to its transcript
     * BEFORE requesting the next step. Used by the critique loop: when
     * the API runs the senior-reviewer LLM and it rejects the finish, the
     * API returns `next: <original finish action>` is NOT used — instead
     * the API returns `next: null` and `systemEvent: { eventType: 'critique',
     * message: ..., issues: [...] }`. The MCP loop appends the event to
     * its transcript as a `system_event` step (without executing it) and
     * immediately requests the next step.
     *
     * This replaces the previous pattern of mutating `req.transcript` on
     * the API side (which had no effect on the MCP's transcript, since the
     * request body is a deserialized copy) and returning a fake
     * `read_file('__CRITIQUE__')` action (which the MCP would try to
     * execute and get ENOENT).
     */
    systemEvent?: AgentScanSystemEventAction;
    /**
     * Per-step LLM call breakdown — decision, retry, critique counts.
     * Lets the MCP and user see when a step used multiple calls.
     * Mirror: api/src/attacker/agentScanProtocol.ts.
     */
    callBreakdown?: {
        decision: number;
        retry: number;
        critique: number;
    };
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

// ── Verify budget ───────────────────────────────────────────────────────────
//
// Phase 2 (verification) runs after the agent loop and can spawn up to
// MAX_ROUNDS × N findings × 2 LLM calls per scan with no aggregate cap.
// This budget enforces hard ceilings across the whole scan so a single
// scan cannot run unbounded verification rounds. The MCP loop owns it
// (server-side credit draws are a separate, softer cap that returns 402
// when credits exhaust — not a deliberate ceiling).

export interface VerifyBudget {
    /** Max number of findings to even attempt to verify. */
    maxFindings: number;
    /** Max rounds per single finding. */
    maxRoundsPerFinding: number;
    /** Aggregate LLM-call cap across all findings (generate + analyze). */
    maxLlmCalls: number;
    /** Aggregate wall-clock cap across all findings, in ms. */
    maxWallClockMs: number;
    /** Aggregate cost cap across all findings, in USD. */
    costCapUsd: number;
}

export const VERIFY_DEFAULTS = {
    maxFindings: 10,
    maxRoundsPerFinding: 8,
    maxLlmCalls: 40,         // 5 findings × 8 rounds × 2 calls = 80 max; default to ~half
    maxWallClockMs: 5 * 60_000, // 5 minutes
    costCapUsd: 0.50,
} as const;

export function defaultVerifyBudget(overrides?: Partial<VerifyBudget>): VerifyBudget {
    return {
        maxFindings: overrides?.maxFindings ?? VERIFY_DEFAULTS.maxFindings,
        maxRoundsPerFinding: overrides?.maxRoundsPerFinding ?? VERIFY_DEFAULTS.maxRoundsPerFinding,
        maxLlmCalls: overrides?.maxLlmCalls ?? VERIFY_DEFAULTS.maxLlmCalls,
        maxWallClockMs: overrides?.maxWallClockMs ?? VERIFY_DEFAULTS.maxWallClockMs,
        costCapUsd: overrides?.costCapUsd ?? VERIFY_DEFAULTS.costCapUsd,
    };
}

/** Mutable tracker used by the verify loop to enforce a VerifyBudget. */
export class VerifyBudgetTracker {
    findingsAttempted = 0;
    roundsUsed = 0;
    llmCallsUsed = 0;
    costSpentUsd = 0;
    readonly startedAtMs: number = Date.now();
    readonly budget: VerifyBudget;

    constructor(budget: VerifyBudget) {
        this.budget = budget;
    }

    get wallClockElapsedMs(): number { return Date.now() - this.startedAtMs; }

    canAttemptFinding(): boolean {
        if (this.findingsAttempted >= this.budget.maxFindings) return false;
        if (this.llmCallsUsed >= this.budget.maxLlmCalls) return false;
        if (this.wallClockElapsedMs >= this.budget.maxWallClockMs) return false;
        if (this.costSpentUsd >= this.budget.costCapUsd) return false;
        return true;
    }

    canAttemptRound(): boolean {
        if (this.llmCallsUsed + 2 > this.budget.maxLlmCalls) return false; // need generate + analyze
        if (this.wallClockElapsedMs >= this.budget.maxWallClockMs) return false;
        if (this.costSpentUsd >= this.budget.costCapUsd) return false;
        return true;
    }

    /** Remaining wall-clock in ms; floored at 1000 to avoid zero-timeout spawns. */
    remainingWallClockMs(): number {
        return Math.max(1000, this.budget.maxWallClockMs - this.wallClockElapsedMs);
    }

    recordLlmCall(costUsd: number): void {
        this.llmCallsUsed += 1;
        this.costSpentUsd += costUsd;
    }
}
