/**
 * Scan-side agent — wire contract mirror.
 *
 * Mirror: api/src/attacker/agentScanProtocol.ts — keep string values in step.
 * Types are duplicated (not shared) between the API and MCP repos.
 */

export const AGENT_SCAN_DEFAULTS = {
    initialSteps: 40,
    extensionSize: 10,
    hardMaxSteps: 80,
    maxSteps: 80,
    costCapUsd: 1.20,
    wallClockMs: 720_000,
    perStepEstimateUsd: 0.08,
    creditsPerRun: 5,
    dailyRunLimit: 20,
    blockedReadRecoveryLimit: 5,
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

export const AGENT_SCAN_PROTOCOL_VERSION = 5;

export const AGENT_SCAN_SUPPORTED_ACTIONS: AgentScanActionType[] = [
    'read_file', 'search_code', 'trace_flow', 'trace_flow_cross_file',
    'check_guard', 'check_policy', 'get_endpoints', 'list_imports',
    'list_files', 'call_graph', 'git_blame', 'git_history', 'git_diff',
    'check_dependencies', 'read_config', 'find_definition', 'find_references', 'find_tests', 'run_tests',
    'finish',
];

export interface AgentScanClientCapabilities {
    /** Protocol version the MCP implements. */
    protocolVersion: number;
    /** Action types the MCP can execute locally. */
    supportedActions: AgentScanActionType[];
}

/**
 * Action constraint sent by the MCP to restrict which actions the API's LLM
 * can select. Used for deterministic blocked-read recovery:
 *
 * - normal: no constraint (all supported actions allowed)
 * - recovery: the MCP forbids read_file and may require a specific action
 *
 * The API MUST filter the LLM's actionType enum using `allowedActions` /
 * `forbiddenActions` — textual instructions alone are insufficient.
 */
export interface AgentActionConstraint {
    mode: 'normal' | 'recovery';
    /** If set, only these actions are allowed (overrides supportedActions). */
    allowedActions?: AgentScanActionType[];
    /** If set, these actions are forbidden (removed from the enum). */
    forbiddenActions?: AgentScanActionType[];
    /** If set, the API should strongly prefer this action. */
    requiredAction?: AgentScanActionType;
    /** Human-readable reason for the constraint (shown to the LLM). */
    reason?: string;
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

/**
 * Structured metadata returned by the executor for a read_file action.
 *
 * The loop records coverage using `actualStart..actualEnd` (the range the
 * executor actually delivered), never the requested range. A large-file read
 * that returns a function map instead of raw content has `truncated === true`
 * and `actualStart/actualEnd` set to 0 (no content lines were delivered).
 */
export interface ReadFileObservation {
    /** Redacted, truncated observation string for the LLM transcript. */
    observation: string;
    /** First line of actual content delivered (1-indexed). 0 if no content. */
    actualStart: number;
    /** Last line of actual content delivered (1-indexed). 0 if no content. */
    actualEnd: number;
    /** Total line count of the file on disk. */
    totalLines: number;
    /** True if the executor returned a function map or otherwise did not deliver raw content. */
    truncated: boolean;
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

export interface AgentScanGitDiffAction {
    type: 'git_diff';
    /** Base git ref to compare from (e.g. "main", "HEAD~1", a commit SHA). */
    baseRef: string;
    /** Optional head ref (defaults to HEAD). */
    headRef?: string;
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

// ── Precision Evidence Model ────────────────────────────────────────────────
//
// Distinguishes "the code branch exists" from "the security impact is proven."
// A pure-function or logic test proves behavior, not vulnerability. The
// scanner must separately establish threat model, reachability, missing
// control, and impact before classifying a candidate as a finding.
//
// Mirror: api/src/attacker/agentScanProtocol.ts — keep in step.

export type VerificationLevel =
    | 'logic-confirmed'
    | 'path-confirmed'
    | 'impact-confirmed'
    | 'exploit-confirmed';

export type ThreatModelApplicability = 'confirmed' | 'rejected' | 'unknown';

export interface EvidenceLocation {
    file: string;
    line: number;
    lineEnd?: number;
    description: string;
}

export interface ControlAssessment {
    expected: string;
    actual: string;
    status: 'missing' | 'ineffective' | 'bypassed' | 'present';
}

export interface ImpactAssessment {
    description: string;
    confirmed: boolean;
}

export interface VerificationAssessment {
    level: VerificationLevel;
    method: string;
}

export interface ThreatModelAssessment {
    attacker: string;
    boundary: string;
    applicable: ThreatModelApplicability;
    evidence: EvidenceLocation[];
}

export interface EvidenceChain {
    source?: EvidenceLocation;
    flow: EvidenceLocation[];
    sink?: EvidenceLocation;
    control?: ControlAssessment;
    impact?: ImpactAssessment;
    verification?: VerificationAssessment;
    threatModel?: ThreatModelAssessment;
}

export interface RootCauseReference {
    rootCauseId: string;
    description: string;
    affectedSurfaces: EvidenceLocation[];
}

export interface InvestigationNote {
    title: string;
    detail: string;
    file: string;
    line?: number;
    lineEnd?: number;
    symbol?: string;
    verificationLevel: VerificationLevel;
    rootCauseId?: string;
    requiredEvidence: string[];
    priority: 'high' | 'medium' | 'low';
}

export interface CoverageGap {
    title: string;
    detail: string;
    file?: string;
    line?: number;
    lineEnd?: number;
    symbol?: string;
    requiredEvidence: string[];
    suggestedNextAction: string;
    priority: 'high' | 'medium' | 'low';
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
    evidenceChain?: EvidenceChain;
    rootCause?: RootCauseReference;
    verificationLevel?: VerificationLevel;
}

export interface AgentScanFinishAction {
    type: 'finish';
    findings: AgentScanFinding[];
    summary: string;
    /** Self-critique the agent writes before reporting — visible to the user. */
    selfCritique?: string | null;
    /** Investigated but unproven concerns — never treated as vulnerabilities. */
    investigationNotes?: InvestigationNote[];
    /** Areas that were not sufficiently investigated — guides future scans. */
    coverageGaps?: CoverageGap[];
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

export type AgentScanSystemEventType = 'critique' | 'error' | 'blocked' | 'budget' | 'finish_gate';

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
    | AgentScanGitDiffAction
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
    | 'git_diff'
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
    stepsGranted: number;
    hardMaxSteps: number;
    extensionsGranted: number;
}

// ── Request / Response ──────────────────────────────────────────────────────

export interface AgentScanScope {
    /** Files that changed (from git diff). */
    changedFiles: string[];
    /** Full blast radius (changed + affected files). */
    blastRadius: string[];
    /** Base git ref used for the diff. */
    baseRef?: string;
    /** Head git ref used for the diff. */
    headRef?: string;
}

export interface AgentScanTarget {
    filePath: string;
    language: string;
    fileContent: string;
    endpointContext?: unknown;
    /** Formatted workspace memory string (false positives + known facts). */
    workspaceMemory?: string;
    /** Diff-aware blast radius scope. When present, the agent should focus
     *  its investigation on files within this scope. */
    scope?: AgentScanScope;
    /** Formatted architecture context string from a prior architecture-scout
     *  run. Gives the agent project-wide context (important files, trust
     *  boundaries, security controls) so it doesn't re-discover them. */
    architectureContext?: string;
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
    investigationProgress?: AgentInvestigationProgress;
    /** Action constraint for deterministic blocked-read recovery. */
    actionConstraint?: AgentActionConstraint;
}

export interface AgentInvestigationProgress {
    completedSteps: string[];
    incompleteSteps: string[];
    consecutiveBlockedReads: number;
    meaningfulProgressSinceLastExtension: boolean;
}

export interface BudgetExtensionEvent {
    granted: number;
    totalGranted: number;
    hardMaxSteps: number;
    reason: string;
}

export interface AgentScanStepResponse {
    next: AgentScanAction | null;
    costUsd: number;
    tokens: number;
    degraded: boolean;
    costCapped: boolean;
    stepsRemaining: number;
    systemEvent?: AgentScanSystemEventAction;
    budgetExtension?: BudgetExtensionEvent;
    /** Protocol v5: server-side finish gate evaluation result. */
    finishGate?: {
        status: 'accepted' | 'rejected' | 'not_evaluated';
        incompleteSteps: string[];
        reason: string;
    };
    callBreakdown?: {
        decision: number;
        retry: number;
        critique: number;
    };
    /** Model telemetry — the actual serving model for this step. */
    model?: string;
    provider?: string;
    fallbackFired?: boolean;
    latencyMs?: number;
    promptTokens?: number;
    completionTokens?: number;
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
    | 'cancelled'
    | 'blocked_recovery';

export type TerminationReason =
    | 'agent_finish'
    | 'forced_incomplete'
    | 'budget_exhausted'
    | 'cost_cap'
    | 'wall_clock'
    | 'blocked_read_recovery'
    | 'api_error'
    | 'cancelled';

// ── Result ───────────────────────────────────────────────────────────────────

export interface AgentScanResult {
    status: AgentScanRunStatus;
    findings: AgentScanFinding[];
    investigationNotes: InvestigationNote[];
    coverageGaps: CoverageGap[];
    summary?: string;
    transcript: AgentScanTranscriptStep[];
    stepsUsed: number;
    stepsGranted: number;
    extensionsGranted: number;
    costSpentUsd: number;
    terminationReason?: TerminationReason;
    error?: string;
    qualityMetrics?: import('./qualityMetrics').ScanQualityMetrics;
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
    maxRoundsPerFinding: 12,
    maxLlmCalls: 60,          // 10 findings × 12 rounds × 2 calls = 240 max; default to ~25%
    maxWallClockMs: 10 * 60_000, // 10 minutes
    costCapUsd: 0.80,
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

// ── Fix verification budget ──────────────────────────────────────────────────
//
// After a fix is generated and approved, the pipeline re-runs the exploit
// verification loop against the merged fixed code to prove the fix actually
// closed the vulnerability. This is a SEPARATE, smaller budget so a single
// fix verification cannot consume the entire original scan verification
// budget.

export type FixVerificationStatus =
    | 'not-run'
    | 'closed'
    | 'still-vulnerable'
    | 'inconclusive'
    | 'syntax-invalid'
    | 'sandbox-unavailable'
    | 'cancelled';

export const FIX_VERIFY_DEFAULTS = {
    maxFindings: 1,
    maxRoundsPerFinding: 3,
    maxLlmCalls: 6,
    maxWallClockMs: 120_000,
    costCapUsd: 0.20,
} as const;

export function defaultFixVerifyBudget(overrides?: Partial<VerifyBudget>): VerifyBudget {
    return {
        maxFindings: overrides?.maxFindings ?? FIX_VERIFY_DEFAULTS.maxFindings,
        maxRoundsPerFinding: overrides?.maxRoundsPerFinding ?? FIX_VERIFY_DEFAULTS.maxRoundsPerFinding,
        maxLlmCalls: overrides?.maxLlmCalls ?? FIX_VERIFY_DEFAULTS.maxLlmCalls,
        maxWallClockMs: overrides?.maxWallClockMs ?? FIX_VERIFY_DEFAULTS.maxWallClockMs,
        costCapUsd: overrides?.costCapUsd ?? FIX_VERIFY_DEFAULTS.costCapUsd,
    };
}
