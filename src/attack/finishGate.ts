/**
 * Hard finish gate — rejects premature finish attempts and continues the
 * investigation while executable work and budget remain.
 *
 * The finish gate is MCP-owned. When the model proposes `finish`, the gate
 * evaluates whether the investigation is actually complete:
 *
 * - Required checklist steps must be complete
 * - Architecture-risk tasks must be resolved, refuted, or blocked
 * - All candidates must be terminal
 * - Security-sensitive handlers must be reviewed
 * - No executable work items remain (when budget is available)
 *
 * If any of these conditions fail and budget remains, finish is REJECTED
 * and the gate returns a recovery action to continue the investigation.
 *
 * If budget is exhausted, finish is accepted as "forced-incomplete" with
 * coverage gaps for every unresolved item.
 */

import type { AgentScanAction, AgentScanFinishAction } from './agentScanProtocol';
import { AGENT_SCAN_DEFAULTS } from './agentScanProtocol';
import type { ScanRunState } from './scanState';
import type { EvidenceLedger } from './evidenceLedger';
import type { WorkItemQueue } from './workItem';
import type { HandlerInventory } from '../project-map/handlerInventory';
import type { CandidateStore } from './candidateStore';
import { missingGateDimensions } from './candidateStore';
import type { InvestigationState } from './investigationState';
import type { ScheduleDecision } from './scanScheduler';

export type FinishGateMode = 'complete' | 'continue' | 'forced-incomplete';

/**
 * When the identical reason-code set rejects this many CONSECUTIVE finishes,
 * the loop accepts the next finish as forced-incomplete (the same salvage
 * semantics as the 75% soft deadline) instead of grinding to the wall clock.
 * Production showed a candidate-blocked agent proposing finish ~16 times with
 * the recovery loop unable to converge — 33 minutes of burn for one finding.
 */
export const FINISH_LOOP_ESCAPE_THRESHOLD = 4;

/**
 * Lower threshold when the only blockers are checklist items (unsatisfied
 * evidence requirements / incomplete checklist steps) and nothing of
 * substance is pending — no candidates and no high-priority unread range.
 * Each rejection costs about two steps; grinding four of them on a
 * checklist that may not apply to the file wastes the budget.
 */
export const FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD = 2;

/**
 * Candidate-only rejections (every reason is `non-terminal-candidate`) also
 * escape after two identical rejections: the open dimensions are recorded
 * as the finding's required evidence and the verifier runs after finish.
 */
export const FINISH_LOOP_CANDIDATE_ESCAPE_THRESHOLD = 2;

const CHECKLIST_ONLY_REASON_CODES = new Set(['unsatisfied-evidence-requirement', 'incomplete-checklist']);

export const HIGH_PRIORITY_KEYWORDS = [
    'authenticat', 'authorize', 'authorization', 'token', 'session',
    'credential', 'password', 'execfile', 'exec(', 'spawn(',
    'child_process', 'writefile', 'permission', 'ownership',
    'bootstrap', 'pairing', 'sql', 'queryraw', 'eval(',
];

export function rangeHasHighPriorityCode(fileContent: string | undefined, range: { start: number; end: number }): boolean {
    if (!fileContent) return false;
    const lines = fileContent.split('\n');
    const rangeText = lines.slice(Math.max(0, range.start - 1), Math.min(lines.length, range.end)).join('\n').toLowerCase();
    return HIGH_PRIORITY_KEYWORDS.some(kw => rangeText.includes(kw));
}

export interface FinishLoopTracker {
    rejections: number;
    signature: string;
    threshold: number;
}

export function newFinishLoopTracker(): FinishLoopTracker {
    return { rejections: 0, signature: '', threshold: FINISH_LOOP_ESCAPE_THRESHOLD };
}

export function finishLoopEscapeThreshold(reasons: FinishGateReason[], activeCandidateCount = 0): number {
    if (reasons.length === 0) return FINISH_LOOP_ESCAPE_THRESHOLD;
    if (reasons.every(r => r.code === 'non-terminal-candidate')) return FINISH_LOOP_CANDIDATE_ESCAPE_THRESHOLD;
    const checklistOnly = reasons.every(r => CHECKLIST_ONLY_REASON_CODES.has(r.code));
    return checklistOnly && activeCandidateCount === 0
        ? FINISH_LOOP_CHECKLIST_ESCAPE_THRESHOLD
        : FINISH_LOOP_ESCAPE_THRESHOLD;
}

/**
 * Record a rejected finish against the tracker. An identical reason-code
 * signature climbs the counter; a changed signature means the investigation
 * is still making progress (fewer/different blockers) and resets it.
 */
export function trackFinishRejection(tracker: FinishLoopTracker, reasons: FinishGateReason[], activeCandidateCount = 0): FinishLoopTracker {
    const signature = reasons.map(r => r.code).sort().join('|');
    if (signature === tracker.signature) {
        tracker.rejections++;
    } else {
        tracker.rejections = 1;
        tracker.signature = signature;
    }
    tracker.threshold = finishLoopEscapeThreshold(reasons, activeCandidateCount);
    return tracker;
}

export function finishLoopEscaped(tracker: FinishLoopTracker): boolean {
    return tracker.rejections >= (tracker.threshold ?? FINISH_LOOP_ESCAPE_THRESHOLD);
}

/**
 * Landing mode: no more credits can be added to the run and the remaining
 * cost budget covers fewer than three steps. Mirrors the API rule so an
 * older API that does not send `landing` still lets the run land.
 */
export function isLandingBudget(
    serverBudget: { creditsUsed: number; maxCredits: number; costSpentUsd: number; costCapUsd: number } | undefined,
    perStepEstimateUsd: number = AGENT_SCAN_DEFAULTS.perStepEstimateUsd,
    extensionCredits: number = AGENT_SCAN_DEFAULTS.extensionCredits,
): boolean {
    if (!serverBudget) return false;
    const { creditsUsed, maxCredits, costSpentUsd, costCapUsd } = serverBudget;
    if (![creditsUsed, maxCredits, costSpentUsd, costCapUsd].every(v => typeof v === 'number' && Number.isFinite(v))) return false;
    return creditsUsed + extensionCredits > maxCredits && costCapUsd - costSpentUsd < 3 * perStepEstimateUsd;
}

export interface FinishGateReason {
    code: string;
    description: string;
}

export interface FinishGateResult {
    accepted: boolean;
    mode: FinishGateMode;
    reasons: FinishGateReason[];
    recoveryAction?: AgentScanAction;
    normalizedFinish?: AgentScanFinishAction;
    coverageGaps?: { title: string; detail: string; file: string; requiredEvidence: string[]; suggestedNextAction: string; priority: 'high' | 'medium' | 'low' }[];
}

export interface FinishGateInput {
    proposal: AgentScanFinishAction;
    state: ScanRunState;
    evidence: EvidenceLedger;
    workItems: WorkItemQueue;
    handlers: HandlerInventory;
    candidates: CandidateStore;
    investigation: InvestigationState;
    scheduler: ScheduleDecision;
    target: { filePath: string; fileContent?: string; segment?: { startLine: number; endLine: number } };
    landing?: boolean;
}

function normalizeGatePath(p: string): string {
    return p.replace(/\\/g, '/').toLowerCase();
}

function countUnreviewedSensitiveHandlers(handlers: HandlerInventory, target: FinishGateInput['target']): number {
    if (!target.segment) return handlers.getUnreviewedSensitiveCount();
    const targetNorm = normalizeGatePath(target.filePath);
    const { startLine, endLine } = target.segment;
    return handlers.getAll().filter(h => {
        if (!h.securitySensitive || h.reviewed) return false;
        const handlerNorm = normalizeGatePath(h.filePath);
        if (handlerNorm !== targetNorm && !handlerNorm.endsWith(`/${targetNorm}`)) return true;
        return h.range.end >= startLine && h.range.start <= endLine;
    }).length;
}

export function evaluateFinishGate(input: FinishGateInput): FinishGateResult {
    const { proposal, state, evidence, workItems, handlers, candidates, investigation, scheduler, target, landing } = input;

    const reasons: FinishGateReason[] = [];
    const coverageGaps: FinishGateResult['coverageGaps'] = [];
    const hasBudget = state.budget.stepsRemaining > 0 &&
                      state.budget.costSpentUsd < state.budget.costCapUsd;
    const hasWallClock = Date.now() - state.budget.startedAt < state.budget.wallClockMs;
    // Soft deadline: once 75% of the wall clock is spent, the gate stops
    // rejecting finishes. Unbounded checks (unread auth ranges, executable
    // work, scheduler actions) can never converge on a large auth-heavy
    // file, so a hard "reject while budget remains" rule grinds deep
    // investigators into a wall-clock discard. The last quarter of the
    // run is the landing window: finishes are accepted with their
    // un-investigated areas recorded as coverage gaps. The API's landing
    // mode (no more credits can be added, under three steps of budget
    // left) opens the same window early.
    const wallClockElapsedMs = Date.now() - state.budget.startedAt;
    const softDeadlinePassed = wallClockElapsedMs >= state.budget.wallClockMs * 0.75 || landing === true;

    // Check 1: Incomplete investigation steps
    const incompleteSteps = investigation.getIncompleteSteps();
    if (incompleteSteps.length > 0) {
        for (const step of incompleteSteps) {
            reasons.push({
                code: 'incomplete-checklist',
                description: `Required investigation step not completed: ${step}`,
            });
            coverageGaps.push({
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
                priority: 'high',
            });
        }
    }

    // Check 2: Unresolved architecture-risk tasks
    const unresolvedTasks = investigation.getUnresolvedTasks();
    if (unresolvedTasks.length > 0) {
        for (const task of unresolvedTasks) {
            reasons.push({
                code: 'unresolved-task',
                description: `Architecture risk task unresolved: ${task.claim}`,
            });
            coverageGaps.push({
                title: `Architecture risk unresolved: ${task.claim}`,
                detail: `This architecture-risk investigation task was not resolved: ${task.claim}. Required evidence: ${task.requiredEvidence.join('; ')}.`,
                file: task.targetFiles[0] || target.filePath,
                requiredEvidence: task.requiredEvidence,
                suggestedNextAction: task.requiredTools[0] || 'continue investigation',
                priority: 'high',
            });
        }
    }

    // Check 3: Candidates not ready for the Juror block finish when budget
    // remains; when budget is exhausted they become coverage gaps. A
    // candidate is ready when its gate dimensions are satisfied, or when a
    // traced source-to-sink flow touches its location and no effective guard
    // was found. `verification` is never a pre-finish requirement: the
    // verifier runs after finish.
    if (!candidates.allReadyForJuror()) {
        for (const candidate of candidates.getBlocking()) {
            const missingDims = missingGateDimensions(candidate);
            const location = candidate.locations.map(l => `${l.filePath}:${l.line}`).join(', ') || target.filePath;
            const blocker = candidate.guardFound
                ? `an effective guard was found (${candidate.guardReason}) — show why it does not apply or drop the finding`
                : `no traced source-to-sink flow reaches ${location} — run trace_flow or trace_flow_cross_file on that file`;
            const dimInfo = missingDims.length > 0
                ? ` (missing proof dimensions: ${missingDims.join(', ')}; ${blocker})`
                : ` (${candidate.evidenceRefs.length} evidence ref(s); ${blocker})`;
            reasons.push({
                code: 'non-terminal-candidate',
                description: `Candidate needs more evidence: ${candidate.claim} (status: ${candidate.status}${dimInfo})`,
            });
            coverageGaps.push({
                title: `Candidate needs more evidence: ${candidate.claim}`,
                detail: `This vulnerability candidate at ${location} has status "${candidate.status}" with ${candidate.evidenceRefs.length} evidence reference(s). Missing proof dimensions: ${missingDims.join(', ') || 'none'}. ${blocker[0].toUpperCase()}${blocker.slice(1)}.`,
                file: candidate.locations[0]?.filePath || target.filePath,
                requiredEvidence: candidate.requiredEvidence.map(e => `${e.description} (tools: ${(e.requiredTools || []).join(', ')})`),
                suggestedNextAction: (candidate.requiredEvidence[0]?.requiredTools || ['trace_flow_cross_file'])[0],
                priority: candidate.severity === 'high' || candidate.severity === 'critical' ? 'high' : 'medium',
            });
        }
    }

    // Check 3b: Unsatisfied evidence-ledger requirements
    const unsatisfiedReqs = evidence.getUnsatisfiedRequirements();
    if (unsatisfiedReqs.length > 0) {
        for (const req of unsatisfiedReqs) {
            reasons.push({
                code: 'unsatisfied-evidence-requirement',
                description: `Evidence requirement not satisfied: ${req.description}`,
            });
            coverageGaps.push({
                title: `Evidence requirement not satisfied: ${req.description}`,
                detail: `The evidence ledger requirement "${req.description}" was not satisfied. Required tools: ${(req.requiredTools || []).join(', ')}. Accepted kinds: ${req.acceptedKinds.join(', ')}.`,
                file: req.targetFiles?.[0] || target.filePath,
                requiredEvidence: [req.description],
                suggestedNextAction: req.requiredTools?.[0] || 'continue investigation',
                priority: 'medium',
            });
        }
    }

    // Check 4: Unreviewed security-sensitive handlers
    const unreviewedSensitive = countUnreviewedSensitiveHandlers(handlers, target);
    if (unreviewedSensitive > 0) {
        reasons.push({
            code: 'unreviewed-handlers',
            description: `${unreviewedSensitive} security-sensitive handler(s) unreviewed`,
        });
    }

    // Check 5: Executable work items remain (only when budget is available)
    const executableWork = workItems.getExecutable();
    if (executableWork.length > 0 && hasBudget && hasWallClock) {
        reasons.push({
            code: 'executable-work-remaining',
            description: `${executableWork.length} executable work item(s) remain`,
        });
    }

    // Check 6: Scheduler has a deterministic action (only when checklist incomplete)
    if (incompleteSteps.length > 0 && scheduler.kind === 'deterministic-action' && hasBudget && hasWallClock) {
        reasons.push({
            code: 'scheduler-has-action',
            description: `Scheduler has a deterministic action available: ${scheduler.reason}`,
        });
    }

    // Check 7: High-priority unread ranges — security-relevant code that
    // was never read. This prevents finishing while authentication,
    // authorization, or command-execution code remains uninspected.
    if (hasBudget && hasWallClock && target.fileContent) {
        const uncoveredRanges = investigation.getUncoveredRanges(target.filePath)
            .map(r => target.segment
                ? { start: Math.max(r.start, target.segment.startLine), end: Math.min(r.end, target.segment.endLine) }
                : r)
            .filter(r => r.start <= r.end);
        if (uncoveredRanges.length > 0) {
            for (const range of uncoveredRanges) {
                const hasHighPriority = rangeHasHighPriorityCode(target.fileContent, range);
                if (hasHighPriority) {
                    reasons.push({
                        code: 'high-priority-unread-range',
                        description: `Unread range lines ${range.start}-${range.end} contains security-relevant code (auth, exec, token, etc.)`,
                    });
                    coverageGaps.push({
                        title: `Unread high-priority range: lines ${range.start}-${range.end} of ${target.filePath}`,
                        detail: `This unread range contains security-relevant code (authentication, authorization, command execution, or token handling). Vulnerabilities in this range were not checked.`,
                        file: target.filePath,
                        requiredEvidence: [`Read lines ${range.start}-${range.end} and analyze for vulnerabilities`],
                        suggestedNextAction: 'read_file',
                        priority: 'high',
                    });
                    break;
                }
            }
        }
    }

    // Decision:
    // - If no reasons → accept as complete
    // - If reasons exist but no budget/wall-clock, or the soft deadline
    //   (75% of the wall clock) has passed → accept as forced-incomplete
    // - If reasons exist and budget remains (and no soft deadline) → reject and continue

    if (reasons.length === 0) {
        return {
            accepted: true,
            mode: 'complete',
            reasons: [],
            normalizedFinish: proposal,
        };
    }

    // Check if we can continue (budget + wall clock available, before the soft deadline)
    const canContinue = hasBudget && hasWallClock && !softDeadlinePassed && !isScanTerminal(state);

    if (!canContinue) {
        // Forced-incomplete: budget or wall clock exhausted
        return {
            accepted: true,
            mode: 'forced-incomplete',
            reasons,
            coverageGaps,
            normalizedFinish: proposal,
        };
    }

    // Reject finish — continue investigation
    const recoveryAction = scheduler.kind === 'deterministic-action' && scheduler.action
        ? scheduler.action
        : undefined;

    return {
        accepted: false,
        mode: 'continue',
        reasons,
        recoveryAction,
        coverageGaps,
    };
}

function isScanTerminal(state: ScanRunState): boolean {
    return state.phase === 'completed' || state.phase === 'terminated';
}
