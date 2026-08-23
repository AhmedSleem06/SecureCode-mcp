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
import type { ScanRunState } from './scanState';
import type { EvidenceLedger } from './evidenceLedger';
import type { WorkItemQueue } from './workItem';
import type { HandlerInventory } from '../project-map/handlerInventory';
import type { CandidateStore } from './candidateStore';
import type { InvestigationState } from './investigationState';
import type { ScheduleDecision } from './scanScheduler';

export type FinishGateMode = 'complete' | 'continue' | 'forced-incomplete';

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
    target: { filePath: string };
}

export function evaluateFinishGate(input: FinishGateInput): FinishGateResult {
    const { proposal, state, evidence, workItems, handlers, candidates, investigation, scheduler, target } = input;

    const reasons: FinishGateReason[] = [];
    const coverageGaps: FinishGateResult['coverageGaps'] = [];
    const hasBudget = state.budget.stepsRemaining > 0 &&
                      state.budget.costSpentUsd < state.budget.costCapUsd;
    const hasWallClock = Date.now() - state.budget.startedAt < state.budget.wallClockMs;

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

    // Check 3: Non-terminal candidates
    if (!candidates.allReadyForJuror()) {
        const underInvestigation = candidates.getUnderInvestigation();
        for (const candidate of underInvestigation) {
            reasons.push({
                code: 'non-terminal-candidate',
                description: `Candidate needs more evidence: ${candidate.claim} (status: ${candidate.status}, ${candidate.evidenceRefs.length} evidence ref(s))`,
            });
            coverageGaps.push({
                title: `Candidate needs more evidence: ${candidate.claim}`,
                detail: `This vulnerability candidate at ${candidate.locations.map(l => `${l.filePath}:${l.line}`).join(', ')} has status "${candidate.status}" with ${candidate.evidenceRefs.length} evidence reference(s). Run trace_flow, check_guard, or check_policy on the finding location to gather more evidence before finishing.`,
                file: candidate.locations[0]?.filePath || target.filePath,
                requiredEvidence: candidate.requiredEvidence.map(e => `${e.description} (tools: ${(e.requiredTools || []).join(', ')})`),
                suggestedNextAction: (candidate.requiredEvidence[0]?.requiredTools || ['trace_flow_cross_file'])[0],
                priority: 'high',
            });
        }
    }

    // Check 4: Unreviewed security-sensitive handlers
    const unreviewedSensitive = handlers.getUnreviewedSensitiveCount();
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
    // When the checklist is complete, we trust it — the scheduler's evidence
    // requirements are tracked separately and may have false positives.
    if (incompleteSteps.length > 0 && scheduler.kind === 'deterministic-action' && hasBudget && hasWallClock) {
        reasons.push({
            code: 'scheduler-has-action',
            description: `Scheduler has a deterministic action available: ${scheduler.reason}`,
        });
    }

    // Decision:
    // - If no reasons → accept as complete
    // - If reasons exist but no budget/wall-clock → accept as forced-incomplete
    // - If reasons exist and budget remains → reject and continue

    if (reasons.length === 0) {
        return {
            accepted: true,
            mode: 'complete',
            reasons: [],
            normalizedFinish: proposal,
        };
    }

    // Check if we can continue (budget + wall clock available)
    const canContinue = hasBudget && hasWallClock && !isScanTerminal(state);

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
