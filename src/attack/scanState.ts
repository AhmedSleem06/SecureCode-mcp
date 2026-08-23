/**
 * Authoritative scan state — the single source of truth for a scan run's
 * phase, budget, recovery, and lifecycle.
 *
 * The MCP owns this state. The model proposes actions; the MCP validates
 * them against this state and owns all transitions.
 *
 * This replaces scattered booleans, counters, and checklist sets with a
 * serializable state object that can be snapshotted for tracing and audit.
 */

import type { AgentScanTarget, AgentScanTranscriptStep, AgentScanBudget } from './agentScanProtocol';

export type ScanPhase =
    | 'planning'
    | 'surveying'
    | 'tracing'
    | 'candidate_investigation'
    | 'finish_review'
    | 'verifying'
    | 'evidence_recovery'
    | 'finalizing'
    | 'completed'
    | 'terminated';

export type ScanTerminationReason =
    | 'agent_finish'
    | 'forced_incomplete'
    | 'cost_cap'
    | 'budget_exhausted'
    | 'wall_clock'
    | 'cancelled'
    | 'api_error'
    | 'blocked_read_recovery';

export interface ScanTermination {
    reason: ScanTerminationReason;
    phase: ScanPhase;
    timestamp: number;
    summary?: string;
}

export interface AgentScanBudgetState {
    stepsUsed: number;
    stepsRemaining: number;
    stepsGranted: number;
    hardMaxSteps: number;
    extensionsGranted: number;
    costSpentUsd: number;
    costCapUsd: number;
    startedAt: number;
    wallClockMs: number;
}

export interface RecoveryState {
    consecutiveBlockedActions: number;
    totalBlockedActions: number;
    lastBlockedAction?: string;
    lastRecoveryAction?: string;
    recoveryAttempts: number;
    meaningfulProgressSinceRecovery: boolean;
}

export interface ScanRunState {
    runId: string;
    phase: ScanPhase;
    target: AgentScanTarget;
    transcript: AgentScanTranscriptStep[];
    budget: AgentScanBudgetState;
    recovery: RecoveryState;
    finishAttempts: number;
    verificationCycles: number;
    termination?: ScanTermination;
    profileId?: string;
}

const VALID_TRANSITIONS: Record<ScanPhase, ScanPhase[]> = {
    planning: ['surveying', 'terminated'],
    surveying: ['tracing', 'terminated'],
    tracing: ['candidate_investigation', 'finish_review', 'terminated'],
    candidate_investigation: ['finish_review', 'tracing', 'terminated'],
    finish_review: ['verifying', 'evidence_recovery', 'surveying', 'tracing', 'terminated'],
    verifying: ['evidence_recovery', 'finalizing', 'terminated'],
    evidence_recovery: ['verifying', 'tracing', 'candidate_investigation', 'terminated'],
    finalizing: ['completed', 'terminated'],
    completed: [],
    terminated: [],
};

export function createScanRunState(
    runId: string,
    target: AgentScanTarget,
    budget: AgentScanBudget,
): ScanRunState {
    return {
        runId,
        phase: 'planning',
        target,
        transcript: [],
        budget: {
            stepsUsed: 0,
            stepsRemaining: budget.stepsRemaining,
            stepsGranted: budget.stepsGranted,
            hardMaxSteps: budget.hardMaxSteps,
            extensionsGranted: budget.extensionsGranted,
            costSpentUsd: 0,
            costCapUsd: budget.costCapUsd,
            startedAt: Date.now(),
            wallClockMs: 720_000,
        },
        recovery: {
            consecutiveBlockedActions: 0,
            totalBlockedActions: 0,
            recoveryAttempts: 0,
            meaningfulProgressSinceRecovery: true,
        },
        finishAttempts: 0,
        verificationCycles: 0,
    };
}

export function transitionScanPhase(
    state: ScanRunState,
    next: ScanPhase,
    reason: string,
): void {
    const allowed = VALID_TRANSITIONS[state.phase];
    if (!allowed.includes(next)) {
        throw new Error(
            `Invalid scan phase transition: ${state.phase} -> ${next} (${reason}). ` +
            `Valid transitions: ${allowed.join(', ')}`,
        );
    }
    state.phase = next;
}

export function terminateScan(
    state: ScanRunState,
    reason: ScanTerminationReason,
    summary?: string,
): void {
    state.termination = {
        reason,
        phase: state.phase,
        timestamp: Date.now(),
        summary,
    };
    state.phase = 'terminated';
}

export function isScanTerminal(state: ScanRunState): boolean {
    return state.phase === 'completed' || state.phase === 'terminated';
}

export function hasBudgetRemaining(state: ScanRunState): boolean {
    return state.budget.stepsRemaining > 0 &&
           state.budget.costSpentUsd < state.budget.costCapUsd;
}

export function hasWallClockRemaining(state: ScanRunState): boolean {
    return Date.now() - state.budget.startedAt < state.budget.wallClockMs;
}

export function canExecuteWork(state: ScanRunState): boolean {
    return hasBudgetRemaining(state) && hasWallClockRemaining(state) && !isScanTerminal(state);
}

export function snapshotState(state: ScanRunState): string {
    return JSON.stringify({
        runId: state.runId,
        phase: state.phase,
        stepsUsed: state.budget.stepsUsed,
        stepsRemaining: state.budget.stepsRemaining,
        costSpentUsd: state.budget.costSpentUsd,
        finishAttempts: state.finishAttempts,
        totalBlockedActions: state.recovery.totalBlockedActions,
        termination: state.termination,
    });
}
