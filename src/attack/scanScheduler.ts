/**
 * Deterministic scan scheduler — chooses the next useful action when the
 * model is blocked, repeats itself, or requests finish too early.
 *
 * The scheduler acts on generic state, not project names. It uses the
 * evidence ledger, work item queue, handler inventory, and candidate
 * store to determine what work remains and what action should execute next.
 *
 * Priority order:
 *   1. Candidate missing critical evidence
 *   2. Unresolved critical/high architecture task
 *   3. Contract/interface target requiring implementation resolution
 *   4. Unreviewed security-sensitive handler or RPC method
 *   5. Missing authentication/authorization/ownership evidence
 *   6. Missing cross-file flow
 *   7. Missing configuration evidence
 *   8. Missing related tests
 *   9. Next unread critical range
 *   10. Lower-priority pending task
 *   11. Finish when no executable work remains
 */

import type { AgentScanAction, AgentScanActionType, AgentScanTarget, AgentActionConstraint } from './agentScanProtocol';
import type { ScanRunState } from './scanState';
import type { EvidenceLedger, EvidenceRequirement } from './evidenceLedger';
import type { WorkItemQueue, WorkItem } from './workItem';
import type { HandlerInventory } from '../project-map/handlerInventory';
import type { CandidateStore } from './candidateStore';
import type { InvestigationState } from './investigationState';

export type ScheduleDecisionKind = 'model' | 'deterministic-action' | 'finish-ready' | 'blocked';

export interface ScheduleDecision {
    kind: ScheduleDecisionKind;
    action?: AgentScanAction;
    constraint?: AgentActionConstraint;
    workItemId?: string;
    reason: string;
}

export interface SchedulerInput {
    state: ScanRunState;
    evidence: EvidenceLedger;
    workItems: WorkItemQueue;
    handlers: HandlerInventory;
    candidates: CandidateStore;
    investigation: InvestigationState;
    target: AgentScanTarget;
    functionBoundaries?: { name: string; startLine: number; endLine: number }[];
}

export function schedule(input: SchedulerInput): ScheduleDecision {
    const { state, evidence, workItems, handlers, candidates, investigation, target } = input;

    // If no budget remains, finish is the only option
    if (!canExecute(input)) {
        return { kind: 'finish-ready', reason: 'No budget or wall-clock remaining' };
    }

    // 1. Active high/critical candidate missing critical evidence
    const activeCandidates = candidates.getActive();
    for (const candidate of activeCandidates) {
        if (candidate.severity === 'critical' || candidate.severity === 'high') {
            const action = actionForCandidateEvidence(candidate, target);
            if (action) {
                return {
                    kind: 'deterministic-action',
                    action,
                    workItemId: candidate.id,
                    reason: `Critical/high candidate "${candidate.claim}" needs evidence`,
                };
            }
        }
    }

    // 2. Unresolved critical/high architecture work items with unsatisfied
    // proof requirements — raised above unread ranges because cross-file
    // proof is the highest-value security work. Without tracing the path
    // to the sink, the agent cannot determine whether the risk is real.
    const topWorkItem = workItems.highestPriority();
    if (topWorkItem && (topWorkItem.priority === 'critical' || topWorkItem.priority === 'high')) {
        if (topWorkItem.status === 'pending' || topWorkItem.status === 'active') {
            const action = actionForWorkItem(topWorkItem, target, workItems);
            if (action) {
                return {
                    kind: 'deterministic-action',
                    action,
                    workItemId: topWorkItem.id,
                    reason: `Unresolved ${topWorkItem.priority} proof work item: ${topWorkItem.title}`,
                };
            }
        }
    }

    // 3. Next unread critical range — source coverage is the foundation
    // for all analysis. Uses security-keyword prioritization to read the
    // most security-relevant uncovered range first.
    const candidateLocations = candidates.getAll().flatMap(c => c.locations.map(l => ({ start: l.line, end: l.line })));
    const nextRange = target.fileContent
        ? investigation.getPrioritizedUnreadRange(target.filePath, target.fileContent, undefined, candidateLocations, input.functionBoundaries)
        : investigation.getNextUnreadRange(target.filePath);
    if (nextRange) {
        const coverage = investigation.getCoverage(target.filePath);
        const totalLines = coverage?.totalLines ?? 0;
        const coveredLines = (coverage?.ranges ?? []).reduce((sum, r) => sum + (r.end - r.start + 1), 0);
        const pct = totalLines > 0 ? Math.round(100 * coveredLines / totalLines) : 0;
        return {
            kind: 'deterministic-action',
            action: {
                type: 'read_file',
                path: target.filePath,
                startLine: nextRange.start,
                endLine: nextRange.end,
                rationale: `Read next unread range (coverage: ${pct}% of ${totalLines} lines)`,
            } as AgentScanAction,
            reason: `Unread range ${nextRange.start}-${nextRange.end} in target file (${pct}% covered)`,
        };
    }

    // 4. Contract/interface target requiring implementation resolution
    const implRequirement = evidence.getUnsatisfiedRequirements().find(r =>
        r.acceptedKinds.includes('implementation-resolution'),
    );
    if (implRequirement) {
        return {
            kind: 'deterministic-action',
            action: {
                type: 'search_code',
                pattern: target.filePath.replace(/\.ts$/, '').replace(/.*\//, ''),
                rationale: 'Resolve implementation for interface target',
            } as AgentScanAction,
            reason: 'Interface target needs implementation resolution',
        };
    }

    // 5. Unreviewed security-sensitive handler
    const unreviewedHandlers = handlers.getUnreviewed();
    const sensitiveUnreviewed = unreviewedHandlers.filter(h => h.securitySensitive);
    if (sensitiveUnreviewed.length > 0) {
        const first = sensitiveUnreviewed[0];
        const range = handlers.getNextUnreviewedRange();
        if (range) {
            return {
                kind: 'deterministic-action',
                action: {
                    type: 'read_file',
                    path: first.filePath,
                    startLine: range.start,
                    endLine: Math.min(range.start + 50, range.end + 50),
                    rationale: `Review unreviewed handler: ${first.symbol || 'unknown'}`,
                } as AgentScanAction,
                workItemId: first.id,
                reason: `${sensitiveUnreviewed.length} security-sensitive handler(s) unreviewed`,
            };
        }
    }

    // 6-8. Missing evidence from unsatisfied requirements
    const unsatisfied = evidence.getUnsatisfiedRequirements();
    if (unsatisfied.length > 0) {
        const action = actionForRequirement(unsatisfied[0], target);
        if (action) {
            return {
                kind: 'deterministic-action',
                action,
                reason: `Missing evidence: ${unsatisfied[0].description}`,
            };
        }
    }

    // 9. Lower-priority pending work items
    const pending = workItems.getPending();
    if (pending.length > 0) {
        const action = actionForWorkItem(pending[0], target, workItems);
        if (action) {
            return {
                kind: 'deterministic-action',
                action,
                workItemId: pending[0].id,
                reason: `Lower-priority pending task: ${pending[0].title}`,
            };
        }
    }

    // 10. No executable work remains — finish is ready
    if (candidates.allTerminal() && workItems.getExecutable().length === 0) {
        return { kind: 'finish-ready', reason: 'All candidates terminal and no executable work items remain' };
    }

    // Default: let the model decide
    return { kind: 'model', reason: 'No deterministic action determined, let model decide' };
}

export function buildRecoveryConstraint(
    state: ScanRunState,
    investigation: InvestigationState,
): AgentActionConstraint | undefined {
    const blocked = state.recovery.consecutiveBlockedActions;
    if (blocked < 2) return undefined;

    const recoveryAction = investigation.getRecommendedRecoveryAction();
    return {
        mode: 'recovery',
        forbiddenActions: blocked >= 2 ? ['read_file'] : undefined,
        requiredAction: recoveryAction as any || undefined,
        reason: `Recovery mode: ${blocked} consecutive blocked actions`,
    };
}

function canExecute(input: SchedulerInput): boolean {
    return input.state.budget.stepsRemaining > 0 &&
           input.state.budget.costSpentUsd < input.state.budget.costCapUsd;
}

function actionForCandidateEvidence(candidate: any, target: AgentScanTarget): AgentScanAction | null {
    if (candidate.requiredEvidence && candidate.requiredEvidence.length > 0) {
        const req = candidate.requiredEvidence[0];
        return actionForRequirement(req, target);
    }
    // Default: trace flow to gather more evidence
    return {
        type: 'trace_flow_cross_file',
        filePath: candidate.locations[0]?.filePath || target.filePath,
        rationale: `Gather evidence for candidate: ${candidate.claim}`,
    } as AgentScanAction;
}

function actionForWorkItem(item: WorkItem, target: AgentScanTarget, queue?: WorkItemQueue): AgentScanAction | null {
    if (item.kind === 'implementation-review') {
        const symbol = item.title.replace('Resolve implementation for: ', '');
        return {
            type: 'search_code',
            pattern: `make${symbol}|Layer\\.effect.*${symbol}`,
            rationale: item.title,
        } as AgentScanAction;
    }
    if (item.requirements.length === 0) return null;
    const unsatisfied = queue ? queue.getUnsatisfiedRequirements(item.id) : item.requirements;
    if (unsatisfied.length === 0) return null;
    const req = unsatisfied[0];
    const targetFile = req.targetFiles?.[0] || item.targetFiles[0] || target.filePath;
    return actionForRequirement(req, target, targetFile);
}

function actionForRequirement(req: EvidenceRequirement, target: AgentScanTarget, explicitTargetFile?: string): AgentScanAction | null {
    const tool = req.requiredTools?.[0];
    if (!tool) return null;
    const targetFile = explicitTargetFile || req.targetFiles?.[0] || target.filePath;

    switch (tool) {
        case 'read_file':
            return {
                type: 'read_file',
                path: targetFile,
                rationale: req.description,
            } as AgentScanAction;
        case 'search_code':
            return {
                type: 'search_code',
                pattern: 'auth|require|guard|permission|owner',
                rationale: req.description,
            } as AgentScanAction;
        case 'check_policy':
            return {
                type: 'check_policy',
                filePath: targetFile,
                rationale: req.description,
            } as AgentScanAction;
        case 'check_guard':
            return {
                type: 'check_guard',
                filePath: targetFile,
                guardName: 'auth',
                attackType: 'broken_access_control',
                rationale: req.description,
            } as AgentScanAction;
        case 'get_endpoints':
            return {
                type: 'get_endpoints',
                rationale: req.description,
            } as AgentScanAction;
        case 'trace_flow':
        case 'trace_flow_cross_file':
            return {
                type: 'trace_flow_cross_file',
                filePath: targetFile,
                rationale: req.description,
            } as AgentScanAction;
        case 'read_config':
            return {
                type: 'read_config',
                configKind: 'all',
                rationale: req.description,
            } as AgentScanAction;
        case 'find_tests':
            return {
                type: 'find_tests',
                filePath: targetFile,
                rationale: req.description,
            } as AgentScanAction;
        case 'find_definition':
            return null;
        case 'find_references':
            return null;
        default:
            return null;
    }
}
