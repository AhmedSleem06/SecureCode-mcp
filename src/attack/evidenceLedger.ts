/**
 * Evidence ledger — tracks why a task or candidate is complete instead of
 * marking checklist steps complete because a tool was merely called.
 *
 * A tool invocation alone does not satisfy an evidence requirement.
 * The ledger records structured evidence with fingerprints and links it
 * to requirements. Progress is derived from newly accepted evidence,
 * not set manually.
 */

import * as crypto from 'crypto';
import type { LineRange } from './investigationState';
import type { AgentScanActionType } from './agentScanProtocol';

export type EvidenceKind =
    | 'source-range'
    | 'symbol-definition'
    | 'symbol-reference'
    | 'handler-inventory'
    | 'policy-result'
    | 'guard-result'
    | 'config-result'
    | 'cross-file-flow'
    | 'test-location'
    | 'test-result'
    | 'implementation-resolution'
    | 'proof-result'
    | 'threat-model-result'
    | 'reachability-result'
    | 'ownership-result'
    | 'capability-result';

export type EvidenceOutcome = 'positive' | 'negative' | 'empty' | 'blocked' | 'error';

export interface EvidenceRef {
    id: string;
    kind: EvidenceKind;
    transcriptStep: number;
    tool: AgentScanActionType;
    filePath?: string;
    range?: LineRange;
    symbol?: string;
    outcome: EvidenceOutcome;
    fingerprint: string;
}

export interface EvidenceRequirement {
    id: string;
    description: string;
    acceptedKinds: EvidenceKind[];
    targetFiles?: string[];
    requiredTools?: AgentScanActionType[];
    minimumCount: number;
    acceptsNegative?: boolean;
}

export interface ProgressDelta {
    newRanges: LineRange[];
    newSymbols: string[];
    newReferences: number;
    newFlows: number;
    completedRequirementIds: string[];
    meaningful: boolean;
}

function fingerprintEvidence(input: {
    kind: EvidenceKind;
    tool: AgentScanActionType;
    filePath?: string;
    range?: LineRange;
    symbol?: string;
    outcome: EvidenceOutcome;
}): string {
    return crypto
        .createHash('sha256')
        .update(JSON.stringify(input))
        .digest('hex')
        .slice(0, 16);
}

export class EvidenceLedger {
    private evidence = new Map<string, EvidenceRef>();
    private requirementStates = new Map<string, { requirement: EvidenceRequirement; count: number }>();
    private symbols = new Set<string>();
    private flows = 0;

    addRequirement(requirement: EvidenceRequirement): void {
        if (!this.requirementStates.has(requirement.id)) {
            this.requirementStates.set(requirement.id, { requirement, count: 0 });
        }
    }

    addRequirements(requirements: EvidenceRequirement[]): void {
        for (const req of requirements) {
            this.addRequirement(req);
        }
    }

    recordEvidence(input: Omit<EvidenceRef, 'id' | 'fingerprint'>): { ref: EvidenceRef; delta: ProgressDelta } {
        const fingerprint = fingerprintEvidence({
            kind: input.kind,
            tool: input.tool,
            filePath: input.filePath,
            range: input.range,
            symbol: input.symbol,
            outcome: input.outcome,
        });

        // Skip duplicate evidence (same fingerprint)
        if (this.evidence.has(fingerprint)) {
            return {
                ref: this.evidence.get(fingerprint)!,
                delta: this.emptyDelta(),
            };
        }

        const ref: EvidenceRef = {
            ...input,
            id: fingerprint,
            fingerprint,
        };
        this.evidence.set(fingerprint, ref);

        // Track symbols and flows
        const newSymbols: string[] = [];
        if (input.symbol && !this.symbols.has(input.symbol)) {
            this.symbols.add(input.symbol);
            newSymbols.push(input.symbol);
        }
        const newFlows = input.kind === 'cross-file-flow' ? 1 : 0;
        this.flows += newFlows;

        // Check if this evidence satisfies any requirements
        const completedRequirementIds: string[] = [];
        for (const [reqId, state] of this.requirementStates) {
            if (state.count >= state.requirement.minimumCount) continue;

            const req = state.requirement;
            if (!req.acceptedKinds.includes(input.kind)) continue;
            if (req.targetFiles && input.filePath &&
                !req.targetFiles.some(f => this.pathMatches(f, input.filePath!))) continue;
            if (req.requiredTools && !req.requiredTools.includes(input.tool)) continue;
            if (input.outcome === 'blocked' || input.outcome === 'error') continue;
            if (input.outcome === 'empty' && !req.acceptsNegative) continue;

            state.count++;
            if (state.count >= req.minimumCount) {
                completedRequirementIds.push(reqId);
            }
        }

        const meaningful = completedRequirementIds.length > 0 ||
                          newSymbols.length > 0 ||
                          newFlows > 0 ||
                          (input.kind === 'source-range' && input.outcome === 'positive');

        return {
            ref,
            delta: {
                newRanges: input.range && input.kind === 'source-range' ? [input.range] : [],
                newSymbols,
                newReferences: input.kind === 'symbol-reference' ? 1 : 0,
                newFlows,
                completedRequirementIds,
                meaningful,
            },
        };
    }

    isRequirementSatisfied(requirementId: string): boolean {
        const state = this.requirementStates.get(requirementId);
        if (!state) return false;
        return state.count >= state.requirement.minimumCount;
    }

    getUnsatisfiedRequirements(): EvidenceRequirement[] {
        const unsatisfied: EvidenceRequirement[] = [];
        for (const [_, state] of this.requirementStates) {
            if (state.count < state.requirement.minimumCount) {
                unsatisfied.push(state.requirement);
            }
        }
        return unsatisfied;
    }

    getAllEvidence(): EvidenceRef[] {
        return [...this.evidence.values()];
    }

    getEvidenceByKind(kind: EvidenceKind): EvidenceRef[] {
        return [...this.evidence.values()].filter(e => e.kind === kind);
    }

    getEvidenceForFile(filePath: string): EvidenceRef[] {
        return [...this.evidence.values()].filter(e => e.filePath && this.pathMatches(filePath, e.filePath));
    }

    snapshot(): { evidenceCount: number; requirementCount: number; satisfiedCount: number; symbolCount: number; flowCount: number } {
        let satisfied = 0;
        for (const [_, state] of this.requirementStates) {
            if (state.count >= state.requirement.minimumCount) satisfied++;
        }
        return {
            evidenceCount: this.evidence.size,
            requirementCount: this.requirementStates.size,
            satisfiedCount: satisfied,
            symbolCount: this.symbols.size,
            flowCount: this.flows,
        };
    }

    private emptyDelta(): ProgressDelta {
        return {
            newRanges: [],
            newSymbols: [],
            newReferences: 0,
            newFlows: 0,
            completedRequirementIds: [],
            meaningful: false,
        };
    }

    private pathMatches(pattern: string, path: string): boolean {
        const np = pattern.replace(/\\/g, '/').toLowerCase();
        const np2 = path.replace(/\\/g, '/').toLowerCase();
        return np === np2 || np2.includes(np) || np.includes(np2);
    }
}
