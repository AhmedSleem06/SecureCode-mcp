/**
 * Candidate store — tracks vulnerability candidates before finish, accumulates
 * evidence, and guarantees every candidate becomes terminal before the scan
 * can complete.
 *
 * Candidates are NOT findings. A candidate is a structured concern that the
 * agent is investigating. Only after verification does a candidate become a
 * finding (or get rejected/unproven).
 *
 * Rules:
 * - Every final finding must originate from a candidate.
 * - The model cannot mark a candidate as 'verified' — only the verifier can.
 * - The model may propose 'rejected' or 'unproven', but the MCP validates evidence.
 * - Duplicate root causes are merged.
 * - Candidates cannot disappear between steps.
 */

import type { EvidenceRequirement } from './evidenceLedger';

export type CandidateStatus =
    | 'discovered'
    | 'investigating'
    | 'supported'
    | 'rejected'
    | 'unproven'
    | 'verified'
    | 'merged'
    | 'blocked';

export type CandidateSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface EvidenceLocation {
    filePath: string;
    line: number;
    symbol?: string;
}

export interface CandidateVerification {
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    reason: string;
    repeatedRuns: number;
    repeatPasses: number;
    mutationDiscriminating: boolean;
}

export type ProofDimension =
    | 'source'
    | 'reachability'
    | 'control'
    | 'threat-model'
    | 'impact'
    | 'verification';

export interface Candidate {
    id: string;
    rootCauseId: string;
    type: string;
    severity: CandidateSeverity;
    locations: EvidenceLocation[];
    claim: string;
    status: CandidateStatus;
    evidenceRefs: string[];
    evidenceCategories?: EvidenceCategory[];
    requiredEvidence: EvidenceRequirement[];
    requiredProofDimensions?: ProofDimension[];
    satisfiedDimensions?: ProofDimension[];
    verification?: CandidateVerification;
    mergedInto?: string;
    blockedReason?: string;
    createdAt: number;
    updatedAt: number;
}

let candidateIdCounter = 0;

export interface CandidateRegistration {
    rootCauseId: string;
    type: string;
    severity: CandidateSeverity;
    locations: EvidenceLocation[];
    claim: string;
    requiredEvidence?: EvidenceRequirement[];
    requiredProofDimensions?: ProofDimension[];
}

export type EvidenceCategory =
    | 'source'
    | 'flow'
    | 'guard'
    | 'policy'
    | 'impact'
    | 'test'
    | 'negative'
    | 'cross-file';

export class CandidateStore {
    private candidates = new Map<string, Candidate>();
    private rootCauseIndex = new Map<string, string[]>();

    register(input: CandidateRegistration): string {
        // Check for existing candidates with the same root cause
        const existing = this.rootCauseIndex.get(input.rootCauseId);
        if (existing && existing.length > 0) {
            // Merge into the first candidate with this root cause
            const firstId = existing[0];
            const first = this.candidates.get(firstId);
            if (first) {
                // Add new locations
                for (const loc of input.locations) {
                    if (!first.locations.some(l => l.filePath === loc.filePath && l.line === loc.line)) {
                        first.locations.push(loc);
                    }
                }
                first.updatedAt = Date.now();
                return firstId;
            }
        }

        const id = `candidate-${++candidateIdCounter}`;
        const now = Date.now();
        const defaultDimensions: ProofDimension[] = input.severity === 'critical' || input.severity === 'high'
            ? ['source', 'reachability', 'control', 'threat-model', 'impact', 'verification']
            : input.severity === 'medium'
                ? ['source', 'reachability', 'control', 'threat-model']
                : ['source', 'control'];
        const requiredProofDimensions = input.requiredProofDimensions || defaultDimensions;
        const candidate: Candidate = {
            id,
            rootCauseId: input.rootCauseId,
            type: input.type,
            severity: input.severity,
            locations: input.locations,
            claim: input.claim,
            status: 'discovered',
            evidenceRefs: [],
            requiredEvidence: input.requiredEvidence || [],
            requiredProofDimensions,
            satisfiedDimensions: [],
            createdAt: now,
            updatedAt: now,
        };
        this.candidates.set(id, candidate);

        // Index by root cause
        const rcList = this.rootCauseIndex.get(input.rootCauseId) || [];
        rcList.push(id);
        this.rootCauseIndex.set(input.rootCauseId, rcList);

        return id;
    }

    get(id: string): Candidate | undefined {
        return this.candidates.get(id);
    }

    update(id: string, update: Partial<Candidate>): void {
        const candidate = this.candidates.get(id);
        if (!candidate) return;

        // The model cannot set status to 'verified' — only the verifier can
        if (update.status === 'verified' && candidate.status !== 'verified') {
            throw new Error('Cannot mark candidate as verified — only the verifier can set this status');
        }

        Object.assign(candidate, update, { updatedAt: Date.now() });
    }

    setVerified(id: string, verification: CandidateVerification): void {
        const candidate = this.candidates.get(id);
        if (!candidate) return;
        candidate.status = 'verified';
        candidate.verification = verification;
        candidate.updatedAt = Date.now();
    }

    setUnproven(id: string, reason: string): void {
        const candidate = this.candidates.get(id);
        if (!candidate) return;
        candidate.status = 'unproven';
        candidate.verification = {
            verdict: 'UNPROVEN',
            reason,
            repeatedRuns: 0,
            repeatPasses: 0,
            mutationDiscriminating: false,
        };
        candidate.updatedAt = Date.now();
    }

    setBlocked(id: string, reason: string): void {
        const candidate = this.candidates.get(id);
        if (!candidate) return;
        candidate.status = 'blocked';
        candidate.blockedReason = reason;
        candidate.verification = undefined;
        candidate.updatedAt = Date.now();
    }

    addEvidence(id: string, evidenceRef: string, category?: EvidenceCategory, dimension?: ProofDimension): void {
        const candidate = this.candidates.get(id);
        if (candidate && !candidate.evidenceRefs.includes(evidenceRef)) {
            candidate.evidenceRefs.push(evidenceRef);
            if (category) {
                if (!candidate.evidenceCategories) candidate.evidenceCategories = [];
                if (!candidate.evidenceCategories.includes(category)) {
                    candidate.evidenceCategories.push(category);
                }
            }
            if (dimension) {
                if (!candidate.satisfiedDimensions) candidate.satisfiedDimensions = [];
                if (!candidate.satisfiedDimensions.includes(dimension)) {
                    candidate.satisfiedDimensions.push(dimension);
                }
            }
            if (candidate.status === 'discovered') {
                candidate.status = 'investigating';
            }
            const required = candidate.requiredProofDimensions || [];
            const satisfied = candidate.satisfiedDimensions || [];
            if (candidate.status === 'investigating' && required.length > 0) {
                const allDimensionsSatisfied = required.every(d => satisfied.includes(d));
                if (allDimensionsSatisfied) {
                    candidate.status = 'supported';
                }
            } else if (candidate.status === 'investigating' && required.length === 0) {
                const categories = candidate.evidenceCategories || [];
                const categoryCount = categories.length;
                const minCategories = (candidate.severity === 'critical' || candidate.severity === 'high') ? 2 : 1;
                if (categoryCount >= minCategories) {
                    candidate.status = 'supported';
                } else if (candidate.evidenceRefs.length >= 1 && categoryCount === 0) {
                    candidate.status = 'supported';
                }
            }
            candidate.updatedAt = Date.now();
        }
    }

    isReadyForJuror(id: string): boolean {
        const candidate = this.candidates.get(id);
        if (!candidate) return false;
        if (candidate.status !== 'supported') return false;
        const required = candidate.requiredProofDimensions || [];
        if (required.length === 0) return true;
        const satisfied = candidate.satisfiedDimensions || [];
        return required.every(d => satisfied.includes(d));
    }

    getCandidatesByRootCause(rootCauseId: string): Candidate[] {
        const ids = this.rootCauseIndex.get(rootCauseId) || [];
        return ids.map(id => this.candidates.get(id)).filter(Boolean) as Candidate[];
    }

    getAll(): Candidate[] {
        return [...this.candidates.values()];
    }

    getActive(): Candidate[] {
        return [...this.candidates.values()].filter(c =>
            c.status === 'discovered' || c.status === 'investigating' || c.status === 'supported',
        );
    }

    getTerminal(): Candidate[] {
        return [...this.candidates.values()].filter(c =>
            c.status === 'verified' || c.status === 'unproven' ||
            c.status === 'rejected' || c.status === 'merged' || c.status === 'blocked',
        );
    }

    getVerified(): Candidate[] {
        return [...this.candidates.values()].filter(c => c.status === 'verified');
    }

    allTerminal(): boolean {
        const all = this.getAll();
        if (all.length === 0) return true;
        return all.every(c =>
            c.status === 'verified' || c.status === 'unproven' ||
            c.status === 'rejected' || c.status === 'merged' || c.status === 'blocked',
        );
    }

    allReadyForJuror(): boolean {
        const all = this.getAll();
        if (all.length === 0) return true;
        return all.every(c =>
            c.status === 'supported' || c.status === 'verified' ||
            c.status === 'unproven' || c.status === 'rejected' ||
            c.status === 'merged' || c.status === 'blocked',
        );
    }

    getUnderInvestigation(): Candidate[] {
        return [...this.candidates.values()].filter(c =>
            c.status === 'discovered' || c.status === 'investigating',
        );
    }

    size(): number {
        return this.candidates.size;
    }

    snapshot(): {
        total: number;
        discovered: number;
        investigating: number;
        supported: number;
        verified: number;
        unproven: number;
        rejected: number;
        merged: number;
        blocked: number;
        terminal: number;
    } {
        const all = this.getAll();
        return {
            total: all.length,
            discovered: all.filter(c => c.status === 'discovered').length,
            investigating: all.filter(c => c.status === 'investigating').length,
            supported: all.filter(c => c.status === 'supported').length,
            verified: all.filter(c => c.status === 'verified').length,
            unproven: all.filter(c => c.status === 'unproven').length,
            rejected: all.filter(c => c.status === 'rejected').length,
            merged: all.filter(c => c.status === 'merged').length,
            blocked: all.filter(c => c.status === 'blocked').length,
            terminal: all.filter(c =>
                c.status === 'verified' || c.status === 'unproven' ||
                c.status === 'rejected' || c.status === 'merged' || c.status === 'blocked',
            ).length,
        };
    }

    clear(): void {
        this.candidates.clear();
        this.rootCauseIndex.clear();
    }
}
