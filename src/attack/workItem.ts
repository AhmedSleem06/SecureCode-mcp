/**
 * Work item — a structured unit of investigation work that the scheduler
 * can prioritize. Work items are derived from profile requirements and
 * architecture-risk tasks.
 */

import type { EvidenceRequirement } from './evidenceLedger';
import type { AgentScanActionType } from './agentScanProtocol';

export type WorkItemKind =
    | 'profile-requirement'
    | 'architecture-risk'
    | 'handler-review'
    | 'implementation-review'
    | 'candidate-evidence'
    | 'verification-recovery';

export type WorkItemPriority = 'critical' | 'high' | 'medium' | 'low';
export type WorkItemStatus = 'pending' | 'active' | 'resolved' | 'refuted' | 'blocked';

export type RequirementStatus = 'missing' | 'satisfied' | 'refuted' | 'blocked';

export interface RequirementEvidence {
    requirementId: string;
    evidenceRefs: string[];
    status: RequirementStatus;
}

export interface WorkItem {
    id: string;
    kind: WorkItemKind;
    title: string;
    priority: WorkItemPriority;
    targetFiles: string[];
    requirements: EvidenceRequirement[];
    evidenceRefs: string[];
    requirementEvidence: Map<string, RequirementEvidence>;
    status: WorkItemStatus;
    attempts: number;
    blockedReason?: string;
    maxAttempts: number;
}

let idCounter = 0;
function nextId(prefix: string): string {
    idCounter++;
    return `${prefix}-${idCounter}`;
}

export function createProfileWorkItem(
    requirement: EvidenceRequirement,
    targetFiles: string[],
): WorkItem {
    return {
        id: nextId('profile'),
        kind: 'profile-requirement',
        title: requirement.description,
        priority: 'high',
        targetFiles,
        requirements: [requirement],
        evidenceRefs: [],
        requirementEvidence: new Map([[requirement.id, { requirementId: requirement.id, evidenceRefs: [], status: 'missing' }]]),
        status: 'pending',
        attempts: 0,
        maxAttempts: 3,
    };
}

export function createArchitectureRiskWorkItem(
    title: string,
    targetFiles: string[],
    requirements: EvidenceRequirement[],
): WorkItem {
    const requirementEvidence = new Map<string, RequirementEvidence>();
    for (const req of requirements) {
        requirementEvidence.set(req.id, { requirementId: req.id, evidenceRefs: [], status: 'missing' });
    }
    return {
        id: nextId('arch-risk'),
        kind: 'architecture-risk',
        title,
        priority: 'high',
        targetFiles,
        requirements,
        evidenceRefs: [],
        requirementEvidence,
        status: 'pending',
        attempts: 0,
        maxAttempts: 3,
    };
}

export function createHandlerReviewWorkItem(
    filePath: string,
    symbol: string,
): WorkItem {
    const reqId = nextId('handler-req');
    const requirement: EvidenceRequirement = {
        id: reqId,
        description: `Review handler ${symbol}`,
        acceptedKinds: ['source-range', 'policy-result'],
        minimumCount: 1,
    };
    return {
        id: nextId('handler'),
        kind: 'handler-review',
        title: `Review handler: ${symbol}`,
        priority: 'medium',
        targetFiles: [filePath],
        requirements: [requirement],
        evidenceRefs: [],
        requirementEvidence: new Map([[reqId, { requirementId: reqId, evidenceRefs: [], status: 'missing' }]]),
        status: 'pending',
        attempts: 0,
        maxAttempts: 2,
    };
}

export function createImplementationReviewWorkItem(
    filePath: string,
    symbol: string,
): WorkItem {
    const reqId = nextId('impl-req');
    const requirement: EvidenceRequirement = {
        id: reqId,
        description: `Resolve implementation of ${symbol}`,
        acceptedKinds: ['implementation-resolution'],
        minimumCount: 1,
    };
    return {
        id: nextId('impl'),
        kind: 'implementation-review',
        title: `Resolve implementation for: ${symbol}`,
        priority: 'critical',
        targetFiles: [filePath],
        requirements: [requirement],
        evidenceRefs: [],
        requirementEvidence: new Map([[reqId, { requirementId: reqId, evidenceRefs: [], status: 'missing' }]]),
        status: 'pending',
        attempts: 0,
        maxAttempts: 2,
    };
}

export class WorkItemQueue {
    private items = new Map<string, WorkItem>();

    add(item: WorkItem): void {
        if (!this.items.has(item.id)) {
            this.items.set(item.id, item);
        }
    }

    addAll(items: WorkItem[]): void {
        for (const item of items) this.add(item);
    }

    get(id: string): WorkItem | undefined {
        return this.items.get(id);
    }

    update(id: string, update: Partial<WorkItem>): void {
        const item = this.items.get(id);
        if (item) {
            Object.assign(item, update);
        }
    }

    addEvidence(id: string, evidenceRef: string): void {
        const item = this.items.get(id);
        if (item && !item.evidenceRefs.includes(evidenceRef)) {
            item.evidenceRefs.push(evidenceRef);
        }
    }

    addEvidenceForRequirement(id: string, requirementId: string, evidenceRef: string): void {
        const item = this.items.get(id);
        if (!item) return;
        if (!item.evidenceRefs.includes(evidenceRef)) {
            item.evidenceRefs.push(evidenceRef);
        }
        const reqEv = item.requirementEvidence.get(requirementId);
        if (reqEv && !reqEv.evidenceRefs.includes(evidenceRef)) {
            reqEv.evidenceRefs.push(evidenceRef);
            if (reqEv.status === 'missing') {
                const req = item.requirements.find(r => r.id === requirementId);
                if (req && reqEv.evidenceRefs.length >= req.minimumCount) {
                    reqEv.status = 'satisfied';
                }
            }
        }
    }

    isRequirementSatisfied(id: string, requirementId: string): boolean {
        const item = this.items.get(id);
        if (!item) return false;
        const reqEv = item.requirementEvidence.get(requirementId);
        return reqEv?.status === 'satisfied' || reqEv?.status === 'refuted';
    }

    isFullyResolved(id: string): boolean {
        const item = this.items.get(id);
        if (!item) return false;
        for (const req of item.requirements) {
            const reqEv = item.requirementEvidence.get(req.id);
            if (!reqEv || (reqEv.status !== 'satisfied' && reqEv.status !== 'refuted')) {
                return false;
            }
        }
        return true;
    }

    getUnsatisfiedRequirements(id: string): EvidenceRequirement[] {
        const item = this.items.get(id);
        if (!item) return [];
        const unsatisfied: EvidenceRequirement[] = [];
        for (const req of item.requirements) {
            const reqEv = item.requirementEvidence.get(req.id);
            if (!reqEv || (reqEv.status !== 'satisfied' && reqEv.status !== 'refuted')) {
                unsatisfied.push(req);
            }
        }
        return unsatisfied;
    }

    incrementAttempt(id: string): void {
        const item = this.items.get(id);
        if (item) {
            item.attempts++;
            if (item.attempts >= item.maxAttempts) {
                item.status = 'blocked';
                item.blockedReason = `Max attempts (${item.maxAttempts}) reached`;
            }
        }
    }

    resolve(id: string): void {
        const item = this.items.get(id);
        if (item && this.isFullyResolved(id)) {
            item.status = 'resolved';
        }
    }

    forceResolve(id: string): void {
        this.update(id, { status: 'resolved' });
    }

    refute(id: string): void {
        this.update(id, { status: 'refuted' });
    }

    getPending(): WorkItem[] {
        return [...this.items.values()].filter(i => i.status === 'pending');
    }

    getActive(): WorkItem[] {
        return [...this.items.values()].filter(i => i.status === 'active');
    }

    getBlocked(): WorkItem[] {
        return [...this.items.values()].filter(i => i.status === 'blocked');
    }

    getUnresolved(): WorkItem[] {
        return [...this.items.values()].filter(i => i.status === 'pending' || i.status === 'active' || i.status === 'blocked');
    }

    getExecutable(): WorkItem[] {
        return [...this.items.values()].filter(i => i.status === 'pending' || i.status === 'active');
    }

    highestPriority(): WorkItem | null {
        const executable = this.getExecutable();
        if (executable.length === 0) return null;
        const priorityOrder: Record<WorkItemPriority, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        executable.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);
        return executable[0];
    }

    all(): WorkItem[] {
        return [...this.items.values()];
    }

    size(): number {
        return this.items.size;
    }
}
