import { describe, it, expect, beforeEach } from 'vitest';
import {
    WorkItemQueue,
    createProfileWorkItem,
    createArchitectureRiskWorkItem,
    createHandlerReviewWorkItem,
    createImplementationReviewWorkItem,
} from '../src/attack/workItem';

describe('WorkItem', () => {
    describe('factory functions', () => {
        it('createProfileWorkItem creates a pending high-priority item', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                ['src/http.ts'],
            );
            expect(item.kind).toBe('profile-requirement');
            expect(item.status).toBe('pending');
            expect(item.priority).toBe('high');
            expect(item.targetFiles).toContain('src/http.ts');
        });

        it('createArchitectureRiskWorkItem creates a high-priority item', () => {
            const item = createArchitectureRiskWorkItem('No rate limiting', ['src/auth.ts'], []);
            expect(item.kind).toBe('architecture-risk');
            expect(item.priority).toBe('high');
        });

        it('createHandlerReviewWorkItem creates a medium-priority item', () => {
            const item = createHandlerReviewWorkItem('src/http.ts', 'handleLogin');
            expect(item.kind).toBe('handler-review');
            expect(item.priority).toBe('medium');
            expect(item.title).toContain('handleLogin');
        });

        it('createImplementationReviewWorkItem creates a critical-priority item', () => {
            const item = createImplementationReviewWorkItem('src/auth.ts', 'ServerAuth');
            expect(item.kind).toBe('implementation-review');
            expect(item.priority).toBe('critical');
        });
    });

    describe('WorkItemQueue', () => {
        let queue: WorkItemQueue;

        beforeEach(() => {
            queue = new WorkItemQueue();
        });

        it('adds and retrieves items', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            expect(queue.get(item.id)).toBeDefined();
            expect(queue.size()).toBe(1);
        });

        it('does not duplicate items with the same id', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            queue.add(item);
            expect(queue.size()).toBe(1);
        });

        it('increments attempts and blocks after maxAttempts', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            item.maxAttempts = 2;
            queue.add(item);
            queue.incrementAttempt(item.id);
            expect(queue.get(item.id)!.status).toBe('pending');
            queue.incrementAttempt(item.id);
            expect(queue.get(item.id)!.status).toBe('blocked');
            expect(queue.get(item.id)!.blockedReason).toContain('Max attempts');
        });

        it('resolves and refutes items', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            queue.addEvidenceForRequirement(item.id, 'req-1', 'ev-1');
            queue.resolve(item.id);
            expect(queue.get(item.id)!.status).toBe('resolved');
            expect(queue.getUnresolved()).toHaveLength(0);
        });

        it('does NOT resolve when requirements are not satisfied', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            queue.addEvidence(item.id, 'ev-1');
            queue.resolve(item.id);
            expect(queue.get(item.id)!.status).toBe('pending');
        });

        it('forceResolve bypasses requirement checks', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            queue.forceResolve(item.id);
            expect(queue.get(item.id)!.status).toBe('resolved');
        });

        it('highestPriority returns the highest-priority executable item', () => {
            const low = createHandlerReviewWorkItem('a.ts', 'low');
            const critical = createImplementationReviewWorkItem('b.ts', 'critical');
            queue.addAll([low, critical]);
            const top = queue.highestPriority();
            expect(top).toBeDefined();
            expect(top!.priority).toBe('critical');
        });

        it('highestPriority returns null when no executable items remain', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            queue.forceResolve(item.id);
            expect(queue.highestPriority()).toBeNull();
        });

        it('addEvidence links evidence to the item', () => {
            const item = createProfileWorkItem(
                { id: 'req-1', description: 'test', acceptedKinds: ['source-range'], minimumCount: 1 },
                [],
            );
            queue.add(item);
            queue.addEvidence(item.id, 'ev-1');
            queue.addEvidence(item.id, 'ev-1'); // duplicate
            expect(queue.get(item.id)!.evidenceRefs).toHaveLength(1);
        });

        it('getUnresolved returns pending, active, and blocked items', () => {
            const item1 = createProfileWorkItem({ id: 'r1', description: 'a', acceptedKinds: [], minimumCount: 1 }, []);
            const item2 = createProfileWorkItem({ id: 'r2', description: 'b', acceptedKinds: [], minimumCount: 1 }, []);
            const item3 = createProfileWorkItem({ id: 'r3', description: 'c', acceptedKinds: [], minimumCount: 1 }, []);
            queue.addAll([item1, item2, item3]);
            queue.forceResolve(item1.id);
            queue.update(item2.id, { status: 'blocked' });
            const unresolved = queue.getUnresolved();
            expect(unresolved).toHaveLength(2);
        });

        it('addEvidenceForRequirement links evidence to specific requirement', () => {
            const item = createArchitectureRiskWorkItem('Shell exec risk', ['wsRpc.ts'], [
                { id: 'req-source', description: 'Find source', acceptedKinds: ['source-range'], minimumCount: 1 },
                { id: 'req-flow', description: 'Trace flow', acceptedKinds: ['cross-file-flow'], minimumCount: 1 },
            ]);
            queue.add(item);
            queue.addEvidenceForRequirement(item.id, 'req-source', 'ev-source-1');
            expect(queue.isRequirementSatisfied(item.id, 'req-source')).toBe(true);
            expect(queue.isRequirementSatisfied(item.id, 'req-flow')).toBe(false);
            expect(queue.isFullyResolved(item.id)).toBe(false);
        });

        it('two source reads do NOT satisfy one source and one flow requirement', () => {
            const item = createArchitectureRiskWorkItem('Shell exec risk', ['wsRpc.ts'], [
                { id: 'req-source', description: 'Find source', acceptedKinds: ['source-range'], minimumCount: 1 },
                { id: 'req-flow', description: 'Trace flow', acceptedKinds: ['cross-file-flow'], minimumCount: 1 },
            ]);
            queue.add(item);
            queue.addEvidenceForRequirement(item.id, 'req-source', 'ev-1');
            queue.addEvidenceForRequirement(item.id, 'req-source', 'ev-2');
            expect(queue.isFullyResolved(item.id)).toBe(false);
            expect(queue.getUnsatisfiedRequirements(item.id)).toHaveLength(1);
            expect(queue.getUnsatisfiedRequirements(item.id)[0].id).toBe('req-flow');
        });

        it('resolves only when ALL requirements are satisfied', () => {
            const item = createArchitectureRiskWorkItem('Shell exec risk', ['wsRpc.ts'], [
                { id: 'req-source', description: 'Find source', acceptedKinds: ['source-range'], minimumCount: 1 },
                { id: 'req-flow', description: 'Trace flow', acceptedKinds: ['cross-file-flow'], minimumCount: 1 },
            ]);
            queue.add(item);
            queue.addEvidenceForRequirement(item.id, 'req-source', 'ev-1');
            queue.resolve(item.id);
            expect(queue.get(item.id)!.status).toBe('pending');
            queue.addEvidenceForRequirement(item.id, 'req-flow', 'ev-2');
            queue.resolve(item.id);
            expect(queue.get(item.id)!.status).toBe('resolved');
        });
    });
});
