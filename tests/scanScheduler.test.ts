import { describe, it, expect, beforeEach } from 'vitest';
import { schedule, type SchedulerInput } from '../src/attack/scanScheduler';
import { createScanRunState, type ScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue, createProfileWorkItem, createImplementationReviewWorkItem } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { InvestigationState } from '../src/attack/investigationState';

const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 1.20, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
const target = { filePath: 'test.ts', language: 'typescript', fileContent: 'export function handler() {}' };

function makeInput(overrides?: Partial<SchedulerInput>): SchedulerInput {
    const state = createScanRunState('run-1', target, budget);
    return {
        state,
        evidence: new EvidenceLedger(),
        workItems: new WorkItemQueue(),
        handlers: new HandlerInventory(),
        candidates: new CandidateStore(),
        investigation: new InvestigationState(),
        target,
        ...overrides,
    };
}

describe('Scan Scheduler', () => {
    it('returns finish-ready when no executable work remains', () => {
        const input = makeInput();
        const decision = schedule(input);
        expect(decision.kind).toBe('finish-ready');
        expect(decision.reason).toContain('no executable work');
    });

    it('returns finish-ready when budget is exhausted', () => {
        const input = makeInput({
            state: createScanRunState('run-1', target, { ...budget, stepsRemaining: 0 }),
        });
        const decision = schedule(input);
        expect(decision.kind).toBe('finish-ready');
        expect(decision.reason).toContain('No budget');
    });

    it('schedules implementation resolution for critical work item', () => {
        const workItems = new WorkItemQueue();
        workItems.add(createImplementationReviewWorkItem('test.ts', 'ServerAuth'));
        const input = makeInput({ workItems });
        const decision = schedule(input);
        expect(decision.kind).toBe('deterministic-action');
        expect(decision.action?.type).toBeDefined();
    });

    it('schedules read_file for unreviewed security-sensitive handler', () => {
        const handlers = new HandlerInventory();
        handlers.add({
            filePath: 'test.ts',
            symbol: 'handleLogin',
            range: { start: 50, end: 80 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        const input = makeInput({ handlers });
        const decision = schedule(input);
        expect(decision.kind).toBe('deterministic-action');
        expect(decision.action?.type).toBe('read_file');
    });

    it('schedules unread critical range when no other work', () => {
        const investigation = new InvestigationState();
        investigation.recordActualRead('test.ts', 1, 100, 500, false);
        const input = makeInput({ investigation });
        const decision = schedule(input);
        // Should schedule the next unread range (101+)
        if (decision.kind === 'deterministic-action') {
            expect(decision.action?.type).toBe('read_file');
        }
    });

    it('schedules evidence-gathering action for unsatisfied requirement', () => {
        const evidence = new EvidenceLedger();
        evidence.addRequirement({
            id: 'req-policy',
            description: 'Check policy on route handlers',
            acceptedKinds: ['policy-result'],
            requiredTools: ['check_policy'],
            minimumCount: 1,
        });
        const input = makeInput({ evidence });
        const decision = schedule(input);
        expect(decision.kind).toBe('deterministic-action');
        expect(decision.action?.type).toBe('check_policy');
    });

    it('schedules read_config for config-inspection requirement', () => {
        const evidence = new EvidenceLedger();
        evidence.addRequirement({
            id: 'req-config',
            description: 'Inspect security configuration',
            acceptedKinds: ['config-result'],
            requiredTools: ['read_config'],
            minimumCount: 1,
            acceptsNegative: true,
        });
        const input = makeInput({ evidence });
        const decision = schedule(input);
        expect(decision.kind).toBe('deterministic-action');
        expect(decision.action?.type).toBe('read_config');
    });

    it('schedules trace_flow_cross_file for cross-file-flow requirement', () => {
        const evidence = new EvidenceLedger();
        evidence.addRequirement({
            id: 'req-flow',
            description: 'Trace cross-file data flow',
            acceptedKinds: ['cross-file-flow'],
            requiredTools: ['trace_flow_cross_file'],
            minimumCount: 1,
        });
        const input = makeInput({ evidence });
        const decision = schedule(input);
        expect(decision.kind).toBe('deterministic-action');
        expect(decision.action?.type).toBe('trace_flow_cross_file');
    });

    it('schedules find_tests for test-location requirement', () => {
        const evidence = new EvidenceLedger();
        evidence.addRequirement({
            id: 'req-tests',
            description: 'Find tests for the target code',
            acceptedKinds: ['test-location'],
            requiredTools: ['find_tests'],
            minimumCount: 1,
            acceptsNegative: true,
        });
        const input = makeInput({ evidence });
        const decision = schedule(input);
        expect(decision.kind).toBe('deterministic-action');
        expect(decision.action?.type).toBe('find_tests');
    });

    it('returns model when no deterministic action can be derived', () => {
        const workItems = new WorkItemQueue();
        workItems.add({
            id: 'item-1', kind: 'profile-requirement', title: 'unknown',
            priority: 'low', targetFiles: [], requirements: [],
            evidenceRefs: [], status: 'pending', attempts: 0, maxAttempts: 3,
        });
        const input = makeInput({ workItems });
        const decision = schedule(input);
        // No requirements → can't derive an action → falls through to model or finish
        expect(['model', 'finish-ready']).toContain(decision.kind);
    });
});
