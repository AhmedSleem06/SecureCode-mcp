import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({
            postJson: vi.fn(),
        })),
    };
});

vi.mock('../src/attack/agentScanExecutor', () => ({
    executeAction: vi.fn(),
    executeReadFileAction: vi.fn(),
    executeFlowAction: vi.fn(),
    extractFunctionBoundaries: vi.fn(),
}));

import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { executeAction, executeReadFileAction, executeFlowAction, extractFunctionBoundaries } from '../src/attack/agentScanExecutor';
import { evaluateFinishGate, unresolvedOpenLeads } from '../src/attack/finishGate';
import { InvestigationState, promptShownRange, uncoveredWithin } from '../src/attack/investigationState';
import { createScanRunState } from '../src/attack/scanState';
import { EvidenceLedger } from '../src/attack/evidenceLedger';
import { WorkItemQueue } from '../src/attack/workItem';
import { HandlerInventory } from '../src/project-map/handlerInventory';
import { CandidateStore } from '../src/attack/candidateStore';
import { HTTP_ROUTE_PROFILE, WEBSOCKET_RPC_PROFILE, suggestedChecks } from '../src/attack/investigationProfiles';
import { buildPriorPartsContext } from '../src/tools/agentScan';

const ctx = { workspaceRoot: '/tmp/securecode-evidence-gate-test-missing', apiUrl: 'http://localhost:3000', apiToken: 'test' };
const budget = { stepsRemaining: 40, costSpentUsd: 0, costCapUsd: 4.0, stepsGranted: 40, hardMaxSteps: 80, extensionsGranted: 0 };
const evidenceHarness = { gateMode: 'evidence', fullReadWindow: 3, reReadPolicy: 'coverage' };
const startResp = (harness?: unknown) => ({ runId: 'run-1', budget, scanCredits: 95, refundId: 'r1', ...(harness ? { harness } : {}) });

function step(next: any, remaining: number, extra: Record<string, unknown> = {}) {
    return { next, costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: remaining, ...extra };
}

function mockPostJson(responses: any[]) {
    const mockFn = vi.fn();
    for (const resp of responses) mockFn.mockResolvedValueOnce(resp);
    mockFn.mockResolvedValue({ settlement: { creditsRefunded: 0, creditsUsed: 5 } });
    (ApiClient as any).mockImplementation(() => ({ postJson: mockFn }));
    return mockFn;
}

function linesContent(total: number, special: Record<number, string> = {}): string {
    return Array.from({ length: total }, (_, i) => special[i + 1] ?? `const v${i + 1} = ${i + 1};`).join('\n');
}

function setupExecutors(totalLines: number, flowLine?: { filePath: string; line: number }) {
    (executeReadFileAction as any).mockImplementation(async (action: any) => ({
        observation: `lines ${action.startLine}-${action.endLine}`,
        actualStart: action.startLine ?? 1,
        actualEnd: action.endLine ?? totalLines,
        totalLines,
        truncated: false,
    }));
    (executeAction as any).mockResolvedValue('ok');
    (executeFlowAction as any).mockResolvedValue({
        observation: 'flow result',
        flowResult: { status: 'confirmed', hops: flowLine ? [flowLine] : [], truncated: false },
    });
    (extractFunctionBoundaries as any).mockResolvedValue(null);
}

const stepBodies = (mockFn: any) => (mockFn.mock.calls as any[]).filter(c => c[0] === '/agent/scan/step').map(c => c[1]);
const rejections = (result: any) => result.transcript.filter((t: any) => t.action.type === 'system_event' && t.action.eventType === 'finish_rejected');
const finding = (line: number, extra: Record<string, unknown> = {}) => ({ line, type: 'missing_authorization', severity: 'high', confidence: 80, evidence: 'no owner check', why: 'any client can change the owner settings', ...extra });
const lead = (id: string, claim: string, line: number | null, status = 'open') => ({ id, claim, line, status, resolution: null });

function gateInput(overrides: Record<string, any> = {}) {
    const target = { filePath: 'svc.ts', language: 'typescript', fileContent: overrides.fileContent ?? linesContent(100) };
    return {
        proposal: { type: 'finish', findings: [], summary: 'done', selfCritique: 'checked' } as any,
        state: createScanRunState('run-1', target, budget),
        evidence: new EvidenceLedger(),
        workItems: new WorkItemQueue(),
        handlers: new HandlerInventory(),
        candidates: new CandidateStore(),
        investigation: new InvestigationState(),
        scheduler: { kind: 'deterministic-action' as const, reason: 'checklist', action: { type: 'read_config', configKind: 'all', rationale: 'r' } as any },
        target: { filePath: 'svc.ts', fileContent: target.fileContent },
        ...overrides,
    };
}

function evidenceGate(overrides: Record<string, any> = {}) {
    return { currentLeads: [], deliveredRanges: [{ start: 1, end: 100 }], targetRange: { start: 1, end: 100 }, openLeadsRejectedOnce: false, ...overrides };
}

describe('promptShownRange', () => {
    it('covers a small file entirely', () => {
        expect(promptShownRange(linesContent(100))).toEqual({ start: 1, end: 100 });
    });

    it('covers only lines that end inside the first 12,000 chars', () => {
        const content = Array.from({ length: 300 }, () => 'x'.repeat(99)).join('\n');
        expect(promptShownRange(content)).toEqual({ start: 1, end: 120 });
    });

    it('covers the shown part of a split file', () => {
        const content = Array.from({ length: 3000 }, () => 'y'.repeat(49)).join('\n');
        expect(promptShownRange(content, { startLine: 1001, endLine: 2000 })).toEqual({ start: 1001, end: 1240 });
        expect(promptShownRange(linesContent(3000), { startLine: 1001, endLine: 1100 })).toEqual({ start: 1001, end: 1100 });
    });

    it('returns null for empty content', () => {
        expect(promptShownRange('')).toBeNull();
        expect(promptShownRange(undefined)).toBeNull();
    });

    it('uncoveredWithin returns the gaps inside the bounds', () => {
        expect(uncoveredWithin({ start: 1, end: 100 }, [{ start: 10, end: 20 }, { start: 15, end: 40 }, { start: 90, end: 120 }]))
            .toEqual([{ start: 1, end: 9 }, { start: 41, end: 89 }]);
        expect(uncoveredWithin({ start: 5, end: 8 }, [{ start: 1, end: 10 }])).toEqual([]);
    });
});

describe('evaluateFinishGate — evidence mode', () => {
    it('accepts with no ritual tools when the target was delivered', () => {
        const result = evaluateFinishGate(gateInput({ gateMode: 'evidence', evidenceGate: evidenceGate() }) as any);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('complete');
        expect(result.recoveryAction).toBeUndefined();
    });

    it('checklist mode still rejects the same finish', () => {
        const result = evaluateFinishGate(gateInput({ evidenceGate: evidenceGate() }) as any);
        expect(result.accepted).toBe(false);
        expect(result.reasons.some(r => r.code === 'incomplete-checklist')).toBe(true);
        expect(result.recoveryAction?.type).toBe('read_config');
    });

    it('floor blocks a finish after one small read when security code is unread', () => {
        const fileContent = linesContent(400, { 300: 'if (password === stored) return issueToken(user);' });
        const result = evaluateFinishGate(gateInput({
            fileContent,
            gateMode: 'evidence',
            evidenceGate: evidenceGate({ deliveredRanges: [{ start: 1, end: 50 }], targetRange: { start: 1, end: 400 } }),
        }) as any);
        expect(result.accepted).toBe(false);
        const codes = result.reasons.map(r => r.code);
        expect(codes).toContain('investigation-floor');
        expect(codes).toContain('high-priority-unread-range');
        expect(result.reasons.find(r => r.code === 'investigation-floor')!.description).toContain('Only 13% of lines 1–400');
    });

    it('floor passes at 50% coverage, or when nothing security-relevant is unread', () => {
        const plain = evaluateFinishGate(gateInput({
            fileContent: linesContent(400),
            gateMode: 'evidence',
            evidenceGate: evidenceGate({ deliveredRanges: [{ start: 1, end: 10 }], targetRange: { start: 1, end: 400 } }),
        }) as any);
        expect(plain.accepted).toBe(true);

        const half = evaluateFinishGate(gateInput({
            fileContent: linesContent(400, { 300: 'const token = req.headers.authorization;' }),
            gateMode: 'evidence',
            evidenceGate: evidenceGate({ deliveredRanges: [{ start: 1, end: 200 }], targetRange: { start: 1, end: 400 } }),
        }) as any);
        expect(half.reasons.map(r => r.code)).not.toContain('investigation-floor');
        expect(half.reasons.map(r => r.code)).toContain('high-priority-unread-range');
    });

    it('rejects open leads once, then accepts', () => {
        const leads = [lead('L1', 'settings write not owner-gated', 40), lead('L2', 'already a note', 12, 'note')];
        const first = evaluateFinishGate(gateInput({ gateMode: 'evidence', evidenceGate: evidenceGate({ currentLeads: leads }) }) as any);
        expect(first.accepted).toBe(false);
        const leadReasons = first.reasons.filter(r => r.code === 'open-leads');
        expect(leadReasons[0].description).toBe('Open lead not resolved: L1: settings write not owner-gated (line 40)');
        expect(leadReasons.some(r => r.description.includes('already a note'))).toBe(false);

        const second = evaluateFinishGate(gateInput({ gateMode: 'evidence', evidenceGate: evidenceGate({ currentLeads: leads, openLeadsRejectedOnce: true }) }) as any);
        expect(second.accepted).toBe(true);
    });

    it('does not reject a lead the finish already lists in coverageGaps', () => {
        const leads = [lead('L1', 'settings write not owner-gated', 40)];
        const proposal = { type: 'finish', findings: [], summary: 'done', coverageGaps: [{ title: 'L1 still open', detail: 'no time', requiredEvidence: [], suggestedNextAction: 'read', priority: 'low' }] };
        const result = evaluateFinishGate(gateInput({ proposal, gateMode: 'evidence', evidenceGate: evidenceGate({ currentLeads: leads }) }) as any);
        expect(result.accepted).toBe(true);
        expect(unresolvedOpenLeads(leads, proposal as any)).toEqual([]);
        expect(unresolvedOpenLeads(leads)).toHaveLength(1);
    });

    it('rejects a finding whose lines were not delivered', () => {
        const findings = [finding(60, { lineEnd: 62 })];
        const result = evaluateFinishGate(gateInput({
            proposal: { type: 'finish', findings, summary: 's' },
            gateMode: 'evidence',
            evidenceGate: evidenceGate({ deliveredRanges: [{ start: 1, end: 59 }, { start: 70, end: 100 }], findings }),
        }) as any);
        expect(result.accepted).toBe(false);
        expect(result.reasons.find(r => r.code === 'finding-unread-lines')!.description)
            .toBe('read lines 60–62 before reporting this finding (missing_authorization at line 60)');

        const read = evaluateFinishGate(gateInput({
            proposal: { type: 'finish', findings, summary: 's' },
            gateMode: 'evidence',
            evidenceGate: evidenceGate({ findings }),
        }) as any);
        expect(read.reasons.map(r => r.code)).not.toContain('finding-unread-lines');
    });

    it('accepts as forced-incomplete without budget and records the unread finding lines', () => {
        const target = { filePath: 'svc.ts', language: 'typescript', fileContent: linesContent(100) };
        const findings = [finding(80)];
        const result = evaluateFinishGate(gateInput({
            state: createScanRunState('run-1', target, { ...budget, stepsRemaining: 0 }),
            proposal: { type: 'finish', findings, summary: 's' },
            gateMode: 'evidence',
            evidenceGate: evidenceGate({ deliveredRanges: [{ start: 1, end: 50 }], findings }),
        }) as any);
        expect(result.accepted).toBe(true);
        expect(result.mode).toBe('forced-incomplete');
        expect(result.coverageGaps!.some(g => g.title.startsWith('Finding cites unread lines 80'))).toBe(true);
    });
});

describe('suggestedChecks', () => {
    it('returns neutral checks per profile', () => {
        expect(suggestedChecks(WEBSOCKET_RPC_PROFILE).some(c => c.includes('Per-method authorization'))).toBe(true);
        expect(suggestedChecks(HTTP_ROUTE_PROFILE).length).toBeGreaterThan(2);
        expect(suggestedChecks({ name: 'unknown', requiredSteps: [], description: '', requirements: [] }).length).toBeGreaterThan(0);
    });
});

describe('runAgentScan — evidence gate', () => {
    beforeEach(() => vi.clearAllMocks());

    const small = { filePath: 'small.ts', language: 'typescript', fileContent: linesContent(100, { 11: 'settings.owner = req.body.owner;' }) };

    it('finishes with no ritual tools and sends suggested checks only on the first step', async () => {
        setupExecutors(100);
        const mockFn = mockPostJson([
            startResp(evidenceHarness),
            step({ type: 'search_code', pattern: 'owner', rationale: 'r', memo: 'plan: check owner writes', leads: [lead('L1', 'owner write', 11)] }, 39),
            step({ type: 'finish', findings: [], summary: 'clean', selfCritique: 'ok', leads: [lead('L1', 'owner write', 11, 'dropped')] }, 38),
        ]);

        const result = await runAgentScan(ctx, small, {});

        expect(result.status).toBe('completed');
        expect(result.terminationReason).toBe('agent_finish');
        expect(rejections(result)).toHaveLength(0);
        const bodies = stepBodies(mockFn);
        expect(bodies[0].suggestedChecks.length).toBeGreaterThan(0);
        expect(bodies[1].suggestedChecks).toBeUndefined();
        const carried = bodies[1].transcript[0].action;
        expect(carried.memo).toBe('plan: check owner writes');
        expect(carried.leads).toEqual([lead('L1', 'owner write', 11)]);
    });

    it('counts prompt-shown source as read: a finding on line 11 is accepted without read_file', async () => {
        setupExecutors(100, { filePath: 'small.ts', line: 11 });
        const baseline = { role: 'client', alreadyCan: 'nothing on settings', alreadyCanLine: null, isEscalation: true };
        mockPostJson([
            startResp(evidenceHarness),
            step({ type: 'trace_flow', filePath: 'small.ts', rationale: 'r' }, 39),
            step({ type: 'finish', findings: [finding(11, { capabilityBaseline: baseline })], summary: 'found', selfCritique: 'ok' }, 38),
        ]);

        const result = await runAgentScan(ctx, small, {});

        expect(rejections(result)).toHaveLength(0);
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.findings.map(f => f.line)).toEqual([11]);
        expect(result.findings[0].capabilityBaseline).toEqual(baseline);
        expect(executeReadFileAction).not.toHaveBeenCalled();
    });

    it('rejects open leads once, carries the notebook on the rejection, then converts them to coverage gaps', async () => {
        setupExecutors(100);
        const leads = [lead('L1', 'terminal write not owner-gated', 40), lead('L2', 'rate limit missing', null)];
        mockPostJson([
            startResp(evidenceHarness),
            step({ type: 'finish', findings: [], summary: 'first', selfCritique: 'ok', memo: 'checked 1-100', leads }, 39),
            step({ type: 'finish', findings: [], summary: 'second', selfCritique: 'ok', memo: null, leads: null }, 38),
        ]);

        const result = await runAgentScan(ctx, small, {});

        const rejected = rejections(result);
        expect(rejected).toHaveLength(1);
        expect(rejected[0].observation).toContain('Open lead not resolved: L1: terminal write not owner-gated (line 40)');
        expect(rejected[0].action.memo).toBe('checked 1-100');
        expect(rejected[0].action.leads).toEqual(leads);
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.summary).toBe('second');
        const leadGaps = result.coverageGaps.filter(g => g.title.startsWith('Lead not resolved: '));
        expect(leadGaps.map(g => g.title)).toEqual([
            'Lead not resolved: terminal write not owner-gated',
            'Lead not resolved: rate limit missing',
        ]);
        expect(leadGaps[0].line).toBe(40);
        expect(leadGaps[0].priority).toBe('medium');
    });

    it('rejects a finding on unread lines until they are read', async () => {
        setupExecutors(3000, { filePath: 'big.ts', line: 2000 });
        const big = { filePath: 'big.ts', language: 'typescript', fileContent: linesContent(3000) };
        mockPostJson([
            startResp(evidenceHarness),
            step({ type: 'finish', findings: [finding(2000, { lineEnd: 2002 })], summary: 'early', selfCritique: 'ok' }, 39),
            step({ type: 'read_file', path: 'big.ts', startLine: 1990, endLine: 2010, rationale: 'confirm' }, 38),
            step({ type: 'trace_flow', filePath: 'big.ts', rationale: 'r' }, 37),
            step({ type: 'finish', findings: [finding(2000, { lineEnd: 2002 })], summary: 'confirmed', selfCritique: 'ok' }, 36),
        ]);

        const result = await runAgentScan(ctx, big, {});

        const rejected = rejections(result);
        expect(rejected.length).toBeGreaterThanOrEqual(1);
        expect(rejected[0].observation).toContain('read lines 2000–2002 before reporting this finding');
        expect(result.terminationReason).toBe('agent_finish');
        expect(result.summary).toBe('confirmed');
        expect(result.findings.map(f => f.line)).toEqual([2000]);
    });

    it('unread-finding rejections count toward the finish-loop escape', async () => {
        setupExecutors(3000);
        const big = { filePath: 'big.ts', language: 'typescript', fileContent: linesContent(3000) };
        const early = () => step({ type: 'finish', findings: [finding(2000)], summary: 'early', selfCritique: 'ok' }, 30);
        mockPostJson([startResp(evidenceHarness), early(), early(), early(), early(), early()]);

        const result = await runAgentScan(ctx, big, {});

        expect(result.terminationReason).toBe('forced_incomplete');
        expect(result.transcript.some(t => String(t.observation).startsWith('[FINISH GATE LOOP DETECTED]'))).toBe(true);
        expect(rejections(result).length).toBeLessThanOrEqual(4);
    });

    describe('finish label after floor rejections', () => {
        const big = { filePath: 'big.ts', language: 'typescript', fileContent: linesContent(3000, { 2500: 'const token = authenticate(req.headers.authorization);' }) };
        const finish = (summary: string, remaining: number, extra: Record<string, unknown> = {}) =>
            step({ type: 'finish', findings: [], summary, selfCritique: 'ok' }, remaining, extra);
        const readAll = (remaining: number) => step({ type: 'read_file', path: 'big.ts', startLine: 1, endLine: 3000, rationale: 'read what the gate asked for' }, remaining);
        const loopDetected = (result: any) => result.transcript.some((t: any) => String(t.observation).startsWith('[FINISH GATE LOOP DETECTED]'));

        it('two floor rejections, then the agent reads the ranges: the third finish ends as agent_finish', async () => {
            setupExecutors(3000);
            mockPostJson([startResp(evidenceHarness), finish('early-1', 39), finish('early-2', 38), readAll(37), finish('done', 36)]);

            const result = await runAgentScan(ctx, big, {});

            const rejected = rejections(result);
            expect(rejected).toHaveLength(2);
            for (const r of rejected) expect(r.observation).toContain('of lines 1–3000 have been read');
            expect(result.terminationReason).toBe('agent_finish');
            expect(result.summary).toBe('done');
            expect(loopDetected(result)).toBe(false);
        });

        it('a passing finish on the escape count is not labelled forced', async () => {
            setupExecutors(3000);
            mockPostJson([startResp(evidenceHarness), finish('early-1', 39), finish('early-2', 38), finish('early-3', 37), readAll(36), finish('done', 35)]);

            const result = await runAgentScan(ctx, big, {});

            expect(rejections(result)).toHaveLength(3);
            expect(result.terminationReason).toBe('agent_finish');
            expect(loopDetected(result)).toBe(false);
        });

        it('a third finish that still fails the gate in the landing window is forced_incomplete', async () => {
            setupExecutors(3000);
            mockPostJson([startResp(evidenceHarness), finish('early-1', 39), finish('early-2', 38), finish('still-early', 37, { landing: true })]);

            const result = await runAgentScan(ctx, big, {});

            expect(rejections(result)).toHaveLength(2);
            expect(result.terminationReason).toBe('forced_incomplete');
            expect(result.coverageGaps.some(g => g.title.startsWith('Unread high-priority range: lines'))).toBe(true);
        });

        it('a finish that still fails when the escape threshold is reached is forced_incomplete', async () => {
            setupExecutors(3000);
            mockPostJson([startResp(evidenceHarness), finish('early-1', 39), finish('early-2', 38), finish('early-3', 37), finish('early-4', 36)]);

            const result = await runAgentScan(ctx, big, {});

            expect(rejections(result)).toHaveLength(3);
            expect(result.terminationReason).toBe('forced_incomplete');
            expect(loopDetected(result)).toBe(true);
        });
    });

    it('floor blocks a one-read finish on a large file with unread auth code', async () => {
        setupExecutors(3000);
        const big = { filePath: 'big.ts', language: 'typescript', fileContent: linesContent(3000, { 2500: 'const token = authenticate(req.headers.authorization);' }) };
        mockPostJson([
            startResp(evidenceHarness),
            step({ type: 'read_file', path: 'big.ts', startLine: 1001, endLine: 1100, rationale: 'r' }, 39),
            step({ type: 'finish', findings: [], summary: 'too early', selfCritique: 'ok' }, 38),
            step(null, 37, { costCapped: true, capReason: 'max_credits' }),
            step(null, 36, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, big, {});

        const rejected = rejections(result);
        expect(rejected).toHaveLength(1);
        expect(rejected[0].observation).toContain('of lines 1–3000 have been read');
        expect(rejected[0].observation).not.toContain('investigation steps');
    });

    it('checklist mode is unchanged: same finish is rejected by the checklist, no suggested checks', async () => {
        setupExecutors(100);
        const mockFn = mockPostJson([
            startResp(),
            step({ type: 'finish', findings: [], summary: 'first', selfCritique: 'ok', leads: [lead('L1', 'x', 1)] }, 39),
            step(null, 38, { costCapped: true, capReason: 'max_credits' }),
            step(null, 37, { costCapped: true, capReason: 'max_credits' }),
        ]);

        const result = await runAgentScan(ctx, small, {});

        const rejected = rejections(result);
        expect(rejected[0].observation).toContain('You must complete the remaining investigation steps before calling finish.');
        expect(rejected[0].observation).not.toContain('Open lead');
        expect(rejected[0].action.leads).toBeUndefined();
        for (const b of stepBodies(mockFn)) expect(b.suggestedChecks).toBeUndefined();
    });
});

describe('buildPriorPartsContext — unresolved leads', () => {
    it('lists earlier parts\u2019 unresolved leads', () => {
        const segment = { groupId: 'g', index: 1, total: 2, startLine: 1, endLine: 100 } as any;
        const context = buildPriorPartsContext([{
            segment,
            result: {
                status: 'completed',
                agentFindings: [],
                investigationNotes: [],
                coverageGaps: [
                    { title: 'Lead not resolved: admin role check missing', line: 40, detail: '', requiredEvidence: [], suggestedNextAction: '', priority: 'medium' },
                    { title: 'Unread range: lines 50-60 of f.ts', detail: '', requiredEvidence: [], suggestedNextAction: '', priority: 'high' },
                ],
            },
        }]);
        expect(context).toContain('lead: admin role check missing (line 40) [open]');
        expect(context).not.toContain('Unread range');
        expect(context).not.toContain('no findings or notes');
    });

    it('renders parts without leads as before', () => {
        const segment = { groupId: 'g', index: 1, total: 2, startLine: 1, endLine: 100 } as any;
        const context = buildPriorPartsContext([{ segment, result: { status: 'completed', agentFindings: [], investigationNotes: [], coverageGaps: [] } }]);
        expect(context).toContain('no findings or notes.');
    });
});
