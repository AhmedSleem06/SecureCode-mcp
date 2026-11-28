import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

vi.mock('../src/attack/verifyLoop', () => ({
    runVerifyLoop: vi.fn(),
}));

vi.mock('../src/attack/agentScanLoop', () => ({
    runAgentScan: vi.fn(),
}));

vi.mock('../src/attack/fixVerifyLoop', () => ({
    runFixVerifyLoop: vi.fn(),
}));

vi.mock('../src/api/client', async (importOriginal) => {
    const actual: any = await importOriginal();
    return {
        ...actual,
        ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
    };
});

vi.mock('../src/project-map/mapContext', () => ({
    getEndpointContextForFile: vi.fn().mockResolvedValue([]),
    getRelatedFilesForFile: vi.fn().mockResolvedValue([]),
    getMap: vi.fn().mockResolvedValue(null),
}));

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { ApiClient } from '../src/api/client';
import { toolAgentScan, countReviews, withKnownReviewStatus } from '../src/tools/agentScan';
import { writeCachedScan } from '../src/project-map/scanCache';

const CODE = 'export function handler(req: any, res: any) {\n    return db.query("SELECT " + req.body.id);\n}\n';

function finding(overrides: Record<string, unknown> = {}) {
    return { type: 'sql_injection', line: 2, lineEnd: 2, evidence: 'db.query("SELECT " + req.body.id)', why: 'user input concatenated into SQL', severity: 'high', confidence: 90, ...overrides };
}

function agentResult(overrides: Record<string, unknown> = {}) {
    return {
        runId: 'run-1', status: 'completed', terminationReason: 'agent_finish', findings: [], transcript: [], investigationNotes: [], coverageGaps: [],
        stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.1, summary: 'done', creditsUsed: 5, baseCredits: 5, maxCredits: 15, creditExtensionsGranted: 0,
        ...overrides,
    } as any;
}

let workspaceRoot: string;

async function runScan(args: Record<string, unknown> = {}) {
    const ctx: any = { workspaceRoot, apiUrl: 'https://api.usesecurecode.tech', apiToken: 'test-token' };
    return toolAgentScan(ctx, { filePath: 'app.ts', language: 'typescript', _skipFix: true, _noCache: false, ...args }) as Promise<any>;
}

describe('review status survives the cache', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-review-cache-'));
        fs.writeFileSync(path.join(workspaceRoot, 'app.ts'), CODE);
        vi.clearAllMocks();
        const postJson = vi.fn(async (p: string) => (p === '/agent/scan/close' ? { settlement: { creditsRefunded: 0, creditsUsed: 5 } } : {}));
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
    });

    it('a normal finish whose review and proof were skipped shows both skips, fresh and cached', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({
            findings: [finding({ aiReview: { status: 'not-reviewed', reason: 'not reviewed: the scan reached its last step' } })],
        }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'INCONCLUSIVE', reason: 'no sandbox', roundsUsed: 0, subVerdict: 'sandbox-unavailable' } as any);

        const fresh = await runScan();
        const cached = await runScan();

        expect(cached.cached).toBe(true);
        for (const r of [fresh, cached]) {
            expect(r.terminationReason).toBe('agent_finish');
            expect(r.agentFindings).toHaveLength(1);
            expect(r.agentFindings[0].aiReview.status).toBe('not-reviewed');
            expect(r.agentFindings[0].proven).toBe('INCONCLUSIVE');
            expect(r.reviewCounts).toEqual({ reviewed: 0, notReviewed: 1, unknown: 0 });
        }
    });

    it('a reviewed and proven finding stays reviewed and proven when served from the cache', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({ findings: [finding({ aiReview: { status: 'reviewed' } })] }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'PROVEN', reason: 'exploit reproduced', roundsUsed: 1 } as any);

        const fresh = await runScan();
        const cached = await runScan();

        for (const r of [fresh, cached]) {
            expect(r.agentFindings[0].aiReview).toEqual({ status: 'reviewed' });
            expect(r.agentFindings[0].proven).toBe('PROVEN');
            expect(r.reviewCounts).toEqual({ reviewed: 1, notReviewed: 0, unknown: 0 });
        }
    });

    it('an incomplete run keeps both facts and is still not cached', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({
            terminationReason: 'forced_incomplete',
            findings: [finding({ aiReview: { status: 'not-reviewed', reason: 'not reviewed: the scan budget was used up' } })],
        }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'PROVEN', reason: 'exploit reproduced', roundsUsed: 1 } as any);

        const first = await runScan();
        const second = await runScan();

        expect(first.terminationReason).toBe('forced_incomplete');
        expect(first.agentFindings[0].proven).toBe('PROVEN');
        expect(first.agentFindings[0].aiReview.status).toBe('not-reviewed');
        expect(second.cached).not.toBe(true);
        expect(vi.mocked(runAgentScan)).toHaveBeenCalledTimes(2);
    });

    it('a proof answers the open questions: a PROVEN finding drops them, fresh and cached', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({
            findings: [finding({ aiReview: { status: 'reviewed' }, openQuestions: ['No guard or policy check was run for this location.'] })],
        }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'PROVEN', reason: 'exploit reproduced', roundsUsed: 1 } as any);

        const fresh = await runScan();
        const cached = await runScan();

        expect(cached.cached).toBe(true);
        for (const r of [fresh, cached]) {
            expect(r.agentFindings[0].proven).toBe('PROVEN');
            expect(r.agentFindings[0]).not.toHaveProperty('openQuestions');
        }
    });

    it('an unproven finding keeps its open questions, fresh and cached', async () => {
        vi.mocked(runAgentScan).mockResolvedValue(agentResult({
            findings: [finding({ aiReview: { status: 'reviewed' }, openQuestions: ['No traced flow or runtime test showed attacker input reaching this line.'] })],
        }));
        vi.mocked(runVerifyLoop).mockResolvedValue({ verdict: 'INCONCLUSIVE', reason: 'test could not reach the handler', roundsUsed: 2 } as any);

        const fresh = await runScan();
        const cached = await runScan();

        for (const r of [fresh, cached]) {
            expect(r.agentFindings[0].proven).toBe('INCONCLUSIVE');
            expect(r.agentFindings[0].openQuestions).toEqual(['No traced flow or runtime test showed attacker input reaching this line.']);
        }
    });

    it('an older cache entry without review status reads as unknown, never as reviewed', async () => {
        writeCachedScan(workspaceRoot, 'app.ts', CODE, {
            findings: [{ ...finding(), proven: 'PROVEN' }] as any,
            investigationNotes: [], coverageGaps: [], status: 'completed', terminationReason: 'agent_finish', summary: 'old result',
            stepsUsed: 5, stepsGranted: 40, extensionsGranted: 0, costSpentUsd: 0.1,
        } as any);

        const cached = await runScan();

        expect(cached.cached).toBe(true);
        expect(vi.mocked(runAgentScan)).not.toHaveBeenCalled();
        expect(cached.agentFindings[0].aiReview.status).toBe('unknown');
        expect(cached.agentFindings[0].proven).toBe('PROVEN');
        expect(cached.reviewCounts).toEqual({ reviewed: 0, notReviewed: 0, unknown: 1 });
    });
});

describe('review helpers', () => {
    it('fills only missing review status', () => {
        const out = withKnownReviewStatus([{ aiReview: { status: 'reviewed' } }, {}] as any[]);
        expect(out[0].aiReview).toEqual({ status: 'reviewed' });
        expect((out[1] as any).aiReview.status).toBe('unknown');
    });

    it('counts each status', () => {
        expect(countReviews([{ aiReview: { status: 'reviewed' } }, { aiReview: { status: 'not-reviewed' } }, {}])).toEqual({ reviewed: 1, notReviewed: 1, unknown: 1 });
    });
});
