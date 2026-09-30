// Integration tests for the agent-scan fix REGENERATION loop:
// a fix that fails verification is regenerated ONCE with the failure
// feedback appended to the prompt, under the same approval.

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

vi.mock('../src/api/client', () => ({
    ApiClient: vi.fn().mockImplementation(() => ({ postJson: vi.fn() })),
}));

vi.mock('../src/approval/broker', () => ({
    ApprovalBroker: vi.fn().mockImplementation(() => ({
        start: vi.fn().mockResolvedValue(0),
        stop: vi.fn().mockResolvedValue(undefined),
        requestApproval: vi.fn().mockResolvedValue({ approved: true, reason: 'ok', requestId: 'fix-approval', duration: 0 }),
    })),
}));

vi.mock('../src/project-map/mapContext', () => ({
    getEndpointContextForFile: vi.fn().mockResolvedValue([]),
    getRelatedFilesForFile: vi.fn().mockResolvedValue([]),
    getMap: vi.fn().mockResolvedValue(null),
}));

vi.mock('../src/project-map/fixTester', () => ({
    testFix: vi.fn().mockResolvedValue({
        passes: true,
        syntaxValid: true,
        fixEffective: true,
        newVulnerabilities: [],
        regressions: [],
        tests: [],
    }),
}));

import { runVerifyLoop } from '../src/attack/verifyLoop';
import { runAgentScan } from '../src/attack/agentScanLoop';
import { runFixVerifyLoop } from '../src/attack/fixVerifyLoop';
import { ApiClient } from '../src/api/client';
import { toolAgentScan } from '../src/tools/agentScan';

const CODE = [
    'import express from "express";',
    'const app = express();',
    'app.post("/users", (req, res) => {',
    '  const q = "SELECT * FROM users WHERE id=" + req.body.id;',
    '  db.query(q);',
    '  res.send("ok");',
    '});',
].join('\n');

function makeFinding() {
    return {
        type: 'sql_injection',
        line: 4,
        lineEnd: 5,
        evidence: 'const q = "SELECT * FROM users WHERE id=" + req.body.id;',
        why: 'user input concatenated into SQL',
        severity: 'high',
        confidence: 95,
    };
}

function setupVerify(proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE') {
    vi.mocked(runVerifyLoop).mockResolvedValue({
        verdict: proven,
        reason: 'exploit reproduced',
        roundsUsed: 2,
        testScript: '',
        testOutput: '',
        subVerdict: 'analyzed',
    } as any);
}

let workspaceRoot: string;

describe('toolAgentScan — fix regeneration loop', () => {
    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-fixregen-'));
        fs.writeFileSync(path.join(workspaceRoot, 'routes.ts'), CODE);
        vi.mocked(runVerifyLoop).mockReset();
        vi.mocked(runAgentScan).mockReset();
        vi.mocked(ApiClient).mockReset();
        vi.clearAllMocks();
        vi.mocked(runAgentScan).mockResolvedValue({
            status: 'completed',
            findings: [makeFinding()],
            transcript: [],
            investigationNotes: [],
            coverageGaps: [],
            stepsUsed: 5,
            stepsGranted: 40,
            extensionsGranted: 0,
            costSpentUsd: 0.05,
            summary: 'done',
        } as any);
        setupVerify('PROVEN');
    });

    afterEach(() => {
        fs.rmSync(workspaceRoot, { recursive: true, force: true });
        vi.unstubAllEnvs();
    });

    function mockFixResponses(responses: any[]) {
        const postJson = vi.fn();
        for (const r of responses) postJson.mockResolvedValueOnce(r);
        vi.mocked(ApiClient).mockImplementation(() => ({ postJson }) as any);
        return postJson;
    }

    async function runScan() {
        const ctx: any = {
            workspaceRoot,
            apiUrl: 'https://api.usesecurecode.tech',
            apiToken: 'test-token',
        };
        return toolAgentScan(ctx, { filePath: 'routes.ts', language: 'typescript' });
    }

    it('regenerates once with failure feedback when the first fix fails verification', async () => {
        const postJson = mockFixResponses([
            { fixed_code: 'fix-attempt-1', fix_summary: 's1', confidence: 80, replace_range: { start_line: 4, end_line: 5 } },
            { fixed_code: 'fix-attempt-2', fix_summary: 's2', confidence: 85, replace_range: { start_line: 4, end_line: 5 } },
        ]);
        // Import runFixVerifyLoop mock dynamically — the tool imports the real module.
        const fixVerify = vi.mocked(runFixVerifyLoop);
        fixVerify.mockReset();
        fixVerify
            .mockResolvedValueOnce({
                status: 'still-vulnerable',
                reason: 'attack payload still returned all rows',
                originalVerdict: 'PROVEN',
                roundsUsed: 2,
                fixedCodeHash: 'h1',
            } as any)
            .mockResolvedValueOnce({
                status: 'closed',
                reason: 'exploit no longer reproduces',
                originalVerdict: 'PROVEN',
                fixedVerdict: 'UNPROVEN',
                roundsUsed: 2,
                fixedCodeHash: 'h2',
            } as any);

        const result: any = await runScan();

        // Two /fix generations happened
        const fixCalls = postJson.mock.calls.filter(c => c[0] === '/fix');
        expect(fixCalls).toHaveLength(2);
        // The regeneration carries the failure feedback
        expect(fixCalls[1][1].vulnerability.verification_evidence).toContain('PREVIOUS FIX ATTEMPT FAILED');
        expect(fixCalls[1][1].vulnerability.verification_evidence).toContain('still reproduces');
        // First call has no failure feedback
        expect(fixCalls[0][1].vulnerability.verification_evidence).not.toContain('PREVIOUS FIX ATTEMPT FAILED');

        const finding = result.agentFindings[0];
        expect(finding.fixStatus).toBe('fix-verified-closed');
        expect(finding.fixAttempts).toBe(2);
        expect(finding.fix.fixedCode).toBe('fix-attempt-2');
        expect(finding.fixVerification.status).toBe('closed');
    });

    it('does not regenerate when the first fix verifies clean', async () => {
        const postJson = mockFixResponses([
            { fixed_code: 'fix-attempt-1', fix_summary: 's1', confidence: 80, replace_range: { start_line: 4, end_line: 5 } },
        ]);
        const fixVerify = vi.mocked(runFixVerifyLoop);
        fixVerify.mockReset();
        fixVerify.mockResolvedValueOnce({
            status: 'closed',
            reason: 'exploit no longer reproduces',
            originalVerdict: 'PROVEN',
            fixedVerdict: 'UNPROVEN',
            roundsUsed: 1,
            fixedCodeHash: 'h1',
        } as any);

        const result: any = await runScan();

        const fixCalls = postJson.mock.calls.filter(c => c[0] === '/fix');
        expect(fixCalls).toHaveLength(1);
        const finding = result.agentFindings[0];
        expect(finding.fixStatus).toBe('fix-verified-closed');
        expect(finding.fixAttempts).toBe(1);
    });

    it('stops after the regeneration attempt even if it still fails', async () => {
        const postJson = mockFixResponses([
            { fixed_code: 'fix-attempt-1', fix_summary: 's1', confidence: 80, replace_range: { start_line: 4, end_line: 5 } },
            { fixed_code: 'fix-attempt-2', fix_summary: 's2', confidence: 80, replace_range: { start_line: 4, end_line: 5 } },
        ]);
        const fixVerify = vi.mocked(runFixVerifyLoop);
        fixVerify.mockReset();
        fixVerify.mockResolvedValue({
            status: 'still-vulnerable',
            reason: 'still broken',
            originalVerdict: 'PROVEN',
            roundsUsed: 2,
            fixedCodeHash: 'h',
        } as any);

        const result: any = await runScan();

        const fixCalls = postJson.mock.calls.filter(c => c[0] === '/fix');
        expect(fixCalls).toHaveLength(2);
        const finding = result.agentFindings[0];
        expect(finding.fixStatus).toBe('fix-still-vulnerable');
        expect(finding.fixAttempts).toBe(2);
    });

    it('sends the scanner analysis (why/severity/verification evidence) to the fixer', async () => {
        const postJson = mockFixResponses([
            { fixed_code: 'fix-attempt-1', fix_summary: 's1', confidence: 80, replace_range: { start_line: 4, end_line: 5 } },
        ]);
        const fixVerify = vi.mocked(runFixVerifyLoop);
        fixVerify.mockReset();
        fixVerify.mockResolvedValue({
            status: 'closed',
            reason: 'ok',
            originalVerdict: 'PROVEN',
            fixedVerdict: 'UNPROVEN',
            roundsUsed: 1,
            fixedCodeHash: 'h',
        } as any);

        await runScan();

        const fixCall = postJson.mock.calls.find(c => c[0] === '/fix');
        expect(fixCall[1].vulnerability.why).toBe('user input concatenated into SQL');
        expect(fixCall[1].vulnerability.severity).toBe('high');
        expect(fixCall[1].vulnerability.verification_evidence).toContain('Original verification');
    });
});
