// Unit tests for deterministic agent-finding corroboration — ported from the
// API's agentCorroboration behavior and strengthened for the MCP's full
// probe-rules port: only findings whose cited transcript step satisfies the
// action's declared expect are stamped 'confirmed'.

import { describe, it, expect } from 'vitest';
import { assembleAgentFindings, corroborateStep } from '../src/attack/agentCorroboration';
import { buildReport, SUSPECTED_FINDING_REASON } from '../src/attack/report';
import type { AgentFinding, AgentHttpRequestAction, AgentObservation, AgentTranscriptStep } from '../src/attack/protocol';

const REFUTED_NOTE = 'Probe rules refuted the cited step — needs review';

function makeStep(
    action?: Partial<AgentHttpRequestAction>,
    observation?: Partial<AgentObservation>,
): AgentTranscriptStep {
    return {
        action: {
            type: 'http_request',
            method: 'GET',
            path: '/api/users',
            rationale: 'probe',
            ...action,
        },
        observation: {
            statusCode: 200,
            headers: {},
            body: '',
            latencyMs: 10,
            ...observation,
        },
    };
}

function makeFinding(overrides?: Partial<AgentFinding>): AgentFinding {
    return {
        category: 'auth-bypass',
        severity: 'critical',
        title: 'Auth bypass on /api/users',
        description: 'Endpoint returns user data without a valid session.',
        evidenceStepIndex: 0,
        ...overrides,
    };
}

describe('assembleAgentFindings — confirmed findings', () => {
    it('confirms a cited step whose successStatus matched while the control was predicted to block', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], expectedStatus: [401, 403] } },
                { statusCode: 200, body: 'user data' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('confirmed');
        expect(finding.rule).toBe('status-mismatch');
        expect(finding.reason).toContain('Predicted blocked (401/403) but got 200');
    });

    it('confirms a cited step whose specific body signature matched (rule-0 signature)', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], successBodyPattern: 'admin|root' } },
                { statusCode: 200, body: 'Welcome to the admin panel' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('confirmed');
        expect(finding.rule).toBe('exploit-signature');
        expect(finding.reason).toContain('admin|root');
    });

    it('confirms a cited step whose header signature matched', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], successHeaders: { 'content-type': 'json' } } },
                { statusCode: 200, headers: { 'content-type': 'application/json' }, body: 'payload' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('confirmed');
        expect(finding.rule).toBe('exploit-signature');
    });

    it('confirms a cited step on the latency basis', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], successConfirmedBy: 'latency', successLatencyMs: { gte: 500 } } },
                { statusCode: 200, latencyMs: 900, body: 'delayed response' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('confirmed');
        expect(finding.rule).toBe('exploit-signature');
        expect(finding.reason).toContain('900ms');
    });

    it('confirms auth bypass when the transcript baseline returned 401 and the cited attack returned 200', () => {
        const transcript = [
            makeStep(undefined, { statusCode: 401, body: 'Unauthorized' }),
            makeStep(
                { expect: { successStatus: [200] } },
                { statusCode: 200, body: '{"users":["admin"]}' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding({ evidenceStepIndex: 1 })], transcript);
        expect(finding.confirmation).toBe('confirmed');
        expect(finding.rule).toBe('auth-bypass');
        expect(finding.reason).toContain('Baseline returned 401');
    });
});

describe('assembleAgentFindings — suspected findings', () => {
    it('never confirms a wildcard body pattern', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], successBodyPattern: '.*' } },
                { statusCode: 200, body: 'anything' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('suspected');
        expect(finding.reason).toBe(SUSPECTED_FINDING_REASON);
    });

    it('does not confirm on a bare success status with no signature, contrast, or baseline', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200] } },
                { statusCode: 200, body: 'user data' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('suspected');
        expect(finding.reason).toBe(SUSPECTED_FINDING_REASON);
    });

    it('keeps a finding suspected when the expected secure status was returned (refuted)', () => {
        const transcript = [
            makeStep(
                { expect: { expectedStatus: [401, 403] } },
                { statusCode: 401, body: 'Unauthorized' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('suspected');
        expect(finding.rule).toBe('blocked');
        expect(finding.reason).toBe(REFUTED_NOTE);
    });

    it('keeps a finding suspected when the attack was rejected with a blocking status (refuted)', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], successBodyPattern: 'admin' } },
                { statusCode: 403, body: 'Forbidden' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('suspected');
        expect(finding.rule).toBe('blocked');
        expect(finding.reason).toBe(REFUTED_NOTE);
    });

    it('marks findings with an out-of-range evidenceStepIndex as suspected with an invalid-citation reason', () => {
        const transcript = [makeStep()];
        const [tooHigh] = assembleAgentFindings([makeFinding({ evidenceStepIndex: 5 })], transcript);
        expect(tooHigh.confirmation).toBe('suspected');
        expect(tooHigh.reason).toBe('Evidence step 5 missing');
        const [negative] = assembleAgentFindings([makeFinding({ evidenceStepIndex: -1 })], transcript);
        expect(negative.confirmation).toBe('suspected');
        expect(negative.reason).toBe('Evidence step -1 missing');
    });

    it('keeps findings without an expect on the cited action suspected (current behavior)', () => {
        const transcript = [
            makeStep(undefined, { statusCode: 200, body: 'user data' }),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('suspected');
        expect(finding.reason).toBe(SUSPECTED_FINDING_REASON);
    });

    it('keeps findings suspected when the cited observation errored', () => {
        const transcript = [
            makeStep(
                { expect: { successStatus: [200], successBodyPattern: 'admin' } },
                { statusCode: 0, body: '', error: 'connect ECONNREFUSED 127.0.0.1:3000' },
            ),
        ];
        const [finding] = assembleAgentFindings([makeFinding()], transcript);
        expect(finding.confirmation).toBe('suspected');
        expect(finding.reason).toBe(SUSPECTED_FINDING_REASON);
    });
});

describe('assembleAgentFindings — mixed findings', () => {
    it('corroborates multiple findings independently', () => {
        const transcript = [
            makeStep(undefined, { statusCode: 401, body: 'Unauthorized' }),
            makeStep(
                { method: 'POST', expect: { successStatus: [200], successBodyPattern: 'admin|root' } },
                { statusCode: 200, body: 'root account exposed' },
            ),
            makeStep(undefined, { statusCode: 200, body: 'no signature declared here' }),
        ];
        const findings = assembleAgentFindings([
            makeFinding({ title: 'IDOR via modified id', evidenceStepIndex: 1 }),
            makeFinding({ title: 'Verbose error disclosure', severity: 'low', evidenceStepIndex: 2 }),
            makeFinding({ title: 'Baseline cited as evidence', evidenceStepIndex: 0 }),
        ], transcript);
        expect(findings).toHaveLength(3);
        expect(findings[0].confirmation).toBe('confirmed');
        expect(findings[0].rule).toBe('exploit-signature');
        expect(findings[1].confirmation).toBe('suspected');
        expect(findings[1].reason).toBe(SUSPECTED_FINDING_REASON);
        expect(findings[2].confirmation).toBe('suspected');
        expect(findings[2].reason).toBe(SUSPECTED_FINDING_REASON);
    });

    it('returns an empty array for no findings', () => {
        expect(assembleAgentFindings([], [])).toEqual([]);
    });
});

describe('corroborateStep', () => {
    it('evaluates a step against the deterministic probe rules with an optional baseline pair', () => {
        const result = corroborateStep(
            { method: 'GET', path: '/api/users', successStatus: [200], successBodyPattern: 'admin' },
            { statusCode: 200, headers: {}, body: 'hello admin', latencyMs: 5 },
            { method: 'GET', path: '/api/users' },
            { statusCode: 401, headers: {}, body: 'Unauthorized', latencyMs: 5 },
        );
        expect(result.verdict).toBe('confirmed-bypass');
        expect(result.rule).toBe('exploit-signature');
    });
});

describe('buildReport — confirmation pass-through', () => {
    it('defaults findings without confirmation fields to suspected with the legacy reason', () => {
        const report = buildReport('completed', [makeFinding()], [], 1, 0);
        expect(report.findings[0].confirmation).toBe('suspected');
        expect(report.findings[0].reason).toBe(SUSPECTED_FINDING_REASON);
    });

    it('passes corroborated findings through untouched', () => {
        const corroborated = assembleAgentFindings(
            [makeFinding()],
            [
                makeStep(
                    { expect: { successStatus: [200], successBodyPattern: 'admin|root' } },
                    { statusCode: 200, body: 'admin session' },
                ),
            ],
        );
        const report = buildReport('completed', corroborated, [], 1, 0);
        expect(report.findings[0].confirmation).toBe('confirmed');
        expect(report.findings[0].rule).toBe('exploit-signature');
        expect(report.findings[0].reason).toContain('success signature');
    });
});
