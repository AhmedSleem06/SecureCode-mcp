// Unit tests for the runtime probe verdict rules — ported from
// api/tests/sandboxRules.test.ts. The MCP's applyProbeRules must yield the
// same verdicts as the API's applyRules for the same inputs (parity suite).

import { describe, it, expect } from 'vitest';
import {
    applyProbeRules,
    passesLuhn,
    type ProbeRuleRequest,
    type ProbeRuleResponse,
} from '../src/attack/probeRules';

function makeResponse(overrides?: Partial<ProbeRuleResponse>): ProbeRuleResponse {
    return { statusCode: 200, headers: {}, body: '', latencyMs: 10, ...overrides };
}

function makeRequest(overrides?: Partial<ProbeRuleRequest>): ProbeRuleRequest {
    return { method: 'GET', path: '/api/test', ...overrides };
}

describe('applyProbeRules — no attack response', () => {
    it('returns inconclusive when attack response is null', () => {
        const result = applyProbeRules(makeRequest(), null);
        expect(result.verdict).toBe('inconclusive');
        expect(result.rule).toBe('none');
        expect(result.reason).toContain('no response');
    });
});

describe('applyProbeRules — Rule 0: exploit signature', () => {
    it('confirms when success status + body pattern match', () => {
        const result = applyProbeRules(
            makeRequest({ successStatus: [200], successBodyPattern: 'admin@internal' }),
            makeResponse({ statusCode: 200, body: 'admin@internal.db泄露' }),
        );
        expect(result.verdict).toBe('confirmed-bypass');
        expect(result.rule).toBe('exploit-signature');
    });

    it('declines on match-anything wildcard pattern', () => {
        const result = applyProbeRules(
            makeRequest({ successStatus: [200], successBodyPattern: '.*' }),
            makeResponse({ statusCode: 200, body: 'anything' }),
        );
        expect(result.verdict).not.toBe('confirmed-bypass');
        expect(result.verdict).toBe('inconclusive');
    });

    it('confirms on latency basis', () => {
        const result = applyProbeRules(
            makeRequest({
                successStatus: [200],
                successConfirmedBy: 'latency',
                successLatencyMs: { gte: 3000 },
            }),
            makeResponse({ statusCode: 200, latencyMs: 5000 }),
        );
        expect(result.verdict).toBe('confirmed-bypass');
        expect(result.rule).toBe('exploit-signature');
    });

    it('is inconclusive on multi-request basis', () => {
        const result = applyProbeRules(
            makeRequest({ successStatus: [200], successConfirmedBy: 'multi-request' }),
            makeResponse({ statusCode: 200 }),
        );
        expect(result.verdict).toBe('inconclusive');
        expect(result.reason).toContain('cannot be decided');
    });
});

describe('applyProbeRules — Rule 1: status mismatch', () => {
    it('confirms when predicted blocked but got 2xx', () => {
        const result = applyProbeRules(
            makeRequest({ expectedStatus: [403] }),
            makeResponse({ statusCode: 200 }),
        );
        expect(result.verdict).toBe('confirmed-bypass');
        expect(result.rule).toBe('status-mismatch');
    });

    it('does not fire when status matches expected', () => {
        const result = applyProbeRules(
            makeRequest({ expectedStatus: [403] }),
            makeResponse({ statusCode: 403 }),
        );
        expect(result.verdict).not.toBe('confirmed-bypass');
    });
});

describe('applyProbeRules — Rule 2: auth bypass', () => {
    it('confirms when baseline 401, attack 200 with non-empty body', () => {
        const result = applyProbeRules(
            makeRequest(),
            makeResponse({ statusCode: 200, body: 'protected user data' }),
            null,
            makeResponse({ statusCode: 401 }),
        );
        expect(result.verdict).toBe('confirmed-bypass');
        expect(result.rule).toBe('auth-bypass');
    });

    it('is inconclusive when the attack body is empty (empty-body guard)', () => {
        const result = applyProbeRules(
            makeRequest(),
            makeResponse({ statusCode: 200, body: '' }),
            null,
            makeResponse({ statusCode: 401 }),
        );
        expect(result.verdict).toBe('inconclusive');
        expect(result.rule).toBe('auth-bypass');
        expect(result.reason).toContain('response body is empty');
    });

    it('does not fire when baseline is also 200', () => {
        const result = applyProbeRules(
            makeRequest(),
            makeResponse({ statusCode: 200, body: 'ok' }),
            null,
            makeResponse({ statusCode: 200, body: 'ok' }),
        );
        expect(result.rule).not.toBe('auth-bypass');
    });
});

describe('applyProbeRules — Rule 3: secret leak', () => {
    it('confirms when attack has secret not in baseline', () => {
        const result = applyProbeRules(
            makeRequest(),
            makeResponse({ body: '{"key":"sk-1234567890abcdefghijklmnop"}' }),
            null,
            makeResponse({ body: '{"user":"test"}' }),
        );
        expect(result.verdict).toBe('confirmed-bypass');
        expect(result.rule).toBe('secret-leak');
    });

    it('is inconclusive when no baseline', () => {
        const result = applyProbeRules(
            makeRequest(),
            makeResponse({ body: '{"key":"sk-1234567890abcdefghijklmnop"}' }),
        );
        expect(result.verdict).toBe('inconclusive');
        expect(result.rule).toBe('secret-leak');
    });
});

describe('applyProbeRules — Rule 6: blocked', () => {
    it('refutes when status matches expected', () => {
        const result = applyProbeRules(
            makeRequest({ expectedStatus: [403] }),
            makeResponse({ statusCode: 403 }),
        );
        expect(result.verdict).toBe('refuted');
        expect(result.rule).toBe('blocked');
    });

    it('refutes on rejection when success signature present but unmatched', () => {
        const result = applyProbeRules(
            makeRequest({ successStatus: [200] }),
            makeResponse({ statusCode: 400 }),
        );
        expect(result.verdict).toBe('refuted');
        expect(result.rule).toBe('blocked');
    });
});

describe('applyProbeRules — auth-precheck', () => {
    it('downgrades to inconclusive when auth env missing', () => {
        const result = applyProbeRules(
            makeRequest({ authRequired: true, authEnvVars: ['JWT_SECRET'] }),
            makeResponse({ statusCode: 200 }),
            null,
            null,
            {},
        );
        expect(result.verdict).toBe('inconclusive');
        expect(result.rule).toBe('auth-precheck');
    });

    it('passes when auth env is set', () => {
        const result = applyProbeRules(
            makeRequest({ authRequired: true, authEnvVars: ['JWT_SECRET'] }),
            makeResponse({ statusCode: 200 }),
            null,
            null,
            { JWT_SECRET: 'secret123' },
        );
        expect(result.rule).not.toBe('auth-precheck');
    });
});

describe('applyProbeRules — fallback', () => {
    it('returns inconclusive when no rule fires', () => {
        const result = applyProbeRules(
            makeRequest(),
            makeResponse({ statusCode: 200, body: '{"ok":true}' }),
        );
        expect(result.verdict).toBe('inconclusive');
        expect(result.reason).toContain('No deterministic rule fired');
    });
});

describe('passesLuhn', () => {
    it('accepts a Luhn-valid card number and rejects an invalid one', () => {
        expect(passesLuhn('4111111111111111')).toBe(true);
        expect(passesLuhn('4111111111111112')).toBe(false);
    });
});
