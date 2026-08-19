import { describe, it, expect } from 'vitest';
import {
    validateAction,
    validateStartResponse,
    validateStepResponse,
    validateToolResponse,
} from '../src/attack/protocolValidator';

describe('protocolValidator', () => {
    // ── validateAction ───────────────────────────────────────────────────

    it('accepts a valid read_file action', () => {
        const r = validateAction({ type: 'read_file', path: 'src/foo.ts', rationale: 'r' });
        expect(r.ok).toBe(true);
    });

    it('rejects read_file with missing path', () => {
        const r = validateAction({ type: 'read_file', rationale: 'r' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('path');
    });

    it('rejects an unknown action type', () => {
        const r = validateAction({ type: 'frobnicate', path: 'x' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('unknown');
    });

    it('rejects a non-object action', () => {
        const r = validateAction('not an object');
        expect(r.ok).toBe(false);
    });

    it('accepts a valid check_guard with a known attackType', () => {
        const r = validateAction({
            type: 'check_guard', filePath: 'a.ts', guardName: 'requireAuth',
            attackType: 'sql_injection', rationale: 'r',
        });
        expect(r.ok).toBe(true);
    });

    it('rejects check_guard with an unknown attackType', () => {
        const r = validateAction({
            type: 'check_guard', filePath: 'a.ts', guardName: 'requireAuth',
            attackType: 'ldap_injection', rationale: 'r',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('attackType');
    });

    it('accepts a valid finish with one finding', () => {
        const r = validateAction({
            type: 'finish',
            findings: [{ line: 5, type: 'xss', severity: 'high', confidence: 80, evidence: 'x', why: 'y' }],
            summary: 'done',
            selfCritique: 'reviewed',
        });
        expect(r.ok).toBe(true);
    });

    it('rejects finish with a finding whose line is 0', () => {
        const r = validateAction({
            type: 'finish',
            findings: [{ line: 0, type: 'xss', severity: 'high', confidence: 80, evidence: 'x', why: 'y' }],
            summary: 'done',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('positive integer');
    });

    it('rejects finish with confidence out of range', () => {
        const r = validateAction({
            type: 'finish',
            findings: [{ line: 5, type: 'xss', severity: 'high', confidence: 150, evidence: 'x', why: 'y' }],
            summary: 'done',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('confidence');
    });

    it('rejects finish with an invalid severity', () => {
        const r = validateAction({
            type: 'finish',
            findings: [{ line: 5, type: 'xss', severity: 'critical-ish', confidence: 80, evidence: 'x', why: 'y' }],
            summary: 'done',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('severity');
    });

    it('accepts a valid system_event (critique)', () => {
        const r = validateAction({
            type: 'system_event', eventType: 'critique', message: 'fix finding 0',
        });
        expect(r.ok).toBe(true);
    });

    it('rejects system_event with an unknown eventType', () => {
        const r = validateAction({
            type: 'system_event', eventType: 'unexpected', message: 'x',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('eventType');
    });

    // ── validateStartResponse ────────────────────────────────────────────

    it('accepts a valid start response', () => {
        const r = validateStartResponse({
            runId: 'run-1', refundId: 'r-1', scanCredits: 95,
            budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 },
        });
        expect(r.ok).toBe(true);
    });

    it('rejects start response with a missing runId', () => {
        const r = validateStartResponse({
            refundId: 'r-1',
            budget: { stepsRemaining: 20, costSpentUsd: 0, costCapUsd: 0.40 },
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('runId');
    });

    it('rejects start response with a non-numeric budget field', () => {
        const r = validateStartResponse({
            runId: 'run-1', refundId: 'r-1',
            budget: { stepsRemaining: '20', costSpentUsd: 0, costCapUsd: 0.40 },
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('stepsRemaining');
    });

    // ── validateStepResponse ─────────────────────────────────────────────

    it('accepts a step response with next=null', () => {
        const r = validateStepResponse({
            next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: true, stepsRemaining: 19,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a step response with a valid action and a valid systemEvent', () => {
        const r = validateStepResponse({
            next: { type: 'read_file', path: 'a.ts', rationale: 'r' },
            costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18,
            systemEvent: { type: 'system_event', eventType: 'critique', message: 'fix' },
        });
        expect(r.ok).toBe(true);
    });

    it('rejects a step response whose next action is malformed', () => {
        const r = validateStepResponse({
            next: { type: 'read_file', rationale: 'r' }, // missing path
            costUsd: 0.01, tokens: 100, degraded: false, costCapped: false, stepsRemaining: 18,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('next');
    });

    it('rejects a step response whose systemEvent has the wrong type', () => {
        const r = validateStepResponse({
            next: null, costUsd: 0, tokens: 0, degraded: false, costCapped: false, stepsRemaining: 18,
            systemEvent: { type: 'read_file', path: 'x', rationale: 'r' },
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('system_event');
    });

    it('rejects a step response with non-boolean degraded', () => {
        const r = validateStepResponse({
            next: null, costUsd: 0, tokens: 0, degraded: 'no', costCapped: false, stepsRemaining: 18,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('degraded');
    });

    // ── validateToolResponse ──────────────────────────────────────────────

    it('accepts a tool response with a string observation', () => {
        const r = validateToolResponse({ observation: 'no findings' });
        expect(r.ok).toBe(true);
    });

    it('rejects a tool response with a missing observation', () => {
        const r = validateToolResponse({});
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('observation');
    });

    it('truncates an oversized observation rather than rejecting it', () => {
        const huge = 'x'.repeat(100_000);
        const r = validateToolResponse({ observation: huge });
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.value.observation.length).toBeLessThan(huge.length);
        if (r.ok) expect(r.value.observation).toContain('truncated');
    });

    // ── run_tests validation ──────────────────────────────────────────────

    it('accepts run_tests existing mode', () => {
        const r = validateAction({
            type: 'run_tests', mode: 'existing', testFiles: ['tests/auth.test.ts'], rationale: 'r',
        });
        expect(r.ok).toBe(true);
    });

    it('accepts run_tests generated mode', () => {
        const r = validateAction({
            type: 'run_tests', mode: 'generated', script: "console.log('PASS')", runner: 'node', rationale: 'r',
        });
        expect(r.ok).toBe(true);
    });

    it('rejects run_tests with invalid mode', () => {
        const r = validateAction({ type: 'run_tests', mode: 'invalid', rationale: 'r' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('mode');
    });

    it('rejects run_tests generated mode without script', () => {
        const r = validateAction({ type: 'run_tests', mode: 'generated', runner: 'node', rationale: 'r' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('script');
    });

    it('rejects run_tests generated mode without runner', () => {
        const r = validateAction({ type: 'run_tests', mode: 'generated', script: "console.log('x')", rationale: 'r' });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('runner');
    });
});
