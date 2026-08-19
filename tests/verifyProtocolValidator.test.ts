import { describe, it, expect } from 'vitest';
import {
    validateVerifyGenerateResponse,
    validateVerifyAnalyzeResponse,
} from '../src/attack/protocolValidator';

// ── validateVerifyGenerateResponse ────────────────────────────────────────

describe('validateVerifyGenerateResponse', () => {
    it('accepts a valid canTest=true response with node runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS: test");',
            runner: 'node',
            description: 'a test',
            skipReason: null,
        });
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.value.canTest).toBe(true);
    });

    it('accepts a valid canTest=true response with python3 runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'print("PASS: test")',
            runner: 'python3',
            description: 'python test',
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid canTest=true response with tsx runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'tsx',
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid canTest=true response with bun runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'bun',
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid canTest=true response with deno runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'deno',
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid canTest=false response with skipReason', () => {
        const r = validateVerifyGenerateResponse({
            canTest: false,
            skipReason: 'needs a running database server',
            testScript: null,
            runner: null,
        });
        expect(r.ok).toBe(true);
        if (r.ok) expect(r.value.canTest).toBe(false);
    });

    it('accepts a response with setupScript', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'node',
            setupScript: 'console.log("setup done")',
        });
        expect(r.ok).toBe(true);
    });

    it('accepts scanCredits as a number', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'node',
            scanCredits: 95,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts costUsd as a number', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'node',
            costUsd: 0.015,
        });
        expect(r.ok).toBe(true);
    });

    it('rejects a non-object', () => {
        expect(validateVerifyGenerateResponse('not an object').ok).toBe(false);
        expect(validateVerifyGenerateResponse(null).ok).toBe(false);
        expect(validateVerifyGenerateResponse(42).ok).toBe(false);
    });

    it('rejects canTest=true with missing testScript', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            runner: 'node',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('testScript');
    });

    it('rejects canTest=true with empty testScript', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: '',
            runner: 'node',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('testScript');
    });

    it('rejects canTest=true with missing runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('runner');
    });

    it('rejects canTest=true with unsupported runner', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'ruby',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('runner');
    });

    it('rejects canTest=false with missing skipReason', () => {
        const r = validateVerifyGenerateResponse({
            canTest: false,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('skipReason');
    });

    it('rejects canTest=false with empty skipReason', () => {
        const r = validateVerifyGenerateResponse({
            canTest: false,
            skipReason: '',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('skipReason');
    });

    it('rejects canTest that is not a boolean', () => {
        const r = validateVerifyGenerateResponse({
            canTest: 'yes',
            testScript: 'console.log("PASS")',
            runner: 'node',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('canTest');
    });

    it('rejects oversized testScript', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'x'.repeat(65 * 1024),
            runner: 'node',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('too large');
    });

    it('rejects oversized setupScript', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'node',
            setupScript: 'x'.repeat(33 * 1024),
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('setupScript');
    });

    it('rejects scanCredits that is not a number', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'node',
            scanCredits: '95',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('scanCredits');
    });

    it('rejects costUsd that is not a number', () => {
        const r = validateVerifyGenerateResponse({
            canTest: true,
            testScript: 'console.log("PASS")',
            runner: 'node',
            costUsd: '0.015',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('costUsd');
    });
});

// ── validateVerifyAnalyzeResponse ──────────────────────────────────────────

describe('validateVerifyAnalyzeResponse', () => {
    it('accepts a valid PROVEN response', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'exploit succeeded',
            shouldRetry: false,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid UNPROVEN response', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'UNPROVEN',
            reason: 'guard blocked the attack',
            shouldRetry: false,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid INCONCLUSIVE response with shouldRetry=true', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'INCONCLUSIVE',
            reason: 'test crashed — import error',
            shouldRetry: true,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts a valid INCONCLUSIVE response with shouldRetry=false', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'INCONCLUSIVE',
            reason: 'could not determine after 8 rounds',
            shouldRetry: false,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts scanCredits as a number', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'ok',
            shouldRetry: false,
            scanCredits: 95,
        });
        expect(r.ok).toBe(true);
    });

    it('accepts costUsd as a number', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'ok',
            shouldRetry: false,
            costUsd: 0.015,
        });
        expect(r.ok).toBe(true);
    });

    it('rejects a non-object', () => {
        expect(validateVerifyAnalyzeResponse('not an object').ok).toBe(false);
        expect(validateVerifyAnalyzeResponse(null).ok).toBe(false);
        expect(validateVerifyAnalyzeResponse(42).ok).toBe(false);
    });

    it('rejects an unknown verdict', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'MAYBE',
            reason: 'unsure',
            shouldRetry: false,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('verdict');
    });

    it('rejects a missing verdict', () => {
        const r = validateVerifyAnalyzeResponse({
            reason: 'ok',
            shouldRetry: false,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('verdict');
    });

    it('rejects a missing reason', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            shouldRetry: false,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('reason');
    });

    it('rejects an empty reason', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: '',
            shouldRetry: false,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('reason');
    });

    it('rejects a missing shouldRetry', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'ok',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('shouldRetry');
    });

    it('rejects shouldRetry that is not a boolean', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'ok',
            shouldRetry: 'no',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('shouldRetry');
    });

    it('rejects PROVEN with shouldRetry=true (definitive verdict cannot retry)', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'exploit worked',
            shouldRetry: true,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('PROVEN');
    });

    it('rejects UNPROVEN with shouldRetry=true (definitive verdict cannot retry)', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'UNPROVEN',
            reason: 'guard held',
            shouldRetry: true,
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('UNPROVEN');
    });

    it('rejects scanCredits that is not a number', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'ok',
            shouldRetry: false,
            scanCredits: '95',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('scanCredits');
    });

    it('rejects costUsd that is not a number', () => {
        const r = validateVerifyAnalyzeResponse({
            verdict: 'PROVEN',
            reason: 'ok',
            shouldRetry: false,
            costUsd: '0.015',
        });
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.error).toContain('costUsd');
    });
});
