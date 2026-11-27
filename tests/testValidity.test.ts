import { describe, it, expect } from 'vitest';
import { testValidity, engineValidity } from '../src/attack/testValidity';
import { PROOF_MARKER_START, PROOF_MARKER_END, HARNESS_LOG_START, HARNESS_LOG_END } from '../src/attack/proofTypes';

function harnessLog(calls: Array<Record<string, unknown>>): string {
    return `${HARNESS_LOG_START}${JSON.stringify({ calls })}${HARNESS_LOG_END}`;
}

function proofMarker(fields: Record<string, unknown>): string {
    return `${PROOF_MARKER_START}${JSON.stringify(fields)}${PROOF_MARKER_END}`;
}

describe('testValidity — proof kind', () => {
    it('valid when harness log shows matched routes and baseline pass', () => {
        const output = [
            proofMarker({ baseline: 'pass', exploit: 'fail', impact: 'not-observed', targetReached: true }),
            harnessLog([
                { method: 'GET', path: '/hello', matched: true, sent: true, status: 200, timedOut: false },
                { method: 'POST', path: '/transfer', matched: true, sent: true, status: 200, timedOut: false },
            ]),
        ].join('\n');
        expect(testValidity(output, { kind: 'proof' })).toEqual({ valid: true });
    });

    it('invalid when harness log shows an unmatched route', () => {
        const output = [
            proofMarker({ baseline: 'pass', exploit: 'fail' }),
            harnessLog([
                { method: 'POST', path: '/wallet/create', matched: false, sent: false, timedOut: false },
            ]),
        ].join('\n');
        const result = testValidity(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('/wallet/create');
        expect(result.reason).toContain('did not match');
    });

    it('invalid when harness log shows a timeout', () => {
        const output = [
            proofMarker({ baseline: 'pass' }),
            harnessLog([
                { method: 'GET', path: '/slow', matched: true, sent: false, status: undefined, timedOut: true },
            ]),
        ].join('\n');
        const result = testValidity(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('timed out');
    });

    it('invalid when harness log shows sent=false (no route response)', () => {
        const output = [
            proofMarker({ baseline: 'pass' }),
            harnessLog([
                { method: 'GET', path: '/hang', matched: true, sent: false, status: undefined, timedOut: false },
            ]),
        ].join('\n');
        const result = testValidity(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('sent=false');
    });

    it('invalid when proof marker baseline is not pass', () => {
        const output = proofMarker({ baseline: 'fail', exploit: 'fail' });
        const result = testValidity(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('baseline did not pass');
    });

    it('invalid when setup=fail', () => {
        const output = proofMarker({ baseline: 'pass', setup: 'fail', setupNote: 'POST /wallet/create returned 404' });
        const result = testValidity(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('setup failed');
        expect(result.reason).toContain('POST /wallet/create returned 404');
    });

    it('missing setup field does not invalidate', () => {
        const output = proofMarker({ baseline: 'pass', exploit: 'fail' });
        expect(testValidity(output, { kind: 'proof' }).valid).toBe(true);
    });

    it('setup=pass does not invalidate', () => {
        const output = proofMarker({ baseline: 'pass', setup: 'pass', exploit: 'fail' });
        expect(testValidity(output, { kind: 'proof' }).valid).toBe(true);
    });

    it('no harness log and baseline pass → valid', () => {
        const output = proofMarker({ baseline: 'pass', exploit: 'fail' });
        expect(testValidity(output, { kind: 'proof' }).valid).toBe(true);
    });

    it('no harness log and no proof marker → valid (non-Express test)', () => {
        const output = 'PASS: some python test\nexit code 0';
        expect(testValidity(output, { kind: 'proof' }).valid).toBe(true);
    });

    it('defaults to proof kind when opts omitted', () => {
        const output = proofMarker({ baseline: 'fail', exploit: 'fail' });
        const result = testValidity(output);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('baseline');
    });
});

describe('testValidity — scenario kind', () => {
    it('valid when harness shows matched routes and controlOk is null', () => {
        const output = harnessLog([
            { method: 'GET', path: '/doc/1', matched: true, sent: true, status: 200, timedOut: false },
        ]);
        expect(testValidity(output, { kind: 'scenario', controlOk: null })).toEqual({ valid: true });
    });

    it('invalid when controlOk is false', () => {
        const output = harnessLog([
            { method: 'GET', path: '/doc/1', matched: true, sent: true, status: 200, timedOut: false },
        ]);
        const result = testValidity(output, { kind: 'scenario', controlOk: false });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('controlOk');
    });

    it('valid when controlOk is true', () => {
        const output = harnessLog([
            { method: 'GET', path: '/doc/1', matched: true, sent: true, status: 403, timedOut: false },
        ]);
        expect(testValidity(output, { kind: 'scenario', controlOk: true }).valid).toBe(true);
    });

    it('invalid when harness log shows unmatched route', () => {
        const output = harnessLog([
            { method: 'DELETE', path: '/doc/1', matched: false, sent: false, timedOut: false },
        ]);
        const result = testValidity(output, { kind: 'scenario' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('did not match');
    });

    it('does not check proof marker baseline for scenario kind', () => {
        const output = [
            proofMarker({ baseline: 'fail' }),
            harnessLog([
                { method: 'GET', path: '/doc/1', matched: true, sent: true, status: 200, timedOut: false },
            ]),
        ].join('\n');
        expect(testValidity(output, { kind: 'scenario' }).valid).toBe(true);
    });
});

describe('testValidity — engine validity', () => {
    it('emulated engine with unsupported patterns → invalid for proof kind', () => {
        const output = `${HARNESS_LOG_START}${JSON.stringify({ calls: [{ method: 'GET', path: '/admin/config', matched: true, sent: true, status: 200, timedOut: false }], engine: 'emulated', unsupported: ['wildcard path /admin/*path'] })}${HARNESS_LOG_END}`;
        const result = testValidity(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('cannot model');
        expect(result.reason).toContain('wildcard path');
    });

    it('emulated engine with unsupported patterns → invalid for scenario kind', () => {
        const output = `${HARNESS_LOG_START}${JSON.stringify({ calls: [{ method: 'GET', path: '/admin/config', matched: true, sent: true, status: 200, timedOut: false }], engine: 'emulated', unsupported: ['mounted router at /api'] })}${HARNESS_LOG_END}`;
        const result = testValidity(output, { kind: 'scenario' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('cannot model');
    });

    it('emulated engine with empty unsupported → valid', () => {
        const output = `${HARNESS_LOG_START}${JSON.stringify({ calls: [{ method: 'GET', path: '/hello', matched: true, sent: true, status: 200, timedOut: false }], engine: 'emulated', unsupported: [] })}${HARNESS_LOG_END}`;
        expect(testValidity(output, { kind: 'proof' }).valid).toBe(true);
    });

    it('real express engine → valid regardless of unsupported', () => {
        const output = `${HARNESS_LOG_START}${JSON.stringify({ calls: [{ method: 'GET', path: '/admin/config', matched: true, sent: true, status: 401, timedOut: false }], engine: 'express@5.0.1', unsupported: [] })}${HARNESS_LOG_END}`;
        expect(testValidity(output, { kind: 'proof' }).valid).toBe(true);
    });

    it('no harness log → valid', () => {
        expect(engineValidity('some output without harness log').valid).toBe(true);
    });

    it('engineValidity returns invalid for emulated+unsupported', () => {
        const output = `${HARNESS_LOG_START}${JSON.stringify({ calls: [], engine: 'emulated', unsupported: ['app.param'] })}${HARNESS_LOG_END}`;
        const result = engineValidity(output);
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('app.param');
    });

    it('engineValidity returns valid for emulated with no unsupported', () => {
        const output = `${HARNESS_LOG_START}${JSON.stringify({ calls: [], engine: 'emulated', unsupported: [] })}${HARNESS_LOG_END}`;
        expect(engineValidity(output).valid).toBe(true);
    });
});
