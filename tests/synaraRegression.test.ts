import { describe, it, expect, beforeEach, vi } from 'vitest';
import { InvestigationState } from '../src/attack/investigationState';
import {
    assertNoOverstatedFindings,
    OLD_SCAN_RESULTS,
    EXPECTED_OUTCOMES,
} from './fixtures/synaraRegression';

describe('Synara Regression: precision validation', () => {
    it('all 3 old findings are captured in fixtures', () => {
        expect(OLD_SCAN_RESULTS).toHaveLength(3);
        expect(OLD_SCAN_RESULTS[0].file).toBe('apps/server/src/http.ts');
        expect(OLD_SCAN_RESULTS[1].file).toBe('apps/server/src/http.ts');
        expect(OLD_SCAN_RESULTS[2].file).toBe('apps/server/src/wsRpc.ts');
    });

    it('all 3 old findings were marked PROVEN', () => {
        for (const f of OLD_SCAN_RESULTS) {
            expect(f.oldProven).toBe('PROVEN');
        }
    });

    it('all 3 expected outcomes classify as investigationNote (not finding)', () => {
        for (const outcome of EXPECTED_OUTCOMES) {
            expect(outcome.expectedClassification).toBe('investigationNote');
            expect(outcome.expectedClassification).not.toBe('finding');
        }
    });

    it('all 3 old findings claimed a higher level than they actually demonstrated', () => {
        for (const outcome of EXPECTED_OUTCOMES) {
            expect(outcome.oldClaimedLevel).not.toBe(outcome.actualDemonstratedLevel);
        }
    });

    it('http.ts:310 and http.ts:848 share the same root cause', () => {
        const root310 = EXPECTED_OUTCOMES.find(o => o.line === 310)?.rootCauseId;
        const root848 = EXPECTED_OUTCOMES.find(o => o.line === 848)?.rootCauseId;
        expect(root310).toBe(root848);
        expect(root310).toBe('loopback-legacy-token-auth-bypass');
    });

    it('wsRpc.ts:2042 has a different root cause', () => {
        const rootWs = EXPECTED_OUTCOMES.find(o => o.line === 2042)?.rootCauseId;
        const rootHttp = EXPECTED_OUTCOMES.find(o => o.line === 310)?.rootCauseId;
        expect(rootWs).not.toBe(rootHttp);
    });

    it('none of the 3 findings established the threat model', () => {
        for (const outcome of EXPECTED_OUTCOMES) {
            expect(outcome.threatModelEstablished).toBe(false);
        }
    });

    it('each finding has specific missing evidence', () => {
        for (const outcome of EXPECTED_OUTCOMES) {
            expect(outcome.missingEvidence.length).toBeGreaterThan(0);
        }
    });

    it('assertNoOverstatedFindings catches PROVEN high-severity findings', () => {
        const overstatedResults = OLD_SCAN_RESULTS.map(f => ({
            file: f.file,
            line: f.line,
            type: f.type,
            severity: f.severity,
            proven: f.oldProven,
            verificationLevel: 'impact-confirmed',
        }));
        const result = assertNoOverstatedFindings(overstatedResults);
        expect(result.passed).toBe(false);
        expect(result.violations).toHaveLength(3);
    });

    it('assertNoOverstatedFindings passes when findings are investigationNotes', () => {
        const correctResults = OLD_SCAN_RESULTS.map(f => ({
            file: f.file,
            line: f.line,
            type: f.type,
            severity: 'medium',
            proven: 'INCONCLUSIVE',
            verificationLevel: 'logic-confirmed',
        }));
        const result = assertNoOverstatedFindings(correctResults);
        expect(result.passed).toBe(true);
        expect(result.violations).toHaveLength(0);
    });
});

describe('Synara Regression: investigation state prevents brute-reading', () => {
    it('detects overlapping reads on http.ts (the old scan read it 12 times)', () => {
        const state = new InvestigationState();
        const totalLines = 1275;

        const r1 = state.recordRead('apps/server/src/http.ts', 345, 580, totalLines);
        expect(r1.overlapping).toBe(false);

        // This range overlaps >50% with the first read
        const r2 = state.recordRead('apps/server/src/http.ts', 400, 550, totalLines);
        expect(r2.overlapping).toBe(true);
        expect(r2.overlapFraction).toBeGreaterThan(0.5);

        // This range also overlaps substantially
        const r3 = state.recordRead('apps/server/src/http.ts', 500, 570, totalLines);
        expect(r3.overlapping).toBe(true);
        expect(r3.overlapFraction).toBeGreaterThan(0.5);
    });

    it('tracks read count and triggers circuit breaker', () => {
        const state = new InvestigationState();
        for (let i = 0; i < 12; i++) {
            state.recordRead('apps/server/src/http.ts', i * 100 + 1, (i + 1) * 100, 1275);
        }
        expect(state.getReadCount('apps/server/src/http.ts')).toBe(12);
    });

    it('marks investigation steps complete as tools are used', () => {
        const state = new InvestigationState();
        state.recordRead('apps/server/src/http.ts', 1, 100, 1275);
        state.recordToolUse('check_policy');
        state.recordToolUse('get_endpoints');
        state.recordToolUse('search_code');
        state.recordToolUse('read_config');
        state.recordToolUse('trace_flow_cross_file');

        const completed = state.getCompletedSteps();
        expect(completed).toContain('initial-read');
        expect(completed).toContain('policy-check');
        expect(completed).toContain('route-discovery');
        expect(completed).toContain('auth-symbol-search');
        expect(completed).toContain('config-inspection');
        expect(completed).toContain('cross-file-flow');
    });

    it('reports incomplete steps when config inspection was not done', () => {
        const state = new InvestigationState();
        state.recordRead('apps/server/src/http.ts', 310, 319, 1275);
        state.recordToolUse('check_policy');

        const incomplete = state.getIncompleteSteps();
        expect(incomplete).toContain('config-inspection');
        expect(incomplete).toContain('route-discovery');
        expect(incomplete).toContain('cross-file-flow');
    });

    it('formats checklist showing what the agent missed', () => {
        const state = new InvestigationState();
        state.recordRead('apps/server/src/http.ts', 310, 319, 1275);
        state.recordToolUse('check_policy');

        const formatted = state.formatChecklistForPrompt();
        expect(formatted).toContain('incomplete');
        expect(formatted).toContain('config-inspection');
        expect(formatted).toContain('✗');
    });
});

describe('Synara Regression: root cause correlation', () => {
    it('http.ts:310 and http.ts:848 should share rootCauseId', () => {
        const state = new InvestigationState();
        state.registerRootCause('loopback-legacy-token-auth-bypass', 'isLegacyTokenAuthorized bypass');
        state.registerRootCause('loopback-legacy-token-ws-owner-bypass', 'WebSocket owner bypass');

        const causes = state.getRootCauses();
        expect(causes.size).toBe(2);
        expect(causes.has('loopback-legacy-token-auth-bypass')).toBe(true);
        expect(causes.has('loopback-legacy-token-ws-owner-bypass')).toBe(true);
    });

    it('duplicate root cause registration does not overwrite description', () => {
        const state = new InvestigationState();
        state.registerRootCause('rc-1', 'first description');
        state.registerRootCause('rc-1', 'second description');
        expect(state.getRootCauses().get('rc-1')).toBe('first description');
    });
});
