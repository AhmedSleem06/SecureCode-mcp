import { describe, it, expect } from 'vitest';
import { InvestigationState } from '../src/attack/investigationState';

describe('InvestigationState', () => {
    it('detects exact duplicate reads', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        const result = state.recordRead('src/http.ts', 1, 100, 500);
        expect(result.overlapping).toBe(true);
        expect(result.overlapFraction).toBe(1.0);
    });

    it('detects overlapping reads with different ranges', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 100, 300, 500);
        const result = state.recordRead('src/http.ts', 200, 350, 500);
        expect(result.overlapping).toBe(true);
        expect(result.overlapFraction).toBeGreaterThan(0.5);
    });

    it('allows non-overlapping reads', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        const result = state.recordRead('src/http.ts', 200, 300, 500);
        expect(result.overlapping).toBe(false);
        expect(result.overlapFraction).toBe(0);
    });

    it('merges adjacent ranges', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        state.recordRead('src/http.ts', 101, 200, 500);
        const coverage = state.getCoverage('src/http.ts');
        expect(coverage).toBeDefined();
        expect(coverage!.ranges).toHaveLength(1);
        expect(coverage!.ranges[0]).toEqual({ start: 1, end: 200 });
    });

    it('tracks read count per file', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        state.recordRead('src/http.ts', 200, 300, 500);
        state.recordRead('src/http.ts', 400, 500, 500);
        expect(state.getReadCount('src/http.ts')).toBe(3);
    });

    it('normalizes paths (backslashes, case)', () => {
        const state = new InvestigationState();
        state.recordRead('src\\HTTP.ts', 1, 100, 500);
        expect(state.getCoverage('src/http.ts')).toBeDefined();
        expect(state.getReadCount('SRC\\http.ts')).toBe(1);
    });

    it('marks initial-read step complete after first read', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        expect(state.getCompletedSteps()).toContain('initial-read');
    });

    it('marks policy-check step complete after check_policy', () => {
        const state = new InvestigationState();
        state.recordToolUse('check_policy');
        expect(state.getCompletedSteps()).toContain('policy-check');
    });

    it('marks cross-file-flow after trace_flow or trace_flow_cross_file', () => {
        const state = new InvestigationState();
        state.recordToolUse('trace_flow_cross_file');
        expect(state.getCompletedSteps()).toContain('cross-file-flow');
    });

    it('marks config-inspection after read_config', () => {
        const state = new InvestigationState();
        state.recordToolUse('read_config');
        expect(state.getCompletedSteps()).toContain('config-inspection');
    });

    it('marks route-discovery after get_endpoints', () => {
        const state = new InvestigationState();
        state.recordToolUse('get_endpoints');
        expect(state.getCompletedSteps()).toContain('route-discovery');
    });

    it('reports incomplete steps', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        const incomplete = state.getIncompleteSteps();
        expect(incomplete).not.toContain('initial-read');
        expect(incomplete).toContain('policy-check');
        expect(incomplete).toContain('config-inspection');
    });

    it('reports all steps complete when required steps are done', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        state.recordToolUse('check_policy');
        state.recordToolUse('get_endpoints');
        state.recordToolUse('search_code');
        state.recordToolUse('trace_flow_cross_file');
        state.recordToolUse('read_config');
        state.markAllHandlersReviewed();
        state.markCandidatesVerified();
        expect(state.getIncompleteSteps()).toHaveLength(0);
    });

    it('formats checklist for prompt with incomplete steps', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        const formatted = state.formatChecklistForPrompt();
        expect(formatted).toContain('incomplete');
        expect(formatted).toContain('policy-check');
        expect(formatted).toContain('✗');
        expect(formatted).toContain('✓');
        expect(formatted).toContain('initial-read');
    });

    it('formats checklist as ALL COMPLETE when done', () => {
        const state = new InvestigationState();
        state.recordRead('src/http.ts', 1, 100, 500);
        state.recordToolUse('check_policy');
        state.recordToolUse('get_endpoints');
        state.recordToolUse('search_code');
        state.recordToolUse('trace_flow_cross_file');
        state.recordToolUse('read_config');
        state.markAllHandlersReviewed();
        state.markCandidatesVerified();
        const formatted = state.formatChecklistForPrompt();
        expect(formatted).toContain('ALL COMPLETE');
    });

    it('tracks root causes', () => {
        const state = new InvestigationState();
        state.registerRootCause('loopback-auth-bypass', 'Legacy token bypass on loopback');
        state.registerRootCause('loopback-auth-bypass', 'duplicate should not overwrite');
        const causes = state.getRootCauses();
        expect(causes.size).toBe(1);
        expect(causes.get('loopback-auth-bypass')).toBe('Legacy token bypass on loopback');
    });

    it('rangesOverlap detects partial overlap', () => {
        expect(InvestigationState.rangesOverlap({ start: 1, end: 100 }, { start: 50, end: 150 })).toBe(true);
        expect(InvestigationState.rangesOverlap({ start: 1, end: 100 }, { start: 101, end: 200 })).toBe(false);
        expect(InvestigationState.rangesOverlap({ start: 50, end: 100 }, { start: 1, end: 60 })).toBe(true);
    });

    it('overlapFraction returns 1.0 for identical ranges', () => {
        const a = { start: 1, end: 100 };
        const b = { start: 1, end: 100 };
        expect(InvestigationState.overlapFraction(a, b)).toBe(1.0);
    });

    it('overlapFraction returns 0 for non-overlapping ranges', () => {
        const a = { start: 1, end: 100 };
        const b = { start: 200, end: 300 };
        expect(InvestigationState.overlapFraction(a, b)).toBe(0);
    });

    it('mergeRanges handles non-adjacent ranges', () => {
        const ranges = [
            { start: 1, end: 100 },
            { start: 200, end: 300 },
            { start: 50, end: 150 },
        ];
        const merged = InvestigationState.mergeRanges(ranges);
        expect(merged).toEqual([
            { start: 1, end: 150 },
            { start: 200, end: 300 },
        ]);
    });

    describe('checkRead (non-recording check)', () => {
        it('detects exact duplicate without recording', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 100, 500);
            const check = state.checkRead('src/http.ts', 1, 100, 500);
            expect(check.isExactDuplicate).toBe(true);
            expect(check.overlapping).toBe(true);
            expect(state.getReadCount('src/http.ts')).toBe(1);
        });

        it('detects overlap without recording', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 200, 500);
            const check = state.checkRead('src/http.ts', 100, 300, 500);
            expect(check.overlapping).toBe(true);
            expect(check.overlapFraction).toBeGreaterThan(0.5);
            expect(state.getReadCount('src/http.ts')).toBe(1);
        });

        it('allows non-overlapping reads without recording', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 100, 500);
            const check = state.checkRead('src/http.ts', 200, 300, 500);
            expect(check.isExactDuplicate).toBe(false);
            expect(check.overlapping).toBe(false);
        });

        it('returns empty coverage for untracked file', () => {
            const state = new InvestigationState();
            const check = state.checkRead('src/new.ts', 1, 100, 500);
            expect(check.isExactDuplicate).toBe(false);
            expect(check.overlapping).toBe(false);
            expect(check.coverageAfter).toEqual([]);
        });
    });

    describe('recordBlockedRead', () => {
        it('increments blockedReadCount without merging ranges', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 100, 500);
            state.recordBlockedRead('src/http.ts');
            state.recordBlockedRead('src/http.ts');
            const coverage = state.getCoverage('src/http.ts');
            expect(coverage!.blockedReadCount).toBe(2);
            expect(coverage!.readCount).toBe(1);
            expect(coverage!.ranges).toHaveLength(1);
        });

        it('does not mark initial-read as complete', () => {
            const state = new InvestigationState();
            state.recordBlockedRead('src/http.ts');
            expect(state.getCompletedSteps()).not.toContain('initial-read');
        });
    });

    describe('getRecommendedRecoveryAction', () => {
        it('returns check_policy when policy-check is incomplete', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 100, 500);
            const rec = state.getRecommendedRecoveryAction();
            const incomplete = state.getIncompleteSteps();
            expect(incomplete[0]).not.toBe('initial-read');
            expect(rec).toBeTruthy();
        });

        it('returns read_config when config-inspection is the first incomplete step', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 100, 500);
            state.recordToolUse('check_policy');
            state.recordToolUse('search_code');
            state.recordToolUse('get_endpoints');
            state.recordToolUse('trace_flow_cross_file');
            state.markAllHandlersReviewed();
            state.markCandidatesVerified();
            const rec = state.getRecommendedRecoveryAction();
            expect(rec).toBe('read_config');
        });

        it('returns null when all steps complete', () => {
            const state = new InvestigationState();
            state.recordRead('src/http.ts', 1, 100, 500);
            state.recordToolUse('check_policy');
            state.recordToolUse('search_code');
            state.recordToolUse('get_endpoints');
            state.recordToolUse('trace_flow_cross_file');
            state.recordToolUse('read_config');
            state.markAllHandlersReviewed();
            state.markCandidatesVerified();
            expect(state.getRecommendedRecoveryAction()).toBeNull();
        });
    });
});
