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

    describe('recordActualRead (actual delivered range)', () => {
        it('records the actual delivered range, not the requested range', () => {
            const state = new InvestigationState();
            // Requested 1-2000, but executor clamped to 1-500 (actual)
            state.recordActualRead('src/big.ts', 1, 500, 2000, false);
            const coverage = state.getCoverage('src/big.ts');
            expect(coverage).toBeDefined();
            expect(coverage!.ranges).toEqual([{ start: 1, end: 500 }]);
            expect(coverage!.totalLines).toBe(2000);
        });

        it('records full coverage for a small file (not truncated)', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/small.ts', 1, 100, 100, false);
            const coverage = state.getCoverage('src/small.ts');
            expect(coverage!.ranges).toEqual([{ start: 1, end: 100 }]);
        });

        it('records no content coverage for a truncated (function map) read', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/large.ts', 0, 0, 2000, true);
            const coverage = state.getCoverage('src/large.ts');
            expect(coverage!.ranges).toEqual([]);
            expect(coverage!.readCount).toBe(1);
            expect(coverage!.totalLines).toBe(2000);
        });

        it('allows a second read of a non-overlapping actual range', () => {
            const state = new InvestigationState();
            const r1 = state.recordActualRead('src/big.ts', 1, 300, 2000, false);
            expect(r1.overlapping).toBe(false);
            const r2 = state.recordActualRead('src/big.ts', 301, 600, 2000, false);
            expect(r2.overlapping).toBe(false);
            const coverage = state.getCoverage('src/big.ts');
            expect(coverage!.ranges).toEqual([{ start: 1, end: 600 }]);
        });

        it('detects overlapping actual ranges', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 300, 2000, false);
            const r2 = state.recordActualRead('src/big.ts', 200, 400, 2000, false);
            expect(r2.overlapping).toBe(true);
            expect(r2.overlapFraction).toBeGreaterThan(0.5);
        });

        it('increments readCount for truncated reads', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/large.ts', 0, 0, 2000, true);
            expect(state.getReadCount('src/large.ts')).toBe(1);
        });

        it('does NOT mark initial-read complete for truncated reads', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/large.ts', 0, 0, 2000, true);
            expect(state.getCompletedSteps()).not.toContain('initial-read');
        });

        it('does not record coverage when actualStart/actualEnd are 0', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/large.ts', 0, 0, 2000, false);
            const coverage = state.getCoverage('src/large.ts');
            expect(coverage!.ranges).toEqual([]);
            expect(coverage!.readCount).toBe(1);
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

    describe('getUncoveredRanges', () => {
        it('returns full file as uncovered when nothing has been read', () => {
            const state = new InvestigationState();
            state.recordRead('src/big.ts', 1, 0, 500);
            state.getCoverage('src/big.ts')!.ranges = [];
            const gaps = state.getUncoveredRanges('src/big.ts');
            expect(gaps).toEqual([{ start: 1, end: 500 }]);
        });

        it('returns gap after a partial read', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 300, 1000, false);
            const gaps = state.getUncoveredRanges('src/big.ts');
            expect(gaps).toEqual([{ start: 301, end: 1000 }]);
        });

        it('returns gap between two read ranges', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 100, 1000, false);
            state.recordActualRead('src/big.ts', 500, 600, 1000, false);
            const gaps = state.getUncoveredRanges('src/big.ts');
            expect(gaps).toEqual([{ start: 101, end: 499 }, { start: 601, end: 1000 }]);
        });

        it('returns empty array when fully covered', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 1000, 1000, false);
            const gaps = state.getUncoveredRanges('src/big.ts');
            expect(gaps).toEqual([]);
        });

        it('returns empty array for untracked file', () => {
            const state = new InvestigationState();
            const gaps = state.getUncoveredRanges('src/unknown.ts');
            expect(gaps).toEqual([]);
        });

        it('returns gap before the first range', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 100, 200, 500, false);
            const gaps = state.getUncoveredRanges('src/big.ts');
            expect(gaps).toEqual([{ start: 1, end: 99 }, { start: 201, end: 500 }]);
        });
    });

    describe('getNextUnreadRange', () => {
        it('returns the first gap chunk for a partially read file', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 300, 1000, false);
            const next = state.getNextUnreadRange('src/big.ts');
            expect(next).toEqual({ start: 301, end: 600 });
        });

        it('returns null when fully covered', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/small.ts', 1, 100, 100, false);
            expect(state.getNextUnreadRange('src/small.ts')).toBeNull();
        });

        it('returns null for untracked file', () => {
            const state = new InvestigationState();
            expect(state.getNextUnreadRange('src/unknown.ts')).toBeNull();
        });

        it('respects the chunk size policy for a 2000-line file', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 300, 2000, false);
            const next = state.getNextUnreadRange('src/big.ts');
            expect(next).toEqual({ start: 301, end: 600 });
        });

        it('uses 250-line chunks for a 500-line file', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/med.ts', 1, 100, 500, false);
            const next = state.getNextUnreadRange('src/med.ts');
            expect(next).toEqual({ start: 101, end: 350 });
        });

        it('clamps the chunk to the file end', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 900, 1000, false);
            const next = state.getNextUnreadRange('src/big.ts');
            expect(next).toEqual({ start: 901, end: 1000 });
        });

        it('returns the full file for a small file with no reads', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/small.ts', 0, 0, 100, true);
            const next = state.getNextUnreadRange('src/small.ts');
            expect(next).toEqual({ start: 1, end: 100 });
        });
    });

    describe('getCoveragePercent', () => {
        it('returns 0 for untracked file', () => {
            const state = new InvestigationState();
            expect(state.getCoveragePercent('src/unknown.ts')).toBe(0);
        });

        it('returns 0 for a file with no coverage', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 0, 0, 1000, true);
            expect(state.getCoveragePercent('src/big.ts')).toBe(0);
        });

        it('returns correct percentage for partial coverage', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 300, 1000, false);
            expect(state.getCoveragePercent('src/big.ts')).toBe(30);
        });

        it('returns 100 for full coverage', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/small.ts', 1, 100, 100, false);
            expect(state.getCoveragePercent('src/small.ts')).toBe(100);
        });

        it('handles multiple ranges', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 1, 200, 1000, false);
            state.recordActualRead('src/big.ts', 500, 700, 1000, false);
            expect(state.getCoveragePercent('src/big.ts')).toBe(40);
        });
    });

    describe('chunkSizeForLines', () => {
        it('returns totalLines for files under 300 lines', () => {
            expect(InvestigationState.chunkSizeForLines(100)).toBe(100);
            expect(InvestigationState.chunkSizeForLines(299)).toBe(299);
        });

        it('returns 250 for files 300-999 lines', () => {
            expect(InvestigationState.chunkSizeForLines(300)).toBe(250);
            expect(InvestigationState.chunkSizeForLines(999)).toBe(250);
        });

        it('returns 300 for files 1000-4999 lines', () => {
            expect(InvestigationState.chunkSizeForLines(1000)).toBe(300);
            expect(InvestigationState.chunkSizeForLines(4999)).toBe(300);
        });

        it('returns 400 for files over 5000 lines', () => {
            expect(InvestigationState.chunkSizeForLines(5000)).toBe(400);
            expect(InvestigationState.chunkSizeForLines(10000)).toBe(400);
        });
    });

    describe('investigation tasks', () => {
        it('addInvestigationTasks stores tasks', () => {
            const state = new InvestigationState();
            state.addInvestigationTasks([{
                id: 'task-1',
                targetFiles: ['src/http.ts'],
                claim: 'Auth bypass on loopback',
                requiredTools: ['read_config', 'trace_flow_cross_file'],
                requiredEvidence: ['Verify defaults'],
                status: 'pending',
            }]);
            expect(state.getAllTasks()).toHaveLength(1);
            expect(state.getPendingTasks()).toHaveLength(1);
        });

        it('updateTaskStatus changes task status', () => {
            const state = new InvestigationState();
            state.addInvestigationTasks([{
                id: 'task-1',
                targetFiles: ['src/http.ts'],
                claim: 'Risk',
                requiredTools: [],
                requiredEvidence: [],
                status: 'pending',
            }]);
            state.updateTaskStatus('task-1', 'verified');
            expect(state.getPendingTasks()).toHaveLength(0);
            expect(state.getUnresolvedTasks()).toHaveLength(0);
        });

        it('getUnresolvedTasks returns pending and blocked', () => {
            const state = new InvestigationState();
            state.addInvestigationTasks([
                { id: 't1', targetFiles: [], claim: 'A', requiredTools: [], requiredEvidence: [], status: 'pending' },
                { id: 't2', targetFiles: [], claim: 'B', requiredTools: [], requiredEvidence: [], status: 'blocked' },
                { id: 't3', targetFiles: [], claim: 'C', requiredTools: [], requiredEvidence: [], status: 'verified' },
            ]);
            const unresolved = state.getUnresolvedTasks();
            expect(unresolved).toHaveLength(2);
            expect(unresolved.map(t => t.id).sort()).toEqual(['t1', 't2']);
        });

        it('marks architecture-risks-addressed when all tasks are resolved', () => {
            const state = new InvestigationState();
            state.setRequiredSteps(['initial-read', 'architecture-risks-addressed', 'candidates-verified']);
            state.addInvestigationTasks([
                { id: 't1', targetFiles: [], claim: 'A', requiredTools: [], requiredEvidence: [], status: 'pending' },
            ]);
            state.recordRead('src/http.ts', 1, 100, 500);
            expect(state.getIncompleteSteps()).toContain('architecture-risks-addressed');
            state.updateTaskStatus('t1', 'verified');
            expect(state.getIncompleteSteps()).not.toContain('architecture-risks-addressed');
        });

        it('does not duplicate tasks with the same id', () => {
            const state = new InvestigationState();
            state.addInvestigationTasks([{
                id: 'task-1', targetFiles: [], claim: 'A',
                requiredTools: [], requiredEvidence: [], status: 'pending',
            }]);
            state.addInvestigationTasks([{
                id: 'task-1', targetFiles: [], claim: 'B (different)',
                requiredTools: [], requiredEvidence: [], status: 'pending',
            }]);
            expect(state.getAllTasks()).toHaveLength(1);
            expect(state.getAllTasks()[0].claim).toBe('A');
        });
    });

    describe('coverage bugs — desired behavior (Phase 1 regression tests)', () => {
        it('function-map-only reads should NOT complete initial-read', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/big.ts', 0, 0, 2000, true);
            // DESIRED: a truncated function-map read delivers no source lines,
            // so initial-read should NOT be complete.
            // CURRENT: initial-read IS marked complete (bug).
            expect(state.getCompletedSteps()).not.toContain('initial-read');
        });

        it('invalid inverted ranges should NOT enter coverage state', () => {
            const state = new InvestigationState();
            // Simulate an inverted range: actualStart > actualEnd
            // This can happen when startLine > totalLines
            state.recordActualRead('src/bad.ts', 500, 100, 200, false);
            const coverage = state.getCoverage('src/bad.ts');
            // DESIRED: inverted ranges should be rejected, no coverage recorded
            // CURRENT: the range is accepted (bug)
            if (coverage) {
                const hasInverted = coverage.ranges.some(r => r.start > r.end);
                expect(hasInverted).toBe(false);
            }
        });

        it('all-handlers-reviewed should not be completable without handler evidence', () => {
            const state = new InvestigationState();
            // DESIRED: markAllHandlersReviewed should require handler inventory evidence
            // CURRENT: it can be called manually with no evidence
            state.markAllHandlersReviewed();
            // After Phase 5, this should NOT complete the step without evidence.
            // For now, it does — documenting the gap.
            expect(state.getCompletedSteps()).toContain('all-handlers-reviewed');
            // This test documents that the step IS completable without evidence,
            // which is the bug. After Phase 5, we'll change this to NOT contain.
        });

        it('candidates-verified should not be completable without terminal candidates', () => {
            const state = new InvestigationState();
            // DESIRED: markCandidatesVerified should require all candidates terminal
            // CURRENT: it can be called manually with no candidates
            state.markCandidatesVerified();
            // After Phase 7, this should NOT complete without candidate evidence.
            expect(state.getCompletedSteps()).toContain('candidates-verified');
            // This test documents that the step IS completable without candidates,
            // which is the bug. After Phase 7, we'll change this to NOT contain.
        });

        it('architecture tasks never transition out of pending in production', () => {
            const state = new InvestigationState();
            state.addInvestigationTasks([{
                id: 'task-1',
                targetFiles: ['src/http.ts'],
                claim: 'No rate limiting',
                requiredTools: ['search_code'],
                requiredEvidence: ['Trace the code path'],
                status: 'pending',
            }]);
            // DESIRED: there should be a production path to resolve tasks.
            // CURRENT: updateTaskStatus is never called in production.
            const pending = state.getPendingTasks();
            expect(pending).toHaveLength(1);
            // Documenting: tasks are created but never resolved in production.
        });

        it('findings-bearing finishes should not bypass unresolved task reporting', () => {
            const state = new InvestigationState();
            state.addInvestigationTasks([{
                id: 'task-1',
                targetFiles: ['src/http.ts'],
                claim: 'Risk',
                requiredTools: [],
                requiredEvidence: [],
                status: 'pending',
            }]);
            const unresolved = state.getUnresolvedTasks();
            expect(unresolved.length).toBeGreaterThan(0);
        });
    });

    describe('classifyRead — read value classification (quality-first Phase 1)', () => {
        it('classifies a first read on a file as new-coverage', () => {
            const state = new InvestigationState();
            const result = state.classifyRead('src/http.ts', 1, 200, 1000);
            expect(result.classification).toBe('new-coverage');
            expect(result.overlapFraction).toBe(0);
            expect(result.newLines).toBe(200);
        });

        it('classifies an exact duplicate read as duplicate', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/http.ts', 1, 200, 1000, false);
            const result = state.classifyRead('src/http.ts', 1, 200, 1000);
            expect(result.classification).toBe('duplicate');
            expect(result.newLines).toBe(0);
            expect(result.nextUnreadRange).not.toBeNull();
        });

        it('classifies a fully covered range as high-overlap', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/http.ts', 1, 500, 1000, false);
            const result = state.classifyRead('src/http.ts', 100, 400, 1000);
            expect(result.classification).toBe('high-overlap');
            expect(result.overlapFraction).toBeGreaterThan(0.5);
            expect(result.newLines).toBeLessThanOrEqual(300);
        });

        it('classifies a partially new range as partial-new-coverage', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/http.ts', 1, 200, 1000, false);
            const result = state.classifyRead('src/http.ts', 150, 400, 1000);
            expect(result.classification).toBe('partial-new-coverage');
            expect(result.overlapFraction).toBeGreaterThan(0);
            expect(result.overlapFraction).toBeLessThanOrEqual(0.5);
            expect(result.newLines).toBeGreaterThan(0);
        });

        it('classifies a non-overlapping new range as new-coverage', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/http.ts', 1, 200, 1000, false);
            const result = state.classifyRead('src/http.ts', 500, 800, 1000);
            expect(result.classification).toBe('new-coverage');
            expect(result.overlapFraction).toBe(0);
            expect(result.newLines).toBe(301);
        });

        it('classifies an inverted range as invalid', () => {
            const state = new InvestigationState();
            const result = state.classifyRead('src/bad.ts', 500, 100, 1000);
            expect(result.classification).toBe('invalid');
            expect(result.newLines).toBe(0);
        });

        it('returns nextUnreadRange for duplicate reads', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/http.ts', 1, 200, 1000, false);
            const result = state.classifyRead('src/http.ts', 1, 200, 1000);
            expect(result.nextUnreadRange).not.toBeNull();
            expect(result.nextUnreadRange!.start).toBeGreaterThan(200);
        });

        it('returns null nextUnreadRange when file is fully covered', () => {
            const state = new InvestigationState();
            state.recordActualRead('src/small.ts', 1, 100, 100, false);
            const result = state.classifyRead('src/small.ts', 1, 100, 100);
            expect(result.classification).toBe('duplicate');
            expect(result.nextUnreadRange).toBeNull();
        });
    });
});
