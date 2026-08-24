import { describe, it, expect, beforeEach } from 'vitest';
import { CandidateStore } from '../src/attack/candidateStore';

describe('Candidate Store', () => {
    let store: CandidateStore;

    beforeEach(() => {
        store = new CandidateStore();
    });

    it('candidates are tracked with a unique id and root cause', () => {
        const id = store.register({
            rootCauseId: 'loopback-auth-bypass',
            type: 'broken_access_control',
            severity: 'high',
            locations: [{ filePath: 'test.ts', line: 10 }],
            claim: 'Loopback auth bypass',
        });
        expect(id).toBeTruthy();
        const candidate = store.get(id);
        expect(candidate).toBeDefined();
        expect(candidate!.status).toBe('discovered');
        expect(candidate!.rootCauseId).toBe('loopback-auth-bypass');
    });

    it('every candidate must become terminal before finish', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [], claim: 'XSS',
        });
        expect(store.allTerminal()).toBe(false);
        store.setUnproven(id, 'cannot reproduce');
        expect(store.allTerminal()).toBe(true);
    });

    it('candidates with the same root cause are merged', () => {
        const id1 = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [{ filePath: 'a.ts', line: 10 }], claim: 'A',
        });
        const id2 = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [{ filePath: 'b.ts', line: 20 }], claim: 'B',
        });
        // Both should return the same id (merged)
        expect(id1).toBe(id2);
        const candidate = store.get(id1);
        expect(candidate!.locations).toHaveLength(2);
    });

    it('candidates cannot be marked verified by the model', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [], claim: 'XSS',
        });
        expect(() => store.update(id, { status: 'verified' })).toThrow('only the verifier');
    });

    it('candidates can be marked rejected by the model', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [], claim: 'XSS',
        });
        store.update(id, { status: 'rejected' });
        expect(store.get(id)!.status).toBe('rejected');
    });

    it('candidates auto-transition from discovered to supported with evidence', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [], claim: 'XSS',
            requiredProofDimensions: [],
        });
        expect(store.get(id)!.status).toBe('discovered');
        store.addEvidence(id, 'ev1');
        expect(store.get(id)!.status).toBe('supported');
    });

    it('candidates stay supported with additional evidence refs', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [], claim: 'XSS',
            requiredProofDimensions: [],
        });
        store.addEvidence(id, 'ev1');
        store.addEvidence(id, 'ev2');
        expect(store.get(id)!.status).toBe('supported');
    });

    it('setVerified is only callable by the verifier', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'high',
            locations: [], claim: 'XSS',
            requiredProofDimensions: [],
        });
        store.setVerified(id, {
            verdict: 'PROVEN', reason: 'exploit confirmed',
            repeatedRuns: 3, repeatPasses: 3, mutationDiscriminating: true,
        });
        expect(store.get(id)!.status).toBe('verified');
        expect(store.get(id)!.verification!.verdict).toBe('PROVEN');
    });

    it('getActive returns non-terminal candidates', () => {
        const id1 = store.register({ rootCauseId: 'rc1', type: 'a', severity: 'low', locations: [], claim: 'A' });
        const id2 = store.register({ rootCauseId: 'rc2', type: 'b', severity: 'low', locations: [], claim: 'B' });
        store.setUnproven(id2, 'cannot reproduce');
        const active = store.getActive();
        expect(active).toHaveLength(1);
        expect(active[0].id).toBe(id1);
    });

    it('getTerminal returns terminal candidates', () => {
        const id1 = store.register({ rootCauseId: 'rc1', type: 'a', severity: 'low', locations: [], claim: 'A' });
        const id2 = store.register({ rootCauseId: 'rc2', type: 'b', severity: 'low', locations: [], claim: 'B' });
        store.setUnproven(id2, 'done');
        const terminal = store.getTerminal();
        expect(terminal).toHaveLength(1);
        expect(terminal[0].id).toBe(id2);
    });

    it('allTerminal returns true when no candidates exist', () => {
        expect(store.allTerminal()).toBe(true);
    });

    it('snapshot returns summary counts', () => {
        const id = store.register({ rootCauseId: 'rc1', type: 'a', severity: 'low', locations: [], claim: 'A', requiredProofDimensions: [] });
        store.addEvidence(id, 'ev1');
        store.setUnproven(id, 'done');
        const snap = store.snapshot();
        expect(snap.total).toBe(1);
        expect(snap.terminal).toBe(1);
        expect(snap.unproven).toBe(1);
    });

    it('candidates cannot disappear between steps', () => {
        const id = store.register({ rootCauseId: 'rc1', type: 'a', severity: 'low', locations: [], claim: 'A' });
        // There's no delete/remove method — candidates persist
        expect(store.size()).toBe(1);
        expect(store.get(id)).toBeDefined();
    });

    it('getCandidatesByRootCause returns all candidates with the same root cause', () => {
        // First registration creates the candidate
        const id1 = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [{ filePath: 'a.ts', line: 10 }], claim: 'A',
        });
        // Second with same root cause merges into first
        store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [{ filePath: 'b.ts', line: 20 }], claim: 'B',
        });
        // Different root cause
        store.register({
            rootCauseId: 'rc2', type: 'sql', severity: 'high',
            locations: [], claim: 'C',
        });
        const rc1Candidates = store.getCandidatesByRootCause('rc1');
        expect(rc1Candidates).toHaveLength(1); // merged
        const rc2Candidates = store.getCandidatesByRootCause('rc2');
        expect(rc2Candidates).toHaveLength(1);
    });

    it('high-severity candidate requires all proof dimensions before supported', () => {
        const id = store.register({
            rootCauseId: 'rc-shell', type: 'command_injection', severity: 'high',
            locations: [{ filePath: 'wsRpc.ts', line: 42 }], claim: 'Shell exec',
        });
        store.addEvidence(id, 'ev1', 'source', 'source');
        expect(store.get(id)!.status).toBe('investigating');
        store.addEvidence(id, 'ev2', 'flow', 'reachability');
        expect(store.get(id)!.status).toBe('investigating');
        store.addEvidence(id, 'ev3', 'guard', 'control');
        expect(store.get(id)!.status).toBe('investigating');
        store.addEvidence(id, 'ev4', 'policy', 'threat-model');
        expect(store.get(id)!.status).toBe('investigating');
        store.addEvidence(id, 'ev5', 'impact', 'impact');
        expect(store.get(id)!.status).toBe('investigating');
        store.addEvidence(id, 'ev6', 'test', 'verification');
        expect(store.get(id)!.status).toBe('supported');
    });

    it('two source reads do NOT support a high-severity candidate', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'high',
            locations: [], claim: 'XSS',
        });
        store.addEvidence(id, 'ev1', 'source', 'source');
        store.addEvidence(id, 'ev2', 'source', 'source');
        expect(store.get(id)!.status).toBe('investigating');
    });

    it('medium candidate requires source, reachability, control, and threat-model', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'medium',
            locations: [], claim: 'XSS',
        });
        store.addEvidence(id, 'ev1', undefined, 'source');
        store.addEvidence(id, 'ev2', undefined, 'reachability');
        store.addEvidence(id, 'ev3', undefined, 'control');
        expect(store.get(id)!.status).toBe('investigating');
        store.addEvidence(id, 'ev4', undefined, 'threat-model');
        expect(store.get(id)!.status).toBe('supported');
    });

    it('isReadyForJuror returns false for incomplete proof dimensions', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'high',
            locations: [], claim: 'XSS',
        });
        store.addEvidence(id, 'ev1', 'source', 'source');
        store.addEvidence(id, 'ev2', 'flow', 'reachability');
        expect(store.isReadyForJuror(id)).toBe(false);
    });

    it('setBlocked preserves the reason', () => {
        const id = store.register({
            rootCauseId: 'rc1', type: 'xss', severity: 'high',
            locations: [], claim: 'XSS',
        });
        store.setBlocked(id, 'Max attempts reached for trace_flow');
        expect(store.get(id)!.status).toBe('blocked');
        expect(store.get(id)!.blockedReason).toBe('Max attempts reached for trace_flow');
    });

    it('default proof dimensions are set based on severity', () => {
        const highId = store.register({
            rootCauseId: 'rc-h', type: 'xss', severity: 'high',
            locations: [], claim: 'H',
        });
        expect(store.get(highId)!.requiredProofDimensions).toContain('impact');
        expect(store.get(highId)!.requiredProofDimensions).toContain('verification');

        const medId = store.register({
            rootCauseId: 'rc-m', type: 'xss', severity: 'medium',
            locations: [], claim: 'M',
        });
        expect(store.get(medId)!.requiredProofDimensions).toContain('threat-model');
        expect(store.get(medId)!.requiredProofDimensions).not.toContain('impact');

        const lowId = store.register({
            rootCauseId: 'rc-l', type: 'xss', severity: 'low',
            locations: [], claim: 'L',
        });
        expect(store.get(lowId)!.requiredProofDimensions).toEqual(['source', 'control']);
    });
});
