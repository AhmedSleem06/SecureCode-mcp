import { describe, it, expect, beforeEach } from 'vitest';
import { EvidenceLedger, type EvidenceRequirement } from '../src/attack/evidenceLedger';

describe('EvidenceLedger', () => {
    let ledger: EvidenceLedger;

    beforeEach(() => {
        ledger = new EvidenceLedger();
    });

    it('records evidence and returns a ref with fingerprint', () => {
        const result = ledger.recordEvidence({
            kind: 'source-range',
            transcriptStep: 1,
            tool: 'read_file',
            filePath: 'src/http.ts',
            range: { start: 1, end: 100 },
            outcome: 'positive',
        });
        expect(result.ref.id).toBeTruthy();
        expect(result.ref.fingerprint).toBeTruthy();
        expect(result.delta.meaningful).toBe(true);
    });

    it('skips duplicate evidence with same fingerprint', () => {
        const input = {
            kind: 'source-range' as const,
            transcriptStep: 1,
            tool: 'read_file' as const,
            filePath: 'src/http.ts',
            range: { start: 1, end: 100 },
            outcome: 'positive' as const,
        };
        const r1 = ledger.recordEvidence(input);
        const r2 = ledger.recordEvidence(input);
        expect(r1.ref.id).toBe(r2.ref.id);
        expect(r2.delta.meaningful).toBe(false);
    });

    it('satisfies a requirement when enough evidence is recorded', () => {
        const req: EvidenceRequirement = {
            id: 'req-auth',
            description: 'Find auth function',
            acceptedKinds: ['symbol-definition'],
            requiredTools: ['search_code'],
            minimumCount: 1,
        };
        ledger.addRequirement(req);
        expect(ledger.isRequirementSatisfied('req-auth')).toBe(false);

        ledger.recordEvidence({
            kind: 'symbol-definition',
            transcriptStep: 1,
            tool: 'search_code',
            symbol: 'authenticate',
            outcome: 'positive',
        });
        expect(ledger.isRequirementSatisfied('req-auth')).toBe(true);
        expect(ledger.getUnsatisfiedRequirements()).toHaveLength(0);
    });

    it('does not satisfy a requirement from blocked or error evidence', () => {
        const req: EvidenceRequirement = {
            id: 'req-1',
            description: 'test',
            acceptedKinds: ['policy-result'],
            requiredTools: ['check_policy'],
            minimumCount: 1,
        };
        ledger.addRequirement(req);

        ledger.recordEvidence({
            kind: 'policy-result',
            transcriptStep: 1,
            tool: 'check_policy',
            outcome: 'error',
        });
        expect(ledger.isRequirementSatisfied('req-1')).toBe(false);
    });

    it('does not satisfy a requirement from empty evidence unless acceptsNegative', () => {
        const req: EvidenceRequirement = {
            id: 'req-1',
            description: 'test',
            acceptedKinds: ['config-result'],
            requiredTools: ['read_config'],
            minimumCount: 1,
            acceptsNegative: false,
        };
        ledger.addRequirement(req);

        ledger.recordEvidence({
            kind: 'config-result',
            transcriptStep: 1,
            tool: 'read_config',
            outcome: 'empty',
        });
        expect(ledger.isRequirementSatisfied('req-1')).toBe(false);
    });

    it('satisfies a requirement from empty evidence when acceptsNegative', () => {
        const req: EvidenceRequirement = {
            id: 'req-1',
            description: 'Confirm no rate limit config',
            acceptedKinds: ['config-result'],
            requiredTools: ['read_config'],
            minimumCount: 1,
            acceptsNegative: true,
        };
        ledger.addRequirement(req);

        ledger.recordEvidence({
            kind: 'config-result',
            transcriptStep: 1,
            tool: 'read_config',
            outcome: 'empty',
        });
        expect(ledger.isRequirementSatisfied('req-1')).toBe(true);
    });

    it('requires minimum count before satisfying', () => {
        const req: EvidenceRequirement = {
            id: 'req-1',
            description: 'Review all handlers',
            acceptedKinds: ['handler-inventory'],
            minimumCount: 3,
        };
        ledger.addRequirement(req);

        for (let i = 0; i < 2; i++) {
            ledger.recordEvidence({
                kind: 'handler-inventory',
                transcriptStep: i + 1,
                tool: 'get_endpoints',
                symbol: `handler${i}`,
                outcome: 'positive',
            });
        }
        expect(ledger.isRequirementSatisfied('req-1')).toBe(false);

        ledger.recordEvidence({
            kind: 'handler-inventory',
            transcriptStep: 3,
            tool: 'get_endpoints',
            symbol: 'handler2',
            outcome: 'positive',
        });
        expect(ledger.isRequirementSatisfied('req-1')).toBe(true);
    });

    it('tracks new symbols as progress', () => {
        const r1 = ledger.recordEvidence({
            kind: 'symbol-definition',
            transcriptStep: 1,
            tool: 'search_code',
            symbol: 'isProjectOwner',
            outcome: 'positive',
        });
        expect(r1.delta.newSymbols).toContain('isProjectOwner');

        const r2 = ledger.recordEvidence({
            kind: 'symbol-reference',
            transcriptStep: 2,
            tool: 'find_references',
            symbol: 'isProjectOwner',
            outcome: 'positive',
        });
        // Same symbol — not new
        expect(r2.delta.newSymbols).toHaveLength(0);
    });

    it('tracks cross-file flows as progress', () => {
        const result = ledger.recordEvidence({
            kind: 'cross-file-flow',
            transcriptStep: 1,
            tool: 'trace_flow_cross_file',
            filePath: 'src/http.ts',
            outcome: 'positive',
        });
        expect(result.delta.newFlows).toBe(1);
        expect(result.delta.meaningful).toBe(true);
    });

    it('filters evidence by kind', () => {
        ledger.recordEvidence({
            kind: 'source-range',
            transcriptStep: 1,
            tool: 'read_file',
            outcome: 'positive',
        });
        ledger.recordEvidence({
            kind: 'policy-result',
            transcriptStep: 2,
            tool: 'check_policy',
            outcome: 'positive',
        });
        expect(ledger.getEvidenceByKind('source-range')).toHaveLength(1);
        expect(ledger.getEvidenceByKind('policy-result')).toHaveLength(1);
    });

    it('filters evidence by file path (case-insensitive, slash-normalized)', () => {
        ledger.recordEvidence({
            kind: 'source-range',
            transcriptStep: 1,
            tool: 'read_file',
            filePath: 'src\\Http.ts',
            range: { start: 1, end: 10 },
            outcome: 'positive',
        });
        expect(ledger.getEvidenceForFile('src/http.ts')).toHaveLength(1);
    });

    it('snapshot returns summary counts', () => {
        ledger.addRequirement({
            id: 'req-1',
            description: 'test',
            acceptedKinds: ['source-range'],
            minimumCount: 1,
        });
        ledger.recordEvidence({
            kind: 'source-range',
            transcriptStep: 1,
            tool: 'read_file',
            range: { start: 1, end: 10 },
            outcome: 'positive',
        });
        const snap = ledger.snapshot();
        expect(snap.evidenceCount).toBe(1);
        expect(snap.requirementCount).toBe(1);
        expect(snap.satisfiedCount).toBe(1);
    });

    it('returns unsatisfied requirements', () => {
        ledger.addRequirements([
            { id: 'req-1', description: 'a', acceptedKinds: ['source-range'], minimumCount: 1 },
            { id: 'req-2', description: 'b', acceptedKinds: ['policy-result'], minimumCount: 1 },
        ]);
        ledger.recordEvidence({
            kind: 'source-range',
            transcriptStep: 1,
            tool: 'read_file',
            outcome: 'positive',
        });
        const unsatisfied = ledger.getUnsatisfiedRequirements();
        expect(unsatisfied).toHaveLength(1);
        expect(unsatisfied[0].id).toBe('req-2');
    });
});
