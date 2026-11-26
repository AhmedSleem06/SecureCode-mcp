import { describe, it, expect } from 'vitest';
import {
    selectAssuranceScenarios,
    buildAssuranceCellUpdates,
    ASSURANCE_DEFAULT_MAX_TESTS,
    ASSURANCE_DEFAULT_MAX_USD,
    ASSURANCE_CONSECUTIVE_UNTESTABLE_LIMIT,
} from '../src/assurance/attackTests';
import type { GridCell, Scenario } from '../src/attack/agentScanProtocol';

function cell(id: string, risk: number, status = 'safe' as GridCell['status'], closure?: GridCell['closure']): GridCell {
    return { id, title: `Cell ${id}`, attackType: 'sqli', risk, status, closure, evidenceLines: [10] } as GridCell;
}

function scenario(id: string, cellId: string, risk = 5): Scenario {
    return { id, cellId, risk, actor: 'anon', preconditions: [], steps: ['send payload'], payloads: ['x'], expectSecure: 'reject', test: undefined } as unknown as Scenario;
}

describe('selectAssuranceScenarios', () => {
    it('sorts by risk descending then weakest closure first', () => {
        const cells = [cell('a', 3), cell('b', 5), cell('c', 4, 'safe', 'reasoning')];
        const scenarios = [scenario('sa', 'a'), scenario('sb', 'b'), scenario('sc', 'c')];
        const result = selectAssuranceScenarios(cells, scenarios, 10);
        expect(result.map(r => r.scenario.id)).toEqual(['sb', 'sc', 'sa']);
    });

    it('respects maxTests cap', () => {
        const cells = Array.from({ length: 10 }, (_, i) => cell(`c${i}`, 5));
        const scenarios = cells.map(c => scenario(`s${c.id}`, c.id));
        const result = selectAssuranceScenarios(cells, scenarios, 3);
        expect(result).toHaveLength(3);
    });

    it('skips already-tested cells', () => {
        const cells = [cell('a', 5, 'safe', 'tested'), cell('b', 5)];
        const scenarios = [scenario('sa', 'a'), scenario('sb', 'b')];
        const result = selectAssuranceScenarios(cells, scenarios, 10);
        expect(result).toHaveLength(1);
        expect(result[0].scenario.id).toBe('sb');
    });
});

describe('buildAssuranceCellUpdates', () => {
    it('marks cells with exploited scenarios as vulnerable/tested', () => {
        const cells = [cell('a', 5)];
        const results = [{ cell: cells[0], scenario: scenario('s1', 'a'), test: 'exploited' as const, note: 'Attack test exploited: found it', line: 10 }];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(1);
        expect(updates[0].status).toBe('vulnerable');
        expect(updates[0].closure).toBe('tested');
    });

    it('marks cells with blocked scenarios as safe/tested', () => {
        const cells = [cell('a', 5)];
        const results = [{ cell: cells[0], scenario: scenario('s1', 'a'), test: 'blocked' as const, note: 'Attack test blocked: safe', line: 10 }];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(1);
        expect(updates[0].status).toBe('safe');
        expect(updates[0].closure).toBe('tested');
    });

    it('skips results for skipped tests', () => {
        const cells = [cell('a', 5)];
        const results = [{ cell: cells[0], scenario: scenario('s1', 'a'), test: 'skipped' as const, note: 'skipped', line: 10 }];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(0);
    });

    it('matchesCell=false does not mark the cell as vulnerable', () => {
        const cells = [cell('a', 5)];
        const results = [{
            cell: cells[0], scenario: scenario('s1', 'a'), test: 'exploited' as const, note: 'exploited but different weakness', line: 10,
            observedWeakness: { type: 'missing_rate_limiting', severity: 'medium' as const, matchesCell: false, summary: 'No rate limiting' },
        }];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(0);
    });

    it('matchesCell=true (or absent) marks the cell as vulnerable normally', () => {
        const cells = [cell('a', 5)];
        const results = [{
            cell: cells[0], scenario: scenario('s1', 'a'), test: 'exploited' as const, note: 'exploited', line: 10,
            observedWeakness: { type: 'sqli', severity: 'critical' as const, matchesCell: true, summary: 'SQL injection found' },
        }];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(1);
        expect(updates[0].status).toBe('vulnerable');
    });

    it('no observedWeakness still marks cell as vulnerable (backward compat)', () => {
        const cells = [cell('a', 5)];
        const results = [{ cell: cells[0], scenario: scenario('s1', 'a'), test: 'exploited' as const, note: 'exploited', line: 10 }];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(1);
        expect(updates[0].status).toBe('vulnerable');
    });

    it('mixed: matchesCell=false exploit + blocked on same cell yields safe/tested', () => {
        const cells = [cell('a', 5)];
        const results = [
            {
                cell: cells[0], scenario: scenario('s1', 'a'), test: 'exploited' as const, note: 'different weakness', line: 10,
                observedWeakness: { type: 'other', severity: 'low' as const, matchesCell: false, summary: 'mismatch' },
            },
            { cell: cells[0], scenario: scenario('s2', 'a'), test: 'blocked' as const, note: 'blocked', line: 10 },
        ];
        const updates = buildAssuranceCellUpdates(cells, results);
        expect(updates).toHaveLength(1);
        expect(updates[0].status).toBe('safe');
        expect(updates[0].closure).toBe('tested');
        expect(updates[0].note).toContain('mismatched exploit');
    });
});

describe('constants', () => {
    it('ASSURANCE_DEFAULT_MAX_TESTS is 20', () => {
        expect(ASSURANCE_DEFAULT_MAX_TESTS).toBe(20);
    });

    it('ASSURANCE_DEFAULT_MAX_USD is 1.5', () => {
        expect(ASSURANCE_DEFAULT_MAX_USD).toBe(1.5);
    });

    it('ASSURANCE_CONSECUTIVE_UNTESTABLE_LIMIT is 3', () => {
        expect(ASSURANCE_CONSECUTIVE_UNTESTABLE_LIMIT).toBe(3);
    });
});
