import { describe, it, expect } from 'vitest';
import { GridState } from '../src/assurance/gridState';
import { selectAssuranceScenarios } from '../src/assurance/attackTests';
import type { GridCell, Scenario } from '../src/attack/agentScanProtocol';

function cell(id: string, risk: GridCell['risk'], overrides: Partial<GridCell> = {}): GridCell {
    return { id, entryId: 'e1', inputId: 'i1', targetId: 's1', attackType: 'idor', title: `cell ${id}`, risk, source: 'seed', status: 'open', ...overrides };
}

function apiScenario(id: string, cellId: string, risk: number, overrides: Partial<Scenario> = {}): Scenario {
    return { id, cellId, actor: 'user', preconditions: [], steps: ['step'], payloads: ['p'], expectSecure: 'deny', risk: risk as any, ...overrides };
}

describe('assurance hand-over: API plan → GridState → selectAssuranceScenarios', () => {
    it('hardening scenario preserved through GridState and excluded from attack selection', () => {
        const cells = [
            cell('c1', 5, { status: 'safe', closure: 'traced' }),
            cell('c2', 4, { status: 'safe', closure: 'reasoning' }),
        ];
        const scenarios: Scenario[] = [
            apiScenario('s1', 'c1', 5, { classification: 'weakness' }),
            apiScenario('s2', 'c1', 5, { classification: 'hardening' }),
            apiScenario('s3', 'c2', 4, { classification: 'weakness' }),
        ];

        const grid = new GridState(cells, scenarios);

        expect(grid.scenarios).toHaveLength(3);
        const s2 = grid.scenarios.find(s => s.id === 's2')!;
        expect(s2.classification).toBe('hardening');

        const selected = selectAssuranceScenarios(grid.cells, grid.scenarios, 10);
        const selectedIds = selected.map(s => s.scenario.id);

        expect(selectedIds).not.toContain('s2');
        expect(selectedIds).toContain('s1');
        expect(selectedIds).toContain('s3');
    });

    it('weakness scenarios are selected normally', () => {
        const cells = [cell('c1', 5, { status: 'safe', closure: 'reasoning' })];
        const scenarios = [
            apiScenario('s1', 'c1', 5, { classification: 'weakness' }),
            apiScenario('s2', 'c1', 5),
        ];

        const grid = new GridState(cells, scenarios);
        const selected = selectAssuranceScenarios(grid.cells, grid.scenarios, 10);
        expect(selected.length).toBe(2);
    });

    it('classification field survives normalizeScenario for both values', () => {
        const cells = [cell('c1', 4, { status: 'safe', closure: 'traced' })];
        const rawScenarios = [
            { id: 's1', cellId: 'c1', actor: 'u', preconditions: [], steps: ['s'], payloads: ['p'], expectSecure: 'x', risk: 4, classification: 'hardening' },
            { id: 's2', cellId: 'c1', actor: 'u', preconditions: [], steps: ['s'], payloads: ['p'], expectSecure: 'x', risk: 4, classification: 'weakness' },
            { id: 's3', cellId: 'c1', actor: 'u', preconditions: [], steps: ['s'], payloads: ['p'], expectSecure: 'x', risk: 4, classification: 'bogus' },
            { id: 's4', cellId: 'c1', actor: 'u', preconditions: [], steps: ['s'], payloads: ['p'], expectSecure: 'x', risk: 4 },
        ];

        const grid = new GridState(cells, rawScenarios);
        const s = grid.scenarios;
        expect(s.find(x => x.id === 's1')!.classification).toBe('hardening');
        expect(s.find(x => x.id === 's2')!.classification).toBe('weakness');
        expect(s.find(x => x.id === 's3')!.classification).toBeUndefined();
        expect(s.find(x => x.id === 's4')!.classification).toBeUndefined();
    });

    it('test and testNote fields survive normalization', () => {
        const cells = [cell('c1', 4, { status: 'safe', closure: 'traced' })];
        const rawScenarios = [
            { id: 's1', cellId: 'c1', actor: 'u', preconditions: [], steps: ['s'], payloads: ['p'], expectSecure: 'x', risk: 4, test: 'blocked', testNote: 'Guard held' },
        ];
        const grid = new GridState(cells, rawScenarios);
        expect(grid.scenarios[0].test).toBe('blocked');
        expect(grid.scenarios[0].testNote).toBeTruthy();
    });

    it('hardening-only cell yields no selected scenarios', () => {
        const cells = [cell('c1', 5, { status: 'safe', closure: 'reasoning' })];
        const scenarios = [
            apiScenario('s1', 'c1', 5, { classification: 'hardening' }),
            apiScenario('s2', 'c1', 5, { classification: 'hardening' }),
        ];
        const grid = new GridState(cells, scenarios);
        const selected = selectAssuranceScenarios(grid.cells, grid.scenarios, 10);
        expect(selected).toHaveLength(0);
    });
});
