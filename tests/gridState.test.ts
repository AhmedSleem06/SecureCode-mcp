import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { GridState, ASSURANCE_DIR, HIGH_RISK, type AttackOutcomeLike } from '../src/assurance/gridState';
import type { GridCell, Scenario, CellUpdate } from '../src/attack/agentScanProtocol';

function cell(id: string, risk: GridCell['risk'], overrides: Partial<GridCell> = {}): GridCell {
    return { id, entryId: 'e1', inputId: 'i1', targetId: 's1', attackType: 'idor', title: `cell ${id}`, risk, source: 'seed', status: 'open', ...overrides };
}

function scenario(id: string, cellId: string, risk: number = 3): Scenario {
    return { id, cellId, actor: 'user', preconditions: [], steps: ['step'], payloads: ['p'], expectSecure: 'deny', risk: risk as any };
}

describe('GridState', () => {
    describe('addCells / addScenarios', () => {
        it('adds cells and skips duplicates', () => {
            const grid = new GridState();
            const added = grid.addCells([cell('c1', 5), cell('c2', 3), cell('c1', 2)]);
            expect(added).toEqual(['c1', 'c2']);
            expect(grid.size).toBe(2);
            expect(grid.getCell('c1')!.risk).toBe(5);
        });

        it('adds scenarios only when their cell exists', () => {
            const grid = new GridState([cell('c1', 4)]);
            const added = grid.addScenarios([scenario('s1', 'c1'), scenario('s2', 'unknown')]);
            expect(added).toEqual(['s1']);
            expect(grid.scenarios).toHaveLength(1);
        });

        it('normalizes bad fields gracefully', () => {
            const grid = new GridState([{ id: 'c1', risk: 99, status: 'bogus', attackType: '', source: 'invalid' }]);
            const c = grid.getCell('c1')!;
            expect(c.risk).toBe(3);
            expect(c.status).toBe('open');
            expect(c.source).toBe('ai');
            expect(c.attackType).toBe('unknown');
        });
    });

    describe('applyCellUpdates', () => {
        it('applies valid updates and clamps', () => {
            const grid = new GridState([cell('c1', 5), cell('c2', 3)]);
            const updates: CellUpdate[] = [
                { cellId: 'c1', status: 'safe', closure: 'traced', evidenceLines: [10, 20] },
            ];
            const result = grid.applyCellUpdates(updates, [{ start: 1, end: 100 }]);
            expect(result.applied).toHaveLength(1);
            expect(grid.getCell('c1')!.status).toBe('safe');
            expect(grid.getCell('c1')!.closure).toBe('traced');
        });

        it('downgrades traced to reasoning when evidence lines were not delivered', () => {
            const grid = new GridState([cell('c1', 5)]);
            const updates: CellUpdate[] = [
                { cellId: 'c1', status: 'safe', closure: 'traced', evidenceLines: [50] },
            ];
            const result = grid.applyCellUpdates(updates, [{ start: 1, end: 20 }]);
            expect(result.downgraded).toContain('c1');
            expect(grid.getCell('c1')!.closure).toBe('reasoning');
        });

        it('never reopens a tested closure', () => {
            const grid = new GridState([cell('c1', 5, { status: 'safe', closure: 'tested' })]);
            const updates: CellUpdate[] = [
                { cellId: 'c1', status: 'open' },
            ];
            const result = grid.applyCellUpdates(updates, []);
            expect(result.skipped).toContain('c1');
            expect(grid.getCell('c1')!.closure).toBe('tested');
        });

        it('prevents the model from setting tested closure directly', () => {
            const grid = new GridState([cell('c1', 5)]);
            const updates: CellUpdate[] = [
                { cellId: 'c1', status: 'safe', closure: 'tested', evidenceLines: [10] },
            ];
            grid.applyCellUpdates(updates, [{ start: 1, end: 100 }]);
            expect(grid.getCell('c1')!.closure).toBe('traced');
        });

        it('respects scope', () => {
            const grid = new GridState([cell('c1', 5), cell('c2', 3)]);
            const scope = new Set(['c1']);
            const updates: CellUpdate[] = [
                { cellId: 'c1', status: 'safe', closure: 'reasoning' },
                { cellId: 'c2', status: 'safe', closure: 'reasoning' },
            ];
            const result = grid.applyCellUpdates(updates, [], scope);
            expect(result.applied).toHaveLength(1);
            expect(grid.getCell('c2')!.status).toBe('open');
        });
    });

    describe('stepView', () => {
        it('returns open cells sorted by risk descending and limited to 40', () => {
            const cells = Array.from({ length: 50 }, (_, i) => cell(`c${i}`, (i % 5 + 1) as any));
            const grid = new GridState(cells);
            const view = grid.stepView();
            expect(view.openCells).toHaveLength(40);
            expect(view.openCells[0].risk).toBeGreaterThanOrEqual(view.openCells[view.openCells.length - 1].risk);
            expect(view.counts.total).toBe(50);
            expect(view.counts.open).toBe(50);
        });

        it('returns scenarios only for shown cells, limited to 20', () => {
            const grid = new GridState([cell('c1', 5), cell('c2', 3)]);
            const scenarios = Array.from({ length: 25 }, (_, i) => scenario(`s${i}`, 'c1'));
            grid.addScenarios(scenarios);
            const view = grid.stepView();
            expect(view.activeScenarios.length).toBeLessThanOrEqual(20);
            expect(view.activeScenarios.every(s => s.cellId === 'c1')).toBe(true);
        });
    });

    describe('isFullyClosed / gateProblems', () => {
        it('reports open cells', () => {
            const grid = new GridState([cell('c1', 5), cell('c2', 3, { status: 'safe', closure: 'traced' })]);
            expect(grid.isFullyClosed()).toBe(false);
            expect(grid.gateProblems().open).toHaveLength(1);
        });

        it('flags safe risk>=4 cells without traced/tested as weak', () => {
            const grid = new GridState([
                cell('c1', 4, { status: 'safe', closure: 'reasoning' }),
                cell('c2', 5, { status: 'safe', closure: 'traced' }),
                cell('c3', 3, { status: 'safe', closure: 'reasoning' }),
            ]);
            expect(grid.isFullyClosed()).toBe(true);
            const problems = grid.gateProblems();
            expect(problems.open).toHaveLength(0);
            expect(problems.weak).toHaveLength(1);
            expect(problems.weak[0].id).toBe('c1');
        });

        it('fully closed grid with all traced', () => {
            const grid = new GridState([
                cell('c1', 5, { status: 'safe', closure: 'traced' }),
                cell('c2', 3, { status: 'not-applicable' }),
            ]);
            expect(grid.isFullyClosed()).toBe(true);
            const problems = grid.gateProblems();
            expect(problems.open).toHaveLength(0);
            expect(problems.weak).toHaveLength(0);
        });
    });

    describe('applyAttackOutcome', () => {
        it('applies scenario and cell updates from an attack outcome', () => {
            const grid = new GridState(
                [cell('c1', 5, { status: 'safe', closure: 'traced' })],
                [scenario('s1', 'c1', 5)],
            );
            const outcome: AttackOutcomeLike = {
                scenarioUpdates: [{ scenarioId: 's1', test: 'blocked', testNote: 'Blocked by guard' }],
                cellUpdates: [{ cellId: 'c1', status: 'safe', closure: 'tested', note: 'Attack test blocked' }],
                approval: { granted: true, reason: 'User approved' },
                costUsd: 0.05,
            };
            grid.applyAttackOutcome(outcome);
            expect(grid.getCell('c1')!.closure).toBe('tested');
            expect(grid.scenarios[0].test).toBe('blocked');
            expect(grid.attackTests!.blocked).toBe(1);
            expect(grid.attackTests!.costUsd).toBe(0.05);
        });

        it('does not downgrade tested to untestable', () => {
            const grid = new GridState([cell('c1', 5, { status: 'safe', closure: 'tested' })]);
            const outcome: AttackOutcomeLike = {
                scenarioUpdates: [],
                cellUpdates: [{ cellId: 'c1', status: 'untestable', closure: 'untestable' }],
                approval: { granted: true, reason: '' },
                costUsd: 0,
            };
            grid.applyAttackOutcome(outcome);
            expect(grid.getCell('c1')!.closure).toBe('tested');
        });
    });

    describe('scopeForRange', () => {
        it('assigns line-anchored cells to the right part', () => {
            const inv = {
                file: 'test.ts',
                entryPoints: [{ id: 'e1', kind: 'http' as const, name: 'GET /a', line: 10 }],
                inputs: [{ id: 'i1', entryId: 'e1', source: 'req.params', line: 12 }],
                sinks: [{ id: 's1', kind: 'sql', line: 50, callExpression: 'db.query()' }],
                guards: [],
                roles: [],
                connected: [],
                flows: [],
            };
            const grid = new GridState(
                [cell('c1', 5, { entryId: 'e1', targetId: 's1' }), cell('c2', 3, { entryId: null, targetId: null, inputId: null })],
                [],
                inv,
            );
            const scope1 = grid.scopeForRange({ startLine: 1, endLine: 30 });
            expect(scope1.has('c1')).toBe(true);
            expect(scope1.has('c2')).toBe(true);
            const scope2 = grid.scopeForRange({ startLine: 40, endLine: 80 });
            expect(scope2.has('c1')).toBe(true);
            expect(scope2.has('c2')).toBe(true);
        });
    });

    describe('persist / load', () => {
        let tmpDir: string;
        beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gridstate-')); });
        afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

        it('persists and loads grid state round-trip', () => {
            const grid = new GridState(
                [cell('c1', 5, { status: 'safe', closure: 'traced', evidenceLines: [10] })],
                [scenario('s1', 'c1', 5)],
            );
            grid.redteamRounds = 1;
            grid.addWarning('test warning');
            const p = grid.persist(tmpDir, 'run-123');
            expect(p).not.toBeNull();
            expect(fs.existsSync(path.join(tmpDir, ASSURANCE_DIR, '.gitignore'))).toBe(true);
            const loaded = GridState.load(tmpDir, 'run-123');
            expect(loaded).not.toBeNull();
            expect(loaded!.size).toBe(1);
            expect(loaded!.getCell('c1')!.closure).toBe('traced');
            expect(loaded!.scenarios).toHaveLength(1);
            expect(loaded!.redteamRounds).toBe(1);
            expect(loaded!.warnings).toContain('test warning');
        });

        it('returns null for missing run', () => {
            expect(GridState.load(tmpDir, 'nonexistent')).toBeNull();
        });
    });

    describe('counts', () => {
        it('counts all statuses', () => {
            const grid = new GridState([
                cell('c1', 5, { status: 'open' }),
                cell('c2', 4, { status: 'safe', closure: 'tested' }),
                cell('c3', 3, { status: 'vulnerable' }),
                cell('c4', 2, { status: 'not-applicable' }),
                cell('c5', 1, { status: 'untestable' }),
                cell('c6', 3, { status: 'depends' }),
            ]);
            const c = grid.counts();
            expect(c.total).toBe(6);
            expect(c.open).toBe(1);
            expect(c.safe).toBe(1);
            expect(c.vulnerable).toBe(1);
            expect(c.notApplicable).toBe(1);
            expect(c.untestable).toBe(1);
            expect(c.depends).toBe(1);
            expect(c.tested).toBe(1);
        });
    });

    describe('toResult', () => {
        it('returns a copy with all fields', () => {
            const grid = new GridState([cell('c1', 5)], [scenario('s1', 'c1')]);
            grid.redteamRounds = 2;
            grid.addWarning('w1');
            const r = grid.toResult();
            expect(r.cells).toHaveLength(1);
            expect(r.scenarios).toHaveLength(1);
            expect(r.redteamRounds).toBe(2);
            expect(r.warnings).toContain('w1');
            expect(r.counts.total).toBe(1);
        });
    });
});
