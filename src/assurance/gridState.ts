import * as fs from 'fs';
import * as path from 'path';
import {
    clampCellUpdates,
    GRID_CELL_CLOSURES,
    GRID_CELL_SOURCES,
    GRID_CELL_STATUSES,
    SCENARIO_TEST_STATUSES,
    type AssuranceCounts,
    type AssuranceStepView,
    type CellUpdate,
    type GridCell,
    type GridCellClosure,
    type Scenario,
} from '../attack/agentScanProtocol';
import { redactText } from '../attack/report';
import type { FileInventory } from './types';

export const ASSURANCE_DIR = path.join('.securecode', 'assurance');
export const STEP_VIEW_MAX_OPEN_CELLS = 40;
export const STEP_VIEW_MAX_SCENARIOS = 20;
export const HIGH_RISK = 4;

export interface LineRange { start: number; end: number }

export interface AttackTestSummary {
    approval: { granted: boolean; reason: string };
    ran: number;
    blocked: number;
    exploited: number;
    untestable: number;
    skipped: number;
    costUsd: number;
}

export interface AssuranceResult {
    cells: GridCell[];
    scenarios: Scenario[];
    counts: AssuranceCounts;
    redteamRounds: number;
    attackTests: AttackTestSummary | null;
    warnings: string[];
}

export interface ApplyCellUpdatesResult {
    applied: CellUpdate[];
    downgraded: string[];
    skipped: string[];
}

export interface GridGateProblems {
    open: GridCell[];
    weak: GridCell[];
}

export interface AttackOutcomeLike {
    scenarioUpdates: { scenarioId: string; test: Scenario['test']; testNote: string; artifactPath?: string }[];
    cellUpdates: CellUpdate[];
    exploitedFindings?: unknown[];
    approval: { granted: boolean; reason: string };
    costUsd: number;
}

interface GridSnapshot {
    version: 1;
    runId: string;
    file: string;
    savedAt: string;
    cells: GridCell[];
    scenarios: Scenario[];
    redteamRounds: number;
    attackTests: AttackTestSummary | null;
    warnings: string[];
}

const RISKS = new Set([1, 2, 3, 4, 5]);
const STATUSES = new Set<string>(GRID_CELL_STATUSES);
const CLOSURES = new Set<string>(GRID_CELL_CLOSURES);
const SOURCES = new Set<string>(GRID_CELL_SOURCES);
const TESTS = new Set<string>(SCENARIO_TEST_STATUSES);

function redact(v: string | undefined): string | undefined {
    return typeof v === 'string' && v ? redactText(v) : v;
}

function inRanges(line: number, ranges: LineRange[]): boolean {
    return ranges.some(r => line >= r.start && line <= r.end);
}

function normalizeCell(raw: unknown): GridCell | null {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const c = raw as Record<string, any>;
    if (typeof c.id !== 'string' || !c.id.trim()) return null;
    const str = (v: unknown) => typeof v === 'string' && v ? v : null;
    return {
        id: c.id.trim(),
        entryId: str(c.entryId),
        inputId: str(c.inputId),
        targetId: str(c.targetId),
        attackType: typeof c.attackType === 'string' && c.attackType ? c.attackType : 'unknown',
        title: typeof c.title === 'string' ? c.title : '',
        risk: RISKS.has(c.risk) ? c.risk : 3,
        source: SOURCES.has(c.source) ? c.source : 'ai',
        status: STATUSES.has(c.status) ? c.status : 'open',
        ...(typeof c.closure === 'string' && CLOSURES.has(c.closure) ? { closure: c.closure as GridCellClosure } : {}),
        ...(Array.isArray(c.evidenceLines) ? { evidenceLines: c.evidenceLines.filter((n: unknown) => Number.isInteger(n)) } : {}),
        ...(typeof c.note === 'string' && c.note ? { note: redact(c.note) } : {}),
        ...(typeof c.dependsOn === 'string' && c.dependsOn ? { dependsOn: redact(c.dependsOn) } : {}),
    };
}

function normalizeScenario(raw: unknown): Scenario | null {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    const s = raw as Record<string, any>;
    if (typeof s.id !== 'string' || !s.id || typeof s.cellId !== 'string' || !s.cellId) return null;
    const list = (v: unknown) => Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
    return {
        id: s.id,
        cellId: s.cellId,
        actor: typeof s.actor === 'string' ? s.actor : '',
        preconditions: list(s.preconditions),
        steps: list(s.steps),
        payloads: list(s.payloads),
        expectSecure: typeof s.expectSecure === 'string' ? s.expectSecure : '',
        risk: RISKS.has(s.risk) ? s.risk : 3,
        ...(TESTS.has(s.test) ? { test: s.test } : {}),
        ...(typeof s.testNote === 'string' && s.testNote ? { testNote: redact(s.testNote) } : {}),
    };
}

function safeRunId(runId: string): string {
    return String(runId).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120) || 'run';
}

export class GridState {
    private readonly cellList: GridCell[] = [];
    private readonly cellById = new Map<string, GridCell>();
    private readonly scenarioList: Scenario[] = [];
    private readonly scenarioIds = new Set<string>();
    private lineIndex: Map<string, number> | null = null;
    inventory: FileInventory | null;
    redteamRounds = 0;
    attackTests: AttackTestSummary | null = null;
    readonly warnings: string[] = [];

    constructor(cells: unknown[] = [], scenarios: unknown[] = [], inventory: FileInventory | null = null) {
        this.inventory = inventory;
        this.addCells(cells);
        this.addScenarios(scenarios);
    }

    get cells(): GridCell[] { return this.cellList.map(c => ({ ...c })); }
    get scenarios(): Scenario[] { return this.scenarioList.map(s => ({ ...s })); }
    get size(): number { return this.cellList.length; }

    getCell(id: string): GridCell | undefined {
        const c = this.cellById.get(id);
        return c ? { ...c } : undefined;
    }

    addWarning(message: string): void {
        if (!this.warnings.includes(message)) this.warnings.push(message);
    }

    /** Adds new cells (duplicate ids are skipped); returns the ids added. */
    addCells(cells: unknown[]): string[] {
        const added: string[] = [];
        for (const raw of Array.isArray(cells) ? cells : []) {
            const cell = normalizeCell(raw);
            if (!cell || this.cellById.has(cell.id)) continue;
            this.cellList.push(cell);
            this.cellById.set(cell.id, cell);
            added.push(cell.id);
        }
        return added;
    }

    /** Adds scenarios whose cell exists (duplicate ids are skipped); returns the ids added. */
    addScenarios(scenarios: unknown[]): string[] {
        const added: string[] = [];
        for (const raw of Array.isArray(scenarios) ? scenarios : []) {
            const s = normalizeScenario(raw);
            if (!s || this.scenarioIds.has(s.id) || !this.cellById.has(s.cellId)) continue;
            this.scenarioList.push(s);
            this.scenarioIds.add(s.id);
            added.push(s.id);
        }
        return added;
    }

    /**
     * Applies model cell updates. Lines cited for a `traced` closure must all
     * have been delivered to the model, otherwise the closure becomes
     * `reasoning`. A `tested` closure is never reopened or overwritten here.
     */
    applyCellUpdates(raw: unknown, deliveredRanges: LineRange[], scope?: Set<string>): ApplyCellUpdatesResult {
        const known = new Set(this.cellList.filter(c => !scope || scope.has(c.id)).map(c => c.id));
        const updates = clampCellUpdates(raw, known);
        const result: ApplyCellUpdatesResult = { applied: [], downgraded: [], skipped: [] };
        for (const u of updates) {
            const cell = this.cellById.get(u.cellId)!;
            if (cell.closure === 'tested') {
                result.skipped.push(u.cellId);
                continue;
            }
            if (u.status === 'open') {
                cell.status = 'open';
                delete cell.closure;
                delete cell.evidenceLines;
                if (u.note) cell.note = redact(u.note);
                result.applied.push(u);
                continue;
            }
            let closure = u.closure === 'tested' ? 'traced' : u.closure;
            if (!closure) closure = u.status === 'untestable' ? 'untestable' : 'reasoning';
            const lines = u.evidenceLines ?? [];
            if (closure === 'traced' && (lines.length === 0 || !lines.every(l => inRanges(l, deliveredRanges)))) {
                closure = 'reasoning';
                result.downgraded.push(u.cellId);
            }
            cell.status = u.status;
            cell.closure = closure;
            if (lines.length > 0) cell.evidenceLines = lines; else delete cell.evidenceLines;
            if (u.note) cell.note = redact(u.note);
            if (u.dependsOn) cell.dependsOn = redact(u.dependsOn);
            result.applied.push({ ...u, closure });
        }
        return result;
    }

    applyAttackOutcome(outcome: AttackOutcomeLike): void {
        for (const su of outcome.scenarioUpdates ?? []) {
            const s = this.scenarioList.find(x => x.id === su.scenarioId);
            if (!s || !TESTS.has(su.test as string)) continue;
            s.test = su.test;
            if (su.testNote) s.testNote = redact(su.testNote);
        }
        const known = new Set(this.cellList.map(c => c.id));
        for (const u of clampCellUpdates(outcome.cellUpdates ?? [], known)) {
            const cell = this.cellById.get(u.cellId)!;
            if (u.closure === 'untestable' && cell.closure && cell.closure !== 'untestable') continue;
            if (cell.closure === 'tested' && u.closure !== 'tested') continue;
            cell.status = u.status;
            if (u.closure) cell.closure = u.closure;
            if (u.evidenceLines?.length) cell.evidenceLines = u.evidenceLines;
            if (u.note) cell.note = redact(u.note);
        }
        const tests = outcome.scenarioUpdates ?? [];
        const count = (t: string) => tests.filter(x => x.test === t).length;
        const prev = this.attackTests;
        const approval = { granted: !!outcome.approval?.granted, reason: String(outcome.approval?.reason ?? '') };
        const cost = typeof outcome.costUsd === 'number' && Number.isFinite(outcome.costUsd) ? outcome.costUsd : 0;
        this.attackTests = {
            approval: prev?.approval.granted && !approval.granted ? prev.approval : approval,
            ran: (prev?.ran ?? 0) + count('blocked') + count('exploited'),
            blocked: (prev?.blocked ?? 0) + count('blocked'),
            exploited: (prev?.exploited ?? 0) + count('exploited'),
            untestable: (prev?.untestable ?? 0) + count('untestable'),
            skipped: (prev?.skipped ?? 0) + count('skipped'),
            costUsd: (prev?.costUsd ?? 0) + cost,
        };
    }

    private cellsIn(scope?: Set<string>): GridCell[] {
        return scope ? this.cellList.filter(c => scope.has(c.id)) : this.cellList;
    }

    counts(scope?: Set<string>): AssuranceCounts {
        const cells = this.cellsIn(scope);
        const n = (s: GridCell['status']) => cells.filter(c => c.status === s).length;
        return {
            total: cells.length,
            open: n('open'),
            safe: n('safe'),
            vulnerable: n('vulnerable'),
            notApplicable: n('not-applicable'),
            untestable: n('untestable'),
            depends: n('depends'),
            tested: cells.filter(c => c.closure === 'tested').length,
        };
    }

    stepView(scope?: Set<string>): AssuranceStepView {
        const order = new Map(this.cellList.map((c, i) => [c.id, i]));
        const open = this.cellsIn(scope)
            .filter(c => c.status === 'open')
            .sort((a, b) => b.risk - a.risk || order.get(a.id)! - order.get(b.id)!)
            .slice(0, STEP_VIEW_MAX_OPEN_CELLS);
        const shown = new Set(open.map(c => c.id));
        const cellRank = new Map(open.map((c, i) => [c.id, i]));
        const activeScenarios = this.scenarioList
            .filter(s => shown.has(s.cellId))
            .sort((a, b) => b.risk - a.risk || cellRank.get(a.cellId)! - cellRank.get(b.cellId)!)
            .slice(0, STEP_VIEW_MAX_SCENARIOS)
            .map(s => ({ ...s }));
        return { openCells: open.map(c => ({ ...c })), activeScenarios, counts: this.counts(scope) };
    }

    isFullyClosed(scope?: Set<string>): boolean {
        const cells = this.cellsIn(scope);
        return cells.length > 0 && cells.every(c => c.status !== 'open');
    }

    gateProblems(scope?: Set<string>): GridGateProblems {
        const cells = this.cellsIn(scope);
        return {
            open: cells.filter(c => c.status === 'open').sort((a, b) => b.risk - a.risk),
            weak: cells
                .filter(c => c.status === 'safe' && c.risk >= HIGH_RISK && c.closure !== 'traced' && c.closure !== 'tested')
                .sort((a, b) => b.risk - a.risk),
        };
    }

    private lineOf(id: string | null): number | undefined {
        if (!id || !this.inventory) return undefined;
        if (!this.lineIndex) {
            const idx = new Map<string, number>();
            const inv = this.inventory;
            for (const list of [inv.entryPoints, inv.inputs, inv.sinks, inv.guards] as Array<Array<{ id: string; line: number }>>) {
                for (const item of list ?? []) {
                    if (item && typeof item.id === 'string' && Number.isInteger(item.line) && item.line > 0) idx.set(item.id, item.line);
                }
            }
            this.lineIndex = idx;
        }
        return this.lineIndex.get(id);
    }

    /** Lines a cell is anchored to: its entry point and target; the input line when neither is known. */
    cellLines(cell: GridCell): number[] {
        const lines = [this.lineOf(cell.entryId), this.lineOf(cell.targetId)].filter((n): n is number => typeof n === 'number');
        if (lines.length > 0) return lines;
        const input = this.lineOf(cell.inputId);
        return typeof input === 'number' ? [input] : [];
    }

    /** Cells for one part of a split file: anchored inside the range, or not anchored to any line. */
    scopeForRange(range: { startLine: number; endLine: number }): Set<string> {
        const scope = new Set<string>();
        for (const cell of this.cellList) {
            const lines = this.cellLines(cell);
            if (lines.length === 0 || lines.some(l => l >= range.startLine && l <= range.endLine)) scope.add(cell.id);
        }
        return scope;
    }

    toResult(scope?: Set<string>): AssuranceResult {
        const cells = this.cellsIn(scope).map(c => ({ ...c }));
        const ids = new Set(cells.map(c => c.id));
        return {
            cells,
            scenarios: this.scenarioList.filter(s => ids.has(s.cellId)).map(s => ({ ...s })),
            counts: this.counts(scope),
            redteamRounds: this.redteamRounds,
            attackTests: this.attackTests ? { ...this.attackTests } : null,
            warnings: [...this.warnings],
        };
    }

    snapshot(runId: string): GridSnapshot {
        return {
            version: 1,
            runId,
            file: this.inventory?.file ?? '',
            savedAt: new Date().toISOString(),
            cells: this.cells.map(c => ({ ...c, note: redact(c.note), dependsOn: redact(c.dependsOn) })).map(stripUndefined),
            scenarios: this.scenarios.map(s => ({ ...s, testNote: redact(s.testNote) })).map(stripUndefined),
            redteamRounds: this.redteamRounds,
            attackTests: this.attackTests,
            warnings: this.warnings.map(w => redactText(w)),
        };
    }

    /** Writes `.securecode/assurance/<runId>.json` (git-ignored); returns the path, or null on failure. */
    persist(workspaceRoot: string, runId: string): string | null {
        try {
            const dir = path.join(workspaceRoot, ASSURANCE_DIR);
            fs.mkdirSync(dir, { recursive: true });
            const ignoreFile = path.join(dir, '.gitignore');
            if (!fs.existsSync(ignoreFile)) {
                try { fs.writeFileSync(ignoreFile, '*\n', 'utf8'); } catch { /* best effort */ }
            }
            const file = path.join(dir, `${safeRunId(runId)}.json`);
            fs.writeFileSync(file, JSON.stringify(this.snapshot(runId), null, 1), 'utf8');
            return file;
        } catch (err: any) {
            console.warn(`[Assurance] Could not save grid state: ${err?.message || err}`);
            return null;
        }
    }

    static load(workspaceRoot: string, runId: string): GridState | null {
        try {
            const file = path.join(workspaceRoot, ASSURANCE_DIR, `${safeRunId(runId)}.json`);
            const data = JSON.parse(fs.readFileSync(file, 'utf8')) as Partial<GridSnapshot>;
            if (!data || data.version !== 1) return null;
            const grid = new GridState(data.cells ?? [], data.scenarios ?? []);
            grid.redteamRounds = typeof data.redteamRounds === 'number' ? data.redteamRounds : 0;
            grid.attackTests = data.attackTests ?? null;
            for (const w of data.warnings ?? []) grid.addWarning(String(w));
            return grid;
        } catch {
            return null;
        }
    }
}

function stripUndefined<T extends object>(o: T): T {
    for (const k of Object.keys(o) as Array<keyof T>) if (o[k] === undefined) delete o[k];
    return o;
}

