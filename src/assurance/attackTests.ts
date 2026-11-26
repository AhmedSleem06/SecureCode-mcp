import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { CELL_UPDATE_LIMITS, clampCellUpdates, type CellUpdate, type GridCell, type Scenario } from '../attack/agentScanProtocol';
import { ApiClient } from '../api/client';
import type { VerifyAnalyzeResponse, VerifyGenerateResponse } from '../api/types';
import { ApprovalBroker, consumeSessionApproval, getSessionApproval, revokeSessionApproval, SESSION_APPROVAL_MAX_TESTS } from '../approval/broker';
import { runLocalTest, type LocalTestResult } from '../utils/localTestRunner';
import { detectRuntime, computeRelativeImportPath } from '../utils/runtimeDetect';
import { detectSandbox } from '../utils/verificationSandbox';
import { validateVerifyAnalyzeResponse, validateVerifyGenerateResponse } from '../attack/protocolValidator';
import { isAgentScanBudgetExhausted, VERIFY_BUDGET_EXHAUSTED_REASON } from '../attack/agentScanCredits';
import { saveProofArtifact, type ProofArtifactRound } from '../attack/proofArtifacts';
import { getRelatedFilesForFile } from '../project-map/mapContext';

export interface AssuranceAttackTestInput {
    ctx: ServerContext;
    runId: string;
    target: { filePath: string; language: string; fileContent: string };
    cells: GridCell[];
    scenarios: Scenario[];
    maxTests?: number;
    signal?: AbortSignal;
    progress?: (message: string) => void;
}

export interface AssuranceAttackTestOutcome {
    scenarioUpdates: { scenarioId: string; test: 'blocked' | 'exploited' | 'untestable' | 'skipped'; testNote: string; artifactPath?: string; backend?: string; isolation?: string; repeatable?: boolean }[];
    cellUpdates: CellUpdate[];
    exploitedFindings: { cellId: string; scenarioId: string; type: string; line: number; title: string; why: string; artifactPath?: string; observedType?: string; severity?: 'critical' | 'high' | 'medium' | 'low'; confidence?: number; repeatable?: boolean }[];
    approval: { granted: boolean; reason: string };
    costUsd: number;
    scenarioSummary?: { ran: number; repeatable: number; downgraded: number };
}

type ScenarioTestResult = AssuranceAttackTestOutcome['scenarioUpdates'][number]['test'];
type ScenarioVerdict = 'BLOCKED' | 'EXPLOITED' | 'UNTESTABLE';

export const ASSURANCE_DEFAULT_MAX_TESTS = 20;
export const ASSURANCE_MAX_SCENARIOS_PER_CELL = 3;
export const ASSURANCE_MAX_ATTEMPTS = 2;
export const ASSURANCE_APPROVAL_TTL_MS = 2 * 60 * 60 * 1000;
export const ASSURANCE_TEST_TIMEOUT_MS = 30_000;
export const ASSURANCE_DEFAULT_MAX_USD = 1.5;
export const ASSURANCE_CONSECUTIVE_UNTESTABLE_LIMIT = 3;
const NOTE_OUTPUT_CHARS = 300;
const TESTED_STATUSES = new Set(['blocked', 'exploited', 'untestable']);
const CLOSURE_STRENGTH: Record<string, number> = { untestable: 1, reasoning: 2, traced: 3, tested: 4 };

function getAssuranceMaxTests(): number {
    const env = process.env.SECURECODE_ASSURANCE_MAX_TESTS;
    if (env) { const n = Number(env); if (Number.isFinite(n) && n > 0) return Math.floor(n); }
    return ASSURANCE_DEFAULT_MAX_TESTS;
}

function getAssuranceMaxUsd(): number {
    const env = process.env.SECURECODE_ASSURANCE_TEST_USD;
    if (env) { const n = Number(env); if (Number.isFinite(n) && n > 0) return n; }
    return ASSURANCE_DEFAULT_MAX_USD;
}

function classifyFailure(result: ScenarioRunResult): string {
    if (result.test === 'untestable') {
        const note = result.note;
        if (/safety check|blocked/i.test(note)) return 'safety-check';
        if (/cannot find module|cannot resolve|module not found|import error/i.test(note)) return 'module-load';
        if (/no PASS\/FAIL|no.*result.*marker|printed no scenario/i.test(note)) return 'no-result-marker';
        const firstLine = note.split('\n')[0].slice(0, 120);
        return `crash:${firstLine}`;
    }
    return '';
}

export interface SelectedScenario {
    cell: GridCell;
    scenario: Scenario;
}

export interface ScenarioMarker {
    found: boolean;
    verdict: ScenarioVerdict | null;
    targetReached: boolean;
    mockedTarget: boolean;
    controlOk: boolean | null;
    reason: string;
}

function isEligibleCell(cell: GridCell): boolean {
    if (cell.closure === 'tested') return false;
    if (cell.status === 'vulnerable' || cell.status === 'not-applicable' || cell.status === 'open') return false;
    if (cell.status === 'safe' && cell.risk >= 3) return true;
    return cell.risk >= 4 && (cell.status === 'depends' || cell.closure === 'reasoning');
}

/**
 * Eligible cells sorted by risk (then weakest closure first); scenarios are taken breadth-first —
 * every cell's best scenario before any cell's second — up to 3 per cell and maxTests overall.
 */
export function selectAssuranceScenarios(cells: GridCell[], scenarios: Scenario[], maxTests = ASSURANCE_DEFAULT_MAX_TESTS): SelectedScenario[] {
    const limit = Math.max(0, Math.min(Math.floor(maxTests), SESSION_APPROVAL_MAX_TESTS));
    const order = new Map(cells.map((c, i) => [c.id, i]));
    const eligible = cells.filter(isEligibleCell).sort((a, b) =>
        (b.risk - a.risk)
        || ((CLOSURE_STRENGTH[a.closure ?? ''] ?? 0) - (CLOSURE_STRENGTH[b.closure ?? ''] ?? 0))
        || ((order.get(a.id) ?? 0) - (order.get(b.id) ?? 0)));
    const sIndex = new Map(scenarios.map((s, i) => [s, i]));
    const perCell = eligible.map((cell) => ({
        cell,
        list: scenarios
            .filter((s) => s.cellId === cell.id && !TESTED_STATUSES.has(s.test ?? '') && (s as any).classification !== 'hardening')
            .sort((a, b) => (b.risk - a.risk) || ((sIndex.get(a) ?? 0) - (sIndex.get(b) ?? 0)))
            .slice(0, ASSURANCE_MAX_SCENARIOS_PER_CELL),
    }));
    const out: SelectedScenario[] = [];
    const seen = new Set<string>();
    for (let tier = 0; tier < ASSURANCE_MAX_SCENARIOS_PER_CELL; tier++) {
        for (const { cell, list } of perCell) {
            if (out.length >= limit) return out;
            const scenario = list[tier];
            if (!scenario || seen.has(scenario.id)) continue;
            seen.add(scenario.id);
            out.push({ cell, scenario });
        }
    }
    return out;
}

const SCENARIO_MARKER_RE = /SECURECODE_SCENARIO_RESULT:(\{[\s\S]*?\}):SECURECODE_SCENARIO_END/g;

export function parseScenarioMarker(output: string): ScenarioMarker {
    const empty: ScenarioMarker = { found: false, verdict: null, targetReached: false, mockedTarget: false, controlOk: null, reason: '' };
    const matches = [...(output || '').matchAll(SCENARIO_MARKER_RE)];
    if (matches.length === 0) return empty;
    try {
        const raw = JSON.parse(matches[matches.length - 1][1]) as Record<string, unknown>;
        const v = typeof raw.verdict === 'string' ? raw.verdict.toUpperCase() : '';
        const verdict = v === 'BLOCKED' || v === 'EXPLOITED' || v === 'UNTESTABLE' ? v : null;
        return {
            found: verdict !== null,
            verdict,
            targetReached: raw.targetReached === true,
            mockedTarget: raw.mockedTarget === true,
            controlOk: typeof raw.controlOk === 'boolean' ? raw.controlOk : null,
            reason: typeof raw.reason === 'string' ? raw.reason.slice(0, 300) : '',
        };
    } catch {
        return empty;
    }
}

type AnalyzeWithScenario = VerifyAnalyzeResponse & { scenarioVerdict?: ScenarioVerdict; targetReached?: boolean; failureLine?: number | null; observedWeakness?: { type: string; severity: 'critical' | 'high' | 'medium' | 'low'; matchesCell: boolean; summary: string } | null };

/** The run's own marker and sandbox verdict must agree with the analyzer before BLOCKED/EXPLOITED is accepted. */
export function decideScenarioVerdict(
    analyze: AnalyzeWithScenario,
    run: Pick<LocalTestResult, 'verdict' | 'output'>,
): { verdict: ScenarioVerdict; reason: string; retryable: boolean } {
    const apiVerdict: ScenarioVerdict = analyze.scenarioVerdict
        ?? (analyze.verdict === 'PROVEN' ? 'EXPLOITED' : analyze.verdict === 'UNPROVEN' ? 'BLOCKED' : 'UNTESTABLE');
    if (apiVerdict === 'UNTESTABLE') return { verdict: 'UNTESTABLE', reason: analyze.reason, retryable: analyze.shouldRetry === true };
    const marker = parseScenarioMarker(run.output);
    if (!marker.found) return { verdict: 'UNTESTABLE', reason: `test printed no scenario result marker (${analyze.reason})`, retryable: true };
    if (!marker.targetReached || analyze.targetReached === false || marker.mockedTarget) {
        return { verdict: 'UNTESTABLE', reason: `test did not reach the real target code (${analyze.reason})`, retryable: true };
    }
    if (marker.controlOk === false) return { verdict: 'UNTESTABLE', reason: `control step failed (${analyze.reason})`, retryable: true };
    if (marker.verdict !== apiVerdict) {
        return { verdict: 'UNTESTABLE', reason: `test result ${marker.verdict} disagrees with analysis ${apiVerdict} (${analyze.reason})`, retryable: true };
    }
    const expectedRun = apiVerdict === 'EXPLOITED' ? 'pass' : 'fail';
    if (run.verdict !== expectedRun) {
        return { verdict: 'UNTESTABLE', reason: `sandbox verdict ${run.verdict} disagrees with ${apiVerdict} (${analyze.reason})`, retryable: true };
    }
    return { verdict: apiVerdict, reason: analyze.reason, retryable: false };
}

interface ScenarioRunResult {
    test: ScenarioTestResult;
    note: string;
    failureLine: number | null;
    observedWeakness?: { type: string; severity: 'critical' | 'high' | 'medium' | 'low'; matchesCell: boolean; summary: string } | null;
    rounds: ProofArtifactRound[];
    stop?: 'budget' | 'sandbox' | 'cancelled';
    repeatable?: boolean;
}

interface RunEnv {
    input: AssuranceAttackTestInput;
    client: ApiClient;
    runtimeInfo: ReturnType<typeof detectRuntime>;
    relativeImportPath: string;
    sandboxBackend?: string;
    sandboxIsolation?: string;
    relatedFiles: Array<{ filePath: string; content: string; relationship: string }>;
    addCost: (usd: unknown) => void;
    consumeGrant: () => boolean;
}

function snippet(text: string): string {
    const t = (text || '').replace(/\s+/g, ' ').trim();
    return t.length > NOTE_OUTPUT_CHARS ? t.slice(0, NOTE_OUTPUT_CHARS) + '…' : t;
}

function focusLines(cell: GridCell): { line: number; lineEnd?: number } {
    const lines = (cell.evidenceLines ?? []).filter((n) => Number.isInteger(n) && n > 0);
    if (lines.length === 0) return { line: 1 };
    const line = Math.min(...lines);
    const end = Math.max(...lines);
    return end > line ? { line, lineEnd: end } : { line };
}

function cellEvidenceText(cell: GridCell): string {
    const parts = [`Grid cell ${cell.id}: ${cell.title}`, `attack type ${cell.attackType}`];
    if (cell.entryId) parts.push(`entry ${cell.entryId}`);
    if (cell.inputId) parts.push(`input ${cell.inputId}`);
    if (cell.targetId) parts.push(`target ${cell.targetId}`);
    if (cell.evidenceLines?.length) parts.push(`relevant lines ${cell.evidenceLines.join(', ')}`);
    return parts.join('; ');
}

function cellNotes(cell: GridCell): string {
    return [cell.note ? `Review note: ${cell.note}` : '', cell.dependsOn ? `Depends on: ${cell.dependsOn}` : ''].filter(Boolean).join('\n');
}

async function runScenarioTest(env: RunEnv, cell: GridCell, scenario: Scenario): Promise<ScenarioRunResult> {
    const { input, client, runtimeInfo } = env;
    const { line, lineEnd } = focusLines(cell);
    const rounds: ProofArtifactRound[] = [];
    const previousErrors: string[] = [];
    const scenarioBody = {
        id: scenario.id,
        actor: scenario.actor,
        preconditions: scenario.preconditions,
        steps: scenario.steps,
        payloads: scenario.payloads,
        expectSecure: scenario.expectSecure,
    };
    const evidence = cellEvidenceText(cell);
    const why = cellNotes(cell);
    let lastNote = 'test could not be run';

    for (let attempt = 1; attempt <= ASSURANCE_MAX_ATTEMPTS; attempt++) {
        if (input.signal?.aborted) return { test: 'skipped', note: 'Cancelled before the attack test finished.', failureLine: null, rounds, stop: 'cancelled' };

        let genRaw: VerifyGenerateResponse;
        try {
            genRaw = await client.postJson<VerifyGenerateResponse>('/verify/generate', {
                code: input.target.fileContent,
                language: input.target.language,
                vulnerabilityType: cell.attackType,
                line,
                ...(lineEnd ? { lineEnd } : {}),
                evidence,
                why,
                filePath: input.target.filePath,
                relatedFiles: env.relatedFiles,
                previousErrors: previousErrors.length > 0 ? previousErrors : undefined,
                projectRuntime: runtimeInfo.runtime,
                suggestedRunner: runtimeInfo.runner,
                framework: runtimeInfo.framework,
                frameworkVersion: runtimeInfo.frameworkVersion,
                testabilityTier: runtimeInfo.testabilityTier,
                packageManager: runtimeInfo.packageManager,
                testFileDir: '.securecode',
                relativeImportPath: env.relativeImportPath,
                depsInstalled: runtimeInfo.depsInstalled,
                verificationPhase: 'original',
                mode: 'expect-blocked',
                scenario: scenarioBody,
                ...(env.sandboxBackend ? { sandboxBackend: env.sandboxBackend } : {}),
                runId: input.runId,
            }, input.signal);
        } catch (err) {
            return apiFailure(err, rounds, input.signal);
        }
        env.addCost(genRaw?.costUsd);

        const gen = validateVerifyGenerateResponse(genRaw);
        if (!gen.ok) {
            lastNote = `test generation returned an invalid response: ${gen.error}`;
            previousErrors.push(`Attempt ${attempt}: ${lastNote}`);
            continue;
        }
        if (!gen.value.canTest || !gen.value.testScript) {
            return { test: 'untestable', note: `Cannot test in the sandbox: ${gen.value.skipReason || 'no test could be generated'}`, failureLine: null, rounds };
        }

        const testScript = gen.value.testScript;
        const setupScript = gen.value.setupScript || '';
        const runner = gen.value.runner || runtimeInfo.runner || (input.target.language === 'typescript' ? 'tsx' : 'node');
        input.progress?.(`Attack test ${scenario.id}: running in the sandbox (attempt ${attempt})...`);
        const run = await runLocalTest(testScript, runner, input.ctx.workspaceRoot, {
            setupScript: setupScript || null,
            timeoutMs: ASSURANCE_TEST_TIMEOUT_MS,
            signal: input.signal,
        });
        rounds.push({ round: attempt, testScript, setupScript, runner, verdict: run.verdict, output: run.output });

        if (run.verdict === 'sandbox-unavailable') {
            return { test: 'skipped', note: 'No sandbox is available to run attack tests.', failureLine: null, rounds, stop: 'sandbox' };
        }
        if (run.verdict === 'cancelled') {
            return { test: 'skipped', note: 'Cancelled before the attack test finished.', failureLine: null, rounds, stop: 'cancelled' };
        }
        if (run.verdict === 'blocked' || run.verdict === 'timeout' || run.verdict === 'error') {
            const what = run.verdict === 'blocked' ? 'was rejected by the static safety check'
                : run.verdict === 'timeout' ? 'timed out'
                : 'crashed or printed no PASS/FAIL line';
            lastNote = `test harness ${what}: ${snippet(run.output)}`;
            previousErrors.push(`Attempt ${attempt}: the test ${what}. Output: ${run.output.slice(0, 600)}`);
            continue;
        }

        input.progress?.(`Attack test ${scenario.id}: analysing the result...`);
        let anRaw: VerifyAnalyzeResponse;
        try {
            anRaw = await client.postJson<VerifyAnalyzeResponse>('/verify/analyze', {
                vulnerabilityType: cell.attackType,
                line,
                evidence,
                why,
                testScript,
                stdout: run.output,
                stderr: '',
                exitCode: run.exitCode,
                round: attempt,
                maxRounds: ASSURANCE_MAX_ATTEMPTS,
                verificationPhase: 'original',
                mode: 'expect-blocked',
                scenario: scenarioBody,
                targetCode: input.target.fileContent,
                filePath: input.target.filePath,
                runId: input.runId,
            }, input.signal);
        } catch (err) {
            return apiFailure(err, rounds, input.signal);
        }
        env.addCost(anRaw?.costUsd);

        const an = validateVerifyAnalyzeResponse(anRaw);
        if (!an.ok) {
            lastNote = `result analysis returned an invalid response: ${an.error}`;
            continue;
        }
        const analyze = an.value as AnalyzeWithScenario;
        const decision = decideScenarioVerdict(analyze, run);
        const lastRound = rounds[rounds.length - 1];
        lastRound.verdict = `${run.verdict}:${decision.verdict}`;
        if (decision.verdict === 'BLOCKED') {
            return { test: 'blocked', note: `Attack test blocked: ${decision.reason}`, failureLine: null, rounds };
        }
        if (decision.verdict === 'EXPLOITED') {
            const fl = typeof analyze.failureLine === 'number' && Number.isInteger(analyze.failureLine) ? analyze.failureLine : null;
            const ow = analyze.observedWeakness && typeof analyze.observedWeakness === 'object' ? analyze.observedWeakness : null;
            if (!env.consumeGrant()) {
                return { test: 'exploited', note: `Attack test exploited: ${decision.reason}`, failureLine: fl, observedWeakness: ow, rounds, repeatable: false };
            }
            const repeatRun = await runLocalTest(testScript, runner, input.ctx.workspaceRoot, {
                setupScript: setupScript || null,
                timeoutMs: ASSURANCE_TEST_TIMEOUT_MS,
                signal: input.signal,
            });
            rounds.push({ round: attempt + 0.5, testScript, setupScript, runner, verdict: repeatRun.verdict, output: repeatRun.output });
            const repeatMarker = parseScenarioMarker(repeatRun.output);
            const repeatAgreed = repeatMarker.found
                && repeatMarker.verdict === 'EXPLOITED'
                && repeatMarker.targetReached
                && !repeatMarker.mockedTarget
                && repeatRun.verdict === 'pass';
            if (repeatAgreed) {
                return { test: 'exploited', note: `Attack test exploited: ${decision.reason}`, failureLine: fl, observedWeakness: ow, rounds, repeatable: true };
            }
            return { test: 'untestable', note: `Attack test could not exercise the code: not repeatable`, failureLine: null, rounds, repeatable: false };
        }
        lastNote = decision.reason;
        if (!decision.retryable) break;
        previousErrors.push(`Attempt ${attempt}: result was UNTESTABLE — ${decision.reason}. Output: ${run.output.slice(0, 600)}`);
    }
    return { test: 'untestable', note: `Attack test could not exercise the code: ${lastNote}`, failureLine: null, rounds };
}

function apiFailure(err: unknown, rounds: ProofArtifactRound[], signal?: AbortSignal): ScenarioRunResult {
    if (isAgentScanBudgetExhausted(err)) {
        return { test: 'skipped', note: `Attack test skipped: ${VERIFY_BUDGET_EXHAUSTED_REASON}`, failureLine: null, rounds, stop: 'budget' };
    }
    if (signal?.aborted) return { test: 'skipped', note: 'Cancelled before the attack test finished.', failureLine: null, rounds, stop: 'cancelled' };
    const msg = err instanceof Error ? err.message : String(err);
    return { test: 'skipped', note: `Attack test skipped: API error (${snippet(msg)})`, failureLine: null, rounds };
}

function clip(text: string): string {
    return text.length > CELL_UPDATE_LIMITS.noteMaxChars ? text.slice(0, CELL_UPDATE_LIMITS.noteMaxChars - 1) + '…' : text;
}

export function buildAssuranceCellUpdates(
    cells: GridCell[],
    results: Array<{ cell: GridCell; scenario: Scenario; test: ScenarioTestResult; note: string; line?: number; observedWeakness?: ScenarioRunResult['observedWeakness'] }>,
): CellUpdate[] {
    const byCell = new Map<string, typeof results>();
    for (const r of results) {
        if (r.test === 'skipped') continue;
        const list = byCell.get(r.cell.id) ?? [];
        list.push(r);
        byCell.set(r.cell.id, list);
    }
    const updates: CellUpdate[] = [];
    for (const [cellId, list] of byCell) {
        const cell = list[0].cell;
        const matchingExploited = list.filter((r) => r.test === 'exploited' && r.observedWeakness?.matchesCell !== false);
        const mismatchExploited = list.filter((r) => r.test === 'exploited' && r.observedWeakness?.matchesCell === false);
        const blocked = list.filter((r) => r.test === 'blocked');
        const untestable = list.filter((r) => r.test === 'untestable');
        const ids = (rs: typeof list) => rs.map((r) => r.scenario.id).join(', ');
        if (matchingExploited.length > 0) {
            const lines = [...new Set(matchingExploited.map((r) => r.line).filter((n): n is number => typeof n === 'number' && n > 0))];
            updates.push({
                cellId,
                status: 'vulnerable',
                closure: 'tested',
                ...(lines.length > 0 ? { evidenceLines: lines } : cell.evidenceLines?.length ? { evidenceLines: cell.evidenceLines } : {}),
                note: clip(`Attack test exploited (scenario ${ids(matchingExploited)}): ${matchingExploited[0].note.replace(/^Attack test exploited:\s*/, '')}`),
            });
        } else if (blocked.length > 0) {
            const extra = untestable.length > 0 ? `; untestable: ${ids(untestable)}` : '';
            const mismatch = mismatchExploited.length > 0 ? `; mismatched exploit: ${ids(mismatchExploited)}` : '';
            updates.push({
                cellId,
                status: 'safe',
                closure: 'tested',
                ...(cell.evidenceLines?.length ? { evidenceLines: cell.evidenceLines } : {}),
                note: clip(`Attack test blocked (scenario ${ids(blocked)}${extra}${mismatch}): ${blocked[0].note.replace(/^Attack test blocked:\s*/, '')}`),
            });
        } else if (mismatchExploited.length > 0) {
            // exploited a different weakness than what the cell describes — do not mark vulnerable
        } else if (untestable.length > 0 && (!cell.closure || cell.closure === 'untestable') && cell.status !== 'depends') {
            updates.push({
                cellId,
                status: 'untestable',
                closure: 'untestable',
                note: clip(`Attack test could not run (scenario ${ids(untestable)}): ${untestable[0].note.replace(/^Attack test could not exercise the code:\s*/, '')}`),
            });
        }
    }
    return clampCellUpdates(updates, new Set(cells.map((c) => c.id)));
}

function relativeTarget(workspaceRoot: string, filePath: string): string {
    const abs = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
    return path.relative(workspaceRoot, abs).split(path.sep).join('/') || filePath;
}

export async function runAssuranceAttackTests(input: AssuranceAttackTestInput): Promise<AssuranceAttackTestOutcome> {
    const outcome: AssuranceAttackTestOutcome = {
        scenarioUpdates: [],
        cellUpdates: [],
        exploitedFindings: [],
        approval: { granted: false, reason: '' },
        costUsd: 0,
    };
    const { ctx, runId, target } = input;
    const selected = selectAssuranceScenarios(input.cells, input.scenarios, input.maxTests ?? getAssuranceMaxTests());
    if (selected.length === 0) {
        outcome.approval.reason = 'No attack tests needed: no eligible scenarios.';
        return outcome;
    }

    const fileRel = relativeTarget(ctx.workspaceRoot, target.filePath);
    const runtimeInfo = detectRuntime(ctx.workspaceRoot, target.filePath || undefined);
    const sandbox = detectSandbox();

    const results: Array<{ cell: GridCell; scenario: Scenario; test: ScenarioTestResult; note: string; line?: number; artifactPath?: string; observedWeakness?: ScenarioRunResult['observedWeakness']; repeatable?: boolean }> = [];
    const finalize = (): AssuranceAttackTestOutcome => {
        const backend = sandbox?.name;
        const isolation = backend === 'docker' ? 'full' : (backend === 'local' ? 'reduced' : undefined);
        outcome.scenarioUpdates = results.map((r) => ({
            scenarioId: r.scenario.id,
            test: r.test,
            testNote: r.note,
            ...(r.artifactPath ? { artifactPath: r.artifactPath } : {}),
            ...(backend ? { backend } : {}),
            ...(isolation ? { isolation } : {}),
            ...(typeof r.repeatable === 'boolean' ? { repeatable: r.repeatable } : {}),
        }));
        outcome.cellUpdates = buildAssuranceCellUpdates(input.cells, results);
        outcome.costUsd = Math.round(outcome.costUsd * 1e6) / 1e6;
        const tested = results.filter((r) => r.test !== 'skipped');
        const repeatableCount = results.filter((r) => r.repeatable === true).length;
        const downgradedCount = results.filter((r) => r.repeatable === false).length;
        if (tested.length > 0) {
            outcome.scenarioSummary = { ran: tested.length, repeatable: repeatableCount, downgraded: downgradedCount };
        }
        return outcome;
    };
    const markRest = (from: number, test: ScenarioTestResult, note: string) => {
        for (const { cell, scenario } of selected.slice(from)) results.push({ cell, scenario, test, note });
    };

    if (!runtimeInfo.canRunLocally) {
        const why = runtimeInfo.skipReason || 'this file cannot run in the local sandbox';
        outcome.approval.reason = `Not requested: ${why}`;
        markRest(0, 'untestable', `Cannot test in the sandbox: ${why}`);
        return finalize();
    }
    if (!sandbox) {
        outcome.approval.reason = 'Not requested: no sandbox is available.';
        markRest(0, 'skipped', 'Attack test skipped: no sandbox is available.');
        return finalize();
    }
    if (input.signal?.aborted) {
        outcome.approval.reason = 'Not requested: scan cancelled.';
        markRest(0, 'skipped', 'Cancelled before attack tests started.');
        return finalize();
    }

    const broker = new ApprovalBroker();
    let brokerStarted = false;
    try {
        try {
            await broker.start();
            brokerStarted = true;
        } catch {
            brokerStarted = false;
        }
        const backendLabel = sandbox.name;
        const isDocker = backendLabel === 'docker';
        const summary = isDocker
            ? `Run up to ${selected.length} attack tests for ${fileRel} in the Docker sandbox.`
            : `Docker not found — run up to ${selected.length} attack tests for ${fileRel} in local mode on this PC (copy of the project, no secrets, network blocked, lower isolation).`;
        const approval = await broker.requestSessionApproval(
            { runId, tool: 'assurance-tests', maxTests: selected.length, ttlMs: ASSURANCE_APPROVAL_TTL_MS },
            summary,
            {
                workspaceRoot: ctx.workspaceRoot,
                onUrl: (url) => input.progress?.(`⏸ Approval required for ${selected.length} attack test(s) on ${fileRel} — open ${url}`),
            },
        );
        if (brokerStarted) {
            await broker.stop().catch(() => undefined);
            brokerStarted = false;
        }
        outcome.approval = { granted: approval.granted, reason: approval.reason };
        if (!approval.granted) {
            markRest(0, 'skipped', approval.reason);
            return finalize();
        }

        const testFileDir = path.join(ctx.workspaceRoot, '.securecode');
        const absTarget = path.isAbsolute(target.filePath) ? target.filePath : path.join(ctx.workspaceRoot, target.filePath);
        let relatedFiles: RunEnv['relatedFiles'] = [];
        try {
            relatedFiles = (await getRelatedFilesForFile(absTarget, ctx.workspaceRoot)).slice(0, 3).map((rf) => ({
                filePath: rf.filePath,
                content: String(rf.content ?? '').slice(0, 8000),
                relationship: rf.relationship,
            }));
        } catch {
            relatedFiles = [];
        }
        const sandboxIsolation = backendLabel === 'docker' ? 'full' : backendLabel.includes('reduced') ? 'reduced' : (backendLabel === 'local' ? 'reduced' : 'full');
        const env: RunEnv = {
            input,
            client: new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken }),
            runtimeInfo,
            relativeImportPath: computeRelativeImportPath(testFileDir, absTarget, runtimeInfo.runner),
            sandboxBackend: sandbox.name,
            sandboxIsolation,
            relatedFiles,
            addCost: (usd) => {
                if (typeof usd === 'number' && Number.isFinite(usd) && usd > 0) outcome.costUsd += usd;
            },
            consumeGrant: () => consumeSessionApproval(runId),
        };
        const fileLines = target.fileContent.split('\n').length;
        const maxUsd = getAssuranceMaxUsd();
        let consecutiveUntestable = 0;
        let lastFailureClass = '';

        for (let i = 0; i < selected.length; i++) {
            const { cell, scenario } = selected[i];
            if (input.signal?.aborted) {
                markRest(i, 'skipped', 'Cancelled before the attack test ran.');
                break;
            }
            if (!consumeSessionApproval(runId)) {
                markRest(i, 'skipped', getSessionApproval(runId).reason);
                break;
            }
            if (outcome.costUsd >= maxUsd) {
                markRest(i, 'skipped', `Attack test budget reached ($${maxUsd.toFixed(2)}).`);
                break;
            }
            input.progress?.(`Attack test ${i + 1}/${selected.length}: scenario ${scenario.id} on ${cell.title} (risk ${cell.risk})`);
            const r = await runScenarioTest(env, cell, scenario);
            const line = r.failureLine && r.failureLine <= fileLines ? r.failureLine : focusLines(cell).line;
            let artifactPath: string | undefined;
            if (r.rounds.length > 0) {
                artifactPath = saveProofArtifact(ctx.workspaceRoot, {
                    proofId: `assurance-${runId}-${scenario.id}-${Date.now()}`,
                    createdAt: new Date().toISOString(),
                    phase: 'assurance',
                    finding: { file: target.filePath, line, type: cell.attackType, severity: `risk-${cell.risk}` },
                    scenario: { id: scenario.id, cellId: cell.id, actor: scenario.actor, steps: scenario.steps, expectSecure: scenario.expectSecure },
                    rounds: r.rounds,
                    proofGate: null,
                    mutation: null,
                    finalVerdict: r.test.toUpperCase(),
                    finalReason: r.note,
                    backend: env.sandboxBackend,
                    isolation: env.sandboxIsolation,
                }) ?? undefined;
            }
            results.push({ cell, scenario, test: r.test, note: r.note, line, ...(artifactPath ? { artifactPath } : {}), ...(r.observedWeakness ? { observedWeakness: r.observedWeakness } : {}), ...(typeof r.repeatable === 'boolean' ? { repeatable: r.repeatable } : {}) });
            if (r.test === 'exploited') {
                consecutiveUntestable = 0;
                lastFailureClass = '';
                const ow = r.observedWeakness;
                outcome.exploitedFindings.push({
                    cellId: cell.id,
                    scenarioId: scenario.id,
                    type: cell.attackType,
                    line,
                    title: cell.title,
                    why: `Attack scenario ${scenario.id} (${scenario.actor}): ${scenario.steps.join(' → ')}. Expected: ${scenario.expectSecure}. ${r.note}`.slice(0, 1500),
                    ...(artifactPath ? { artifactPath } : {}),
                    ...(ow ? { observedType: ow.type, severity: ow.severity, confidence: 85 } : {}),
                    ...(typeof r.repeatable === 'boolean' ? { repeatable: r.repeatable } : {}),
                });
            } else if (r.test === 'blocked') {
                consecutiveUntestable = 0;
                lastFailureClass = '';
            } else if (r.test === 'untestable') {
                const cls = classifyFailure(r);
                if (cls && cls === lastFailureClass) {
                    consecutiveUntestable++;
                } else {
                    consecutiveUntestable = cls ? 1 : 0;
                    lastFailureClass = cls;
                }
                if (consecutiveUntestable >= ASSURANCE_CONSECUTIVE_UNTESTABLE_LIMIT) {
                    markRest(i + 1, 'skipped', `Stopped: the previous ${ASSURANCE_CONSECUTIVE_UNTESTABLE_LIMIT} tests failed the same way (${lastFailureClass}).`);
                    break;
                }
            } else {
                consecutiveUntestable = 0;
                lastFailureClass = '';
            }
            if (r.stop) {
                const note = r.stop === 'budget' ? `Attack test skipped: ${VERIFY_BUDGET_EXHAUSTED_REASON}`
                    : r.stop === 'sandbox' ? 'Attack test skipped: no sandbox is available.'
                    : 'Cancelled before the attack test ran.';
                markRest(i + 1, 'skipped', note);
                break;
            }
        }
        return finalize();
    } finally {
        revokeSessionApproval(runId);
        if (brokerStarted) await broker.stop().catch(() => undefined);
    }
}
