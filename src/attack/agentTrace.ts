/**
 * Agent trace — structured per-step event logging for agent scan runs.
 *
 * Every tool call, LLM call, blocked action, and verify round is recorded
 * as a structured event correlated by runId + stepIndex. Events are stored
 * locally in `.securecode/agent-runs/<runId>/events.jsonl` (one JSON per
 * line) for replay and debugging.
 *
 * Privacy: local tool observations and source code NEVER leave the machine.
 * The API logs metadata only (model, tokens, cost, latency, action type).
 *
 * Retention: 7 days or 20 runs per workspace, whichever is less.
 */

import * as fs from 'fs';
import * as path from 'path';

export type AgentEventType =
    | 'run_started'
    | 'step_requested'
    | 'action_selected'
    | 'tool_completed'
    | 'tool_blocked'
    | 'model_retry'
    | 'critique_completed'
    | 'verify_round'
    | 'finding_finalized'
    | 'run_completed';

export interface AgentTraceEvent {
    timestamp: string;
    runId: string;
    stepIndex: number;
    eventType: AgentEventType;
    /** Action type selected by the LLM (action_selected, tool_completed, tool_blocked). */
    actionType?: string;
    /** Tool observation (tool_completed only) — redacted + truncated. */
    observation?: string;
    /** Blocked reason (tool_blocked only). */
    blockedReason?: string;
    /** LLM metadata (step_requested, action_selected, model_retry). */
    model?: string;
    provider?: string;
    tokens?: number;
    costUsd?: number;
    latencyMs?: number;
    fallbackFired?: boolean;
    /** Verify round metadata (verify_round). */
    verifyRound?: number;
    verifyVerdict?: string;
    /** Finding metadata (finding_finalized). */
    findingType?: string;
    findingLine?: number;
    findingConfidence?: number;
    findingProven?: string;
    findingEvidenceLevel?: string;
    /** Run status (run_started, run_completed). */
    runStatus?: string;
    /** Error message (any event type). */
    error?: string;
}

const RUNS_DIR = '.securecode';
const MAX_RUN_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_RUNS_PER_WORKSPACE = 20;

function eventsFilePath(workspaceRoot: string, runId: string): string {
    return path.join(workspaceRoot, RUNS_DIR, 'agent-runs', runId, 'events.jsonl');
}

function ensureRunDir(workspaceRoot: string, runId: string): string {
    const dir = path.dirname(eventsFilePath(workspaceRoot, runId));
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

export class AgentTraceLogger {
    private workspaceRoot: string;
    private runId: string;
    private stepIndex: number = 0;
    private events: AgentTraceEvent[] = [];

    constructor(workspaceRoot: string, runId: string) {
        this.workspaceRoot = workspaceRoot;
        this.runId = runId;
        ensureRunDir(workspaceRoot, runId);
    }

    log(event: Omit<AgentTraceEvent, 'timestamp' | 'runId' | 'stepIndex'>): void {
        const fullEvent: AgentTraceEvent = {
            timestamp: new Date().toISOString(),
            runId: this.runId,
            stepIndex: this.stepIndex,
            ...event,
        };
        this.events.push(fullEvent);
        try {
            fs.appendFileSync(
                eventsFilePath(this.workspaceRoot, this.runId),
                JSON.stringify(fullEvent) + '\n',
                'utf8',
            );
        } catch { /* best-effort — tracing must never break the scan */ }
    }

    nextStep(): void {
        this.stepIndex++;
    }

    logRunStarted(): void {
        this.log({ eventType: 'run_started', runStatus: 'started' });
    }

    logStepRequested(model?: string, tokens?: number, costUsd?: number, latencyMs?: number): void {
        this.log({ eventType: 'step_requested', model, tokens, costUsd, latencyMs });
    }

    logActionSelected(actionType: string, model?: string, fallbackFired?: boolean): void {
        this.log({ eventType: 'action_selected', actionType, model, fallbackFired });
    }

    logToolCompleted(actionType: string, observation: string, latencyMs?: number): void {
        this.log({ eventType: 'tool_completed', actionType, observation: observation.slice(0, 2000), latencyMs });
    }

    logToolBlocked(actionType: string, reason: string): void {
        this.log({ eventType: 'tool_blocked', actionType, blockedReason: reason });
    }

    logModelRetry(error: string): void {
        this.log({ eventType: 'model_retry', error });
    }

    logCritiqueCompleted(verdict: string, issues: number): void {
        this.log({ eventType: 'critique_completed', error: `${verdict} (${issues} issues)` });
    }

    logVerifyRound(round: number, verdict: string): void {
        this.log({ eventType: 'verify_round', verifyRound: round, verifyVerdict: verdict });
    }

    logFindingFinalized(
        type: string, line: number, confidence: number, proven: string, evidenceLevel?: string,
    ): void {
        this.log({
            eventType: 'finding_finalized',
            findingType: type, findingLine: line, findingConfidence: confidence,
            findingProven: proven, findingEvidenceLevel: evidenceLevel,
        });
    }

    logRunCompleted(status: string): void {
        this.log({ eventType: 'run_completed', runStatus: status });
    }

    getEvents(): AgentTraceEvent[] {
        return [...this.events];
    }
}

export function readTraceEvents(workspaceRoot: string, runId: string): AgentTraceEvent[] {
    const filePath = eventsFilePath(workspaceRoot, runId);
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return content
            .split('\n')
            .filter(Boolean)
            .map(line => JSON.parse(line) as AgentTraceEvent);
    } catch {
        return [];
    }
}

export function listRecentRuns(workspaceRoot: string): { runId: string; createdAt: string; eventCount: number }[] {
    const runsDir = path.join(workspaceRoot, RUNS_DIR, 'agent-runs');
    if (!fs.existsSync(runsDir)) return [];

    const entries: { runId: string; createdAt: string; eventCount: number }[] = [];
    const now = Date.now();

    for (const dir of fs.readdirSync(runsDir)) {
        const filePath = path.join(runsDir, dir, 'events.jsonl');
        if (!fs.existsSync(filePath)) continue;

        const stat = fs.statSync(filePath);
        const ageMs = now - stat.mtimeMs;
        if (ageMs > MAX_RUN_AGE_MS) {
            try { fs.rmSync(path.join(runsDir, dir), { recursive: true, force: true }); } catch {}
            continue;
        }

        const lineCount = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean).length;
        entries.push({
            runId: dir,
            createdAt: new Date(stat.mtimeMs).toISOString(),
            eventCount: lineCount,
        });
    }

    entries.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    if (entries.length > MAX_RUNS_PER_WORKSPACE) {
        for (const e of entries.slice(MAX_RUNS_PER_WORKSPACE)) {
            try { fs.rmSync(path.join(runsDir, e.runId), { recursive: true, force: true }); } catch {}
        }
    }

    return entries.slice(0, MAX_RUNS_PER_WORKSPACE);
}

export function formatTraceForReplay(events: AgentTraceEvent[]): string {
    if (events.length === 0) return 'No events recorded.';

    const lines: string[] = [`Agent run replay (${events.length} events):`];
    let currentStep = -1;

    for (const e of events) {
        if (e.stepIndex !== currentStep) {
            currentStep = e.stepIndex;
            lines.push('');
            lines.push(`── Step ${currentStep} ──`);
        }

        switch (e.eventType) {
            case 'run_started':
                lines.push(`  [run_started] run started`);
                break;
            case 'step_requested':
                lines.push(`  [step_requested] model=${e.model || '?'} tokens=${e.tokens || 0} cost=$${(e.costUsd || 0).toFixed(4)} ${e.latencyMs || 0}ms`);
                break;
            case 'action_selected':
                lines.push(`  [action_selected] ${e.actionType} (model=${e.model || '?'}${e.fallbackFired ? ' FALLBACK' : ''})`);
                break;
            case 'tool_completed':
                lines.push(`  [tool_completed] ${e.actionType} → ${(e.observation || '').slice(0, 100)}...`);
                break;
            case 'tool_blocked':
                lines.push(`  [tool_blocked] ${e.actionType} — ${e.blockedReason}`);
                break;
            case 'model_retry':
                lines.push(`  [model_retry] ${e.error}`);
                break;
            case 'critique_completed':
                lines.push(`  [critique_completed] ${e.error}`);
                break;
            case 'verify_round':
                lines.push(`  [verify_round] round ${e.verifyRound} → ${e.verifyVerdict}`);
                break;
            case 'finding_finalized':
                lines.push(`  [finding_finalized] ${e.findingType} L${e.findingLine} conf=${e.findingConfidence} proven=${e.findingProven} evidence=${e.findingEvidenceLevel || '?'}`);
                break;
            case 'run_completed':
                lines.push(`  [run_completed] status=${e.runStatus}`);
                break;
        }
    }

    return lines.join('\n');
}
