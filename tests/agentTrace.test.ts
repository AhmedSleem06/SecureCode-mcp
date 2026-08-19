import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { AgentTraceLogger, readTraceEvents, listRecentRuns, formatTraceForReplay } from '../src/attack/agentTrace';

const TMP_DIR = path.join(__dirname, '..', '.tmp-trace-test');
const WORKSPACE = path.join(TMP_DIR, 'ws');

beforeAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true });
    fs.mkdirSync(WORKSPACE, { recursive: true });
});

afterAll(() => {
    try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}
});

describe('AgentTraceLogger', () => {
    it('writes events to .securecode/agent-runs/<runId>/events.jsonl', () => {
        const logger = new AgentTraceLogger(WORKSPACE, 'run-1');
        logger.logRunStarted();
        logger.logActionSelected('read_file');
        logger.logToolCompleted('read_file', 'File content here');
        logger.logRunCompleted('completed');

        const events = readTraceEvents(WORKSPACE, 'run-1');
        expect(events.length).toBe(4);
        expect(events[0].eventType).toBe('run_started');
        expect(events[1].eventType).toBe('action_selected');
        expect(events[1].actionType).toBe('read_file');
        expect(events[2].eventType).toBe('tool_completed');
        expect(events[3].eventType).toBe('run_completed');
    });

    it('increments stepIndex correctly', () => {
        const logger = new AgentTraceLogger(WORKSPACE, 'run-2');
        logger.logRunStarted();
        logger.nextStep();
        logger.logActionSelected('search_code');
        logger.nextStep();
        logger.logActionSelected('trace_flow');

        const events = readTraceEvents(WORKSPACE, 'run-2');
        expect(events[0].stepIndex).toBe(0);
        expect(events[1].stepIndex).toBe(1);
        expect(events[2].stepIndex).toBe(2);
    });

    it('truncates long observations to 2000 chars', () => {
        const logger = new AgentTraceLogger(WORKSPACE, 'run-3');
        const longObs = 'x'.repeat(5000);
        logger.logToolCompleted('read_file', longObs);

        const events = readTraceEvents(WORKSPACE, 'run-3');
        expect(events[0].observation!.length).toBe(2000);
    });

    it('records all event types', () => {
        const logger = new AgentTraceLogger(WORKSPACE, 'run-4');
        logger.logRunStarted();
        logger.logStepRequested('GLM-5.2', 500, 0.01, 2000);
        logger.logActionSelected('check_guard', 'GLM-5.2', false);
        logger.logToolBlocked('read_file', 'already read');
        logger.logModelRetry('parse error');
        logger.logCritiqueCompleted('reject', 2);
        logger.logVerifyRound(1, 'PROVEN');
        logger.logFindingFinalized('sql_injection', 42, 85, 'PROVEN', 'taint-traced+verified');
        logger.logRunCompleted('completed');

        const events = readTraceEvents(WORKSPACE, 'run-4');
        expect(events.length).toBe(9);
        expect(events.map(e => e.eventType)).toEqual([
            'run_started', 'step_requested', 'action_selected', 'tool_blocked',
            'model_retry', 'critique_completed', 'verify_round', 'finding_finalized', 'run_completed',
        ]);
    });

    it('returns empty array for non-existent run', () => {
        const events = readTraceEvents(WORKSPACE, 'nonexistent');
        expect(events).toEqual([]);
    });
});

describe('listRecentRuns', () => {
    it('lists runs sorted by creation date (newest first)', () => {
        const logger1 = new AgentTraceLogger(WORKSPACE, 'list-run-1');
        logger1.logRunStarted();
        const logger2 = new AgentTraceLogger(WORKSPACE, 'list-run-2');
        logger2.logRunStarted();

        const runs = listRecentRuns(WORKSPACE);
        expect(runs.length).toBeGreaterThanOrEqual(2);
        expect(runs[0].runId).toBe('list-run-2');
    });

    it('returns empty for workspace with no runs', () => {
        const emptyWs = path.join(TMP_DIR, 'empty');
        fs.mkdirSync(emptyWs, { recursive: true });
        const runs = listRecentRuns(emptyWs);
        expect(runs).toEqual([]);
    });
});

describe('formatTraceForReplay', () => {
    it('produces a readable replay from events', () => {
        const logger = new AgentTraceLogger(WORKSPACE, 'replay-run');
        logger.logRunStarted();
        logger.nextStep();
        logger.logActionSelected('read_file');
        logger.logToolCompleted('read_file', 'const x = 1');
        logger.nextStep();
        logger.logActionSelected('finish');
        logger.logRunCompleted('completed');

        const events = readTraceEvents(WORKSPACE, 'replay-run');
        const replay = formatTraceForReplay(events);
        expect(replay).toContain('Step 0');
        expect(replay).toContain('Step 1');
        expect(replay).toContain('action_selected');
        expect(replay).toContain('read_file');
        expect(replay).toContain('tool_completed');
        expect(replay).toContain('run_completed');
    });

    it('handles empty events', () => {
        const replay = formatTraceForReplay([]);
        expect(replay).toContain('No events');
    });
});
