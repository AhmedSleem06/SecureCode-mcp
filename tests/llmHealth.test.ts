import { describe, it, expect } from 'vitest';
import {
    createLlmHealthMonitor,
    DEFAULT_LLM_HEALTH_CONFIG,
} from '../src/attack/llmHealth';

function recordActions(monitor: ReturnType<typeof createLlmHealthMonitor>, fps: string[]) {
    for (const fp of fps) monitor.recordModelAction(fp);
}

const A = 'read_file:src/a.ts:1:50';
const B = 'read_config:all';

describe('createLlmHealthMonitor', () => {
    it('healthy varied action stream never trips', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [
            'read_file:src/a.ts:1:50',
            'search_code:auth',
            'trace_flow:src/a.ts',
            'read_file:src/b.ts:1:30',
            'check_guard:session',
            'get_endpoints:*.ts',
            'read_config:rate_limit',
            'finish:',
        ]);
        expect(m.evaluate().tripped).toBe(false);
    });

    it('trips on A/B alternation — the read_config <-> read_file pathology', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [A, B, A, B, A, B]);
        const trip = m.evaluate();
        expect(trip.tripped).toBe(true);
        expect(trip.signal).toBe('alternation');
        expect(trip.detail).toContain(A);
    });

    it('alternation requires 2 full cycles (A,B,A,B alone is not enough)', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [A, B, A, B]);
        const trip = m.evaluate();
        expect(trip.tripped).toBe(false);
    });

    it('identical repeat bursts do NOT trip — the blocked-read machinery owns repeats', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [A, A, A, A, A, A, A, A]);
        const trip = m.evaluate();
        expect(trip.tripped).toBe(false);
    });

    it('does not evaluate action tripwires before minActions', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [A, B, A, B, A]);
        expect(m.evaluate().tripped).toBe(false);
    });

    it('alternation interleaved with one-off actions still trips when the window holds 2 cycles', () => {
        const m = createLlmHealthMonitor();
        // window of 8: the A/B alternation starts at index 1, not 0
        recordActions(m, ['search_code:auth', A, B, A, B, A, B, 'trace_flow:src/a.ts']);
        const trip = m.evaluate();
        expect(trip.tripped).toBe(true);
        expect(trip.signal).toBe('alternation');
    });

    it('old actions slide out of the window — recovery is automatic', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [A, B, A, B, A, B, 'search_code:auth', 'trace_flow:src/a.ts', 'check_guard:session']);
        // The A,B alternation slid out — no trip
        const trip = m.evaluate();
        expect(trip.tripped).toBe(false);
    });

    it('trips on a sustained degraded/fallback streak', () => {
        const m = createLlmHealthMonitor();
        for (let i = 0; i < DEFAULT_LLM_HEALTH_CONFIG.degradedStreakLimit; i++) {
            m.recordStepTelemetry(true);
        }
        const trip = m.evaluate();
        expect(trip.tripped).toBe(true);
        expect(trip.signal).toBe('degraded-streak');
    });

    it('degraded streak resets on a healthy step', () => {
        const m = createLlmHealthMonitor();
        for (let i = 0; i < DEFAULT_LLM_HEALTH_CONFIG.degradedStreakLimit - 1; i++) {
            m.recordStepTelemetry(true);
        }
        m.recordStepTelemetry(false);
        m.recordStepTelemetry(true);
        expect(m.evaluate().tripped).toBe(false);
    });

    it('a tripped monitor stays tripped (terminal decision)', () => {
        const m = createLlmHealthMonitor();
        recordActions(m, [A, B, A, B, A, B]);
        expect(m.evaluate().tripped).toBe(true);
        // Even after "healthy" actions, evaluate must keep reporting the trip
        m.recordModelAction('search_code:auth');
        expect(m.evaluate().tripped).toBe(true);
        expect(m.evaluate().signal).toBe('alternation');
    });

    it('respects custom config overrides', () => {
        const m = createLlmHealthMonitor({ alternationCycles: 1, minActions: 4 });
        recordActions(m, [A, B, A, B]);
        const trip = m.evaluate();
        expect(trip.tripped).toBe(true);
        expect(trip.signal).toBe('alternation');
    });
});
