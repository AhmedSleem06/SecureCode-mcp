/**
 * LLM health monitor — detects degraded-model behavior that the
 * consecutive-blocked-read counters provably miss.
 *
 * Scope (deliberately narrow — the blocked-read machinery already owns
 * pure repeats):
 *
 *   1. A/B alternation — the model ping-pongs between two actions
 *      (read_config:all <-> read_file) where each action often executes
 *      or resets recovery counters, so blocked-read accounting never
 *      accumulates. Observed in production (synara audit, 2026-09-30):
 *      scans burned 16-29 steps oscillating before dying.
 *
 *   2. Provider degraded streak — the API reports degraded/fallback
 *      serving for many consecutive steps (both primary and fallback
 *      struggling).
 *
 * NOT covered here on purpose: identical repeat bursts. The loop already
 * blocks the 3rd identical tool call, recovers deterministically, and
 * terminates via blocked_read_recovery — adding a breaker on top would
 * kill the recovery machinery's own working scenarios.
 *
 * The monitor watches the stream of MODEL-proposed actions (stepResp.next)
 * and per-step telemetry (degraded/fallback flags from the API). A trip is
 * terminal for the scan: the loop terminates with 'llm_degraded' instead of
 * burning the remaining budget against a degraded model.
 */

export interface LlmHealthConfig {
    /** Ring-buffer size for model action fingerprints. */
    windowSize: number;
    /** Full A/B alternation cycles required inside the window before tripping. */
    alternationCycles: number;
    /** Consecutive degraded/fallback steps before tripping on telemetry alone. */
    degradedStreakLimit: number;
    /** Minimum recorded model actions before action-based tripwires evaluate. */
    minActions: number;
}

export const DEFAULT_LLM_HEALTH_CONFIG: LlmHealthConfig = {
    windowSize: 8,
    alternationCycles: 2,
    degradedStreakLimit: 6,
    minActions: 6,
};

export type LlmHealthSignal =
    | 'alternation'
    | 'degraded-streak';

export interface LlmHealthTrip {
    tripped: boolean;
    signal: LlmHealthSignal | null;
    detail: string;
}

export interface LlmHealthMonitor {
    /** Record one model-proposed action (fingerprinted). */
    recordModelAction(fingerprint: string): void;
    /** Record per-step provider telemetry. */
    recordStepTelemetry(degraded: boolean): void;
    /** Evaluate all tripwires; a tripped monitor stays tripped. */
    evaluate(): LlmHealthTrip;
}

function hasAlternationPattern(window: string[], cyclesNeeded: number): string | null {
    // A full A/B cycle = 2 occurrences of each of two distinct fingerprints
    // in strict alternation: A,B,A,B. cyclesNeeded cycles = A,B repeated
    // cyclesNeeded+1 times (a cycle needs 2*(cyclesNeeded+1) entries).
    const span = 2 * (cyclesNeeded + 1);
    for (let i = 0; i + span <= window.length; i++) {
        const a = window[i];
        const b = window[i + 1];
        if (a === b) continue;
        let ok = true;
        for (let j = 2; j < span; j++) {
            if (window[i + j] !== (j % 2 === 0 ? a : b)) {
                ok = false;
                break;
            }
        }
        if (ok) return a;
    }
    return null;
}

export function createLlmHealthMonitor(
    config: Partial<LlmHealthConfig> = {},
): LlmHealthMonitor {
    const cfg = { ...DEFAULT_LLM_HEALTH_CONFIG, ...config };
    const window: string[] = [];
    let degradedStreak = 0;
    let tripped: LlmHealthTrip | null = null;

    const recordModelAction = (fingerprint: string): void => {
        window.push(fingerprint);
        if (window.length > cfg.windowSize) window.shift();
    };

    const recordStepTelemetry = (degraded: boolean): void => {
        degradedStreak = degraded ? degradedStreak + 1 : 0;
    };

    const evaluate = (): LlmHealthTrip => {
        if (tripped) return tripped;

        if (degradedStreak >= cfg.degradedStreakLimit) {
            tripped = {
                tripped: true,
                signal: 'degraded-streak',
                detail: `Provider reported degraded/fallback for ${degradedStreak} consecutive steps.`,
            };
            return tripped;
        }

        if (window.length < cfg.minActions) {
            return { tripped: false, signal: null, detail: 'not enough actions yet' };
        }

        const alt = hasAlternationPattern(window, cfg.alternationCycles);
        if (alt !== null) {
            tripped = {
                tripped: true,
                signal: 'alternation',
                detail: `Model is stuck alternating between two actions (${alt} <-> other) for ${cfg.alternationCycles}+ full cycles.`,
            };
            return tripped;
        }

        return { tripped: false, signal: null, detail: 'healthy' };
    };

    return { recordModelAction, recordStepTelemetry, evaluate };
}
