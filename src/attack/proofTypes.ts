export type ProofSourceMode = 'real-import' | 'real-server' | 'extracted-logic' | 'synthetic';

export interface ProofEvidence {
    proofId: string;
    sourceMode: ProofSourceMode;
    targetFile: string;
    targetLine: number;
    targetSymbol?: string;
    reachedTarget: boolean;
    baselinePassed: boolean;
    exploitPassed: boolean;
    impactObserved: boolean;
    deterministicAssertion: boolean;
    mocksVulnerablePath: boolean;
    repeatedRuns: number;
    repeatPasses: number;
    sandboxBackend: string;
    environmentFingerprint?: string;
    assumptions: string[];
    artifactPath?: string;
}

export interface ProofGateResult {
    eligibleForProven: boolean;
    failedGates: string[];
    warnings: string[];
    downgradedVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE';
}

export type ProofSubVerdict =
    | 'proof-marker-missing'
    | 'proof-assertion-failed'
    | 'flaky-proof'
    | 'mock-vulnerable-path'
    | 'target-not-reached'
    | 'baseline-failed'
    | 'impact-not-observed'
    | 'gate-passed'
    | 'gate-rejected';

export interface ParsedProofMarker {
    found: boolean;
    baseline?: 'pass' | 'fail';
    exploit?: 'pass' | 'fail';
    impact?: 'observed' | 'not-observed';
    targetReached?: boolean;
    assertion?: 'deterministic' | 'llm-only';
    mockedVulnerablePath?: boolean;
    sourceMode?: ProofSourceMode;
    setup?: 'pass' | 'fail';
    setupNote?: string;
}

/**
 * Per-run validation result for a single repeatability run. Each repeat
 * must independently validate all proof properties — a run is only
 * counted as "passed" if ALL of these are true:
 *   - verdict === 'pass'
 *   - markerValid (proof marker was found and parsed)
 *   - targetReached (the proof reached the target file/line)
 *   - impactObserved (the exploit produced an observable impact)
 */
export interface ProofRunResult {
    runIndex: number;
    verdict: 'pass' | 'fail' | 'error' | 'timeout';
    markerValid: boolean;
    targetReached: boolean;
    impactObserved: boolean;
    baselineResult?: 'pass' | 'fail';
    exploitResult?: 'pass' | 'fail';
}

export const PROOF_MARKER_START = 'SECURECODE_PROOF_RESULT:';
export const PROOF_MARKER_END = ':SECURECODE_PROOF_END';

export function parseProofMarker(output: string): ParsedProofMarker {
    const startIdx = output.indexOf(PROOF_MARKER_START);
    if (startIdx === -1) return { found: false };
    const endIdx = output.indexOf(PROOF_MARKER_END, startIdx);
    if (endIdx === -1) return { found: false };
    const jsonStr = output.slice(startIdx + PROOF_MARKER_START.length, endIdx).trim();
    try {
        const parsed = JSON.parse(jsonStr);
        return {
            found: true,
            baseline: parsed.baseline,
            exploit: parsed.exploit,
            impact: parsed.impact,
            targetReached: parsed.targetReached,
            assertion: parsed.assertion,
            mockedVulnerablePath: parsed.mockedVulnerablePath,
            sourceMode: parsed.sourceMode,
            ...(parsed.setup === 'pass' || parsed.setup === 'fail' ? { setup: parsed.setup } : {}),
            ...(typeof parsed.setupNote === 'string' ? { setupNote: parsed.setupNote } : {}),
        };
    } catch {
        return { found: false };
    }
}

export const HARNESS_LOG_START = 'SECURECODE_HARNESS_LOG:';
export const HARNESS_LOG_END = ':SECURECODE_HARNESS_END';

export interface HarnessCall {
    method: string;
    path: string;
    matched: boolean;
    sent: boolean;
    status: number | undefined;
    timedOut: boolean;
}

export interface HarnessLog {
    found: boolean;
    calls: HarnessCall[];
    engine?: string;
    unsupported?: string[];
}

export function parseHarnessLog(output: string): HarnessLog {
    const startIdx = output.indexOf(HARNESS_LOG_START);
    if (startIdx === -1) return { found: false, calls: [] };
    const endIdx = output.indexOf(HARNESS_LOG_END, startIdx);
    if (endIdx === -1) return { found: false, calls: [] };
    const jsonStr = output.slice(startIdx + HARNESS_LOG_START.length, endIdx).trim();
    try {
        const parsed = JSON.parse(jsonStr);
        if (!Array.isArray(parsed.calls)) return { found: true, calls: [] };
        return {
            found: true,
            calls: parsed.calls.map((c: any) => ({
                method: String(c.method ?? ''),
                path: String(c.path ?? ''),
                matched: c.matched === true,
                sent: c.sent === true,
                status: typeof c.status === 'number' ? c.status : undefined,
                timedOut: c.timedOut === true,
            })),
            engine: typeof parsed.engine === 'string' ? parsed.engine : undefined,
            unsupported: Array.isArray(parsed.unsupported) ? parsed.unsupported.map(String) : undefined,
        };
    } catch {
        return { found: false, calls: [] };
    }
}
