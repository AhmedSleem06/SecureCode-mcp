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
        };
    } catch {
        return { found: false };
    }
}
