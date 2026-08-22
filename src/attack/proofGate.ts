import type {
    ProofEvidence,
    ProofGateResult,
    ParsedProofMarker,
    ProofSourceMode,
} from './proofTypes';

const DEFAULT_MINIMUM_REPEAT_RUNS = 3;

export function evaluateProofGate(
    marker: ParsedProofMarker,
    context: {
        sandboxBackend: string;
        targetFile: string;
        targetLine: number;
        repeatedRuns: number;
        repeatPasses: number;
        llmVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
        sourceMode?: ProofSourceMode;
        minimumRepeatRuns?: number;
    },
): ProofGateResult {
    const failedGates: string[] = [];
    const warnings: string[] = [];

    if (!marker.found) {
        failedGates.push('proof-marker-missing');
        return {
            eligibleForProven: false,
            failedGates,
            warnings,
            downgradedVerdict: 'INCONCLUSIVE',
        };
    }

    if (marker.sourceMode === 'synthetic') {
        failedGates.push('synthetic-source');
        warnings.push('Proof uses synthetic reproduction, not real production code');
    }

    if (marker.sourceMode === 'extracted-logic') {
        failedGates.push('extracted-logic-source');
        warnings.push('Proof uses extracted/reconstructed logic, not exact production import');
    }

    if (marker.mockedVulnerablePath === true) {
        failedGates.push('mock-vulnerable-path');
        warnings.push('Test mocks the vulnerable decision path');
    }

    if (marker.targetReached === false) {
        failedGates.push('target-not-reached');
        warnings.push('Test did not reach the reported vulnerability location');
    }

    if (marker.baseline !== 'pass') {
        failedGates.push('baseline-failed');
        warnings.push('Baseline secure case did not pass — cannot distinguish exploit from normal behavior');
    }

    if (marker.exploit !== 'pass') {
        failedGates.push('exploit-failed');
        warnings.push('Exploit case did not pass');
    }

    if (marker.impact !== 'observed') {
        failedGates.push('impact-not-observed');
        warnings.push('No measurable impact observed from the exploit');
    }

    if (marker.assertion !== 'deterministic') {
        failedGates.push('non-deterministic-assertion');
        warnings.push('Test uses LLM-only assertion, not deterministic code');
    }

    if (context.repeatedRuns < (context.minimumRepeatRuns ?? DEFAULT_MINIMUM_REPEAT_RUNS)) {
        failedGates.push('insufficient-repeats');
        warnings.push(`Only ${context.repeatedRuns} run(s), need ${context.minimumRepeatRuns ?? DEFAULT_MINIMUM_REPEAT_RUNS} for PROVEN`);
    }

    if (context.repeatPasses < context.repeatedRuns) {
        failedGates.push('flaky-proof');
        warnings.push(`${context.repeatPasses}/${context.repeatedRuns} runs passed — proof is flaky`);
    }

    if (context.llmVerdict !== 'PROVEN' && failedGates.length === 0) {
        warnings.push('LLM verdict was not PROVEN but proof marker passed — overriding to PROVEN');
    }

    if (context.llmVerdict === 'PROVEN' && failedGates.length > 0) {
        warnings.push('LLM said PROVEN but deterministic gates failed — downgrading');
    }

    const eligibleForProven = failedGates.length === 0;

    let downgradedVerdict: ProofGateResult['downgradedVerdict'];
    if (eligibleForProven) {
        downgradedVerdict = 'PROVEN';
    } else if (failedGates.includes('exploit-failed') || failedGates.includes('impact-not-observed')) {
        downgradedVerdict = 'UNPROVEN';
    } else if (failedGates.includes('synthetic-source') || failedGates.includes('extracted-logic-source')) {
        downgradedVerdict = 'INCONCLUSIVE';
    } else {
        downgradedVerdict = 'INCONCLUSIVE';
    }

    return {
        eligibleForProven,
        failedGates,
        warnings,
        downgradedVerdict,
    };
}

export function buildProofEvidence(
    marker: ParsedProofMarker,
    context: {
        sandboxBackend: string;
        targetFile: string;
        targetLine: number;
        targetSymbol?: string;
        repeatedRuns: number;
        repeatPasses: number;
        assumptions?: string[];
    },
): ProofEvidence {
    return {
        proofId: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
        sourceMode: marker.sourceMode ?? 'synthetic',
        targetFile: context.targetFile,
        targetLine: context.targetLine,
        targetSymbol: context.targetSymbol,
        reachedTarget: marker.targetReached ?? false,
        baselinePassed: marker.baseline === 'pass',
        exploitPassed: marker.exploit === 'pass',
        impactObserved: marker.impact === 'observed',
        deterministicAssertion: marker.assertion === 'deterministic',
        mocksVulnerablePath: marker.mockedVulnerablePath ?? false,
        repeatedRuns: context.repeatedRuns,
        repeatPasses: context.repeatPasses,
        sandboxBackend: context.sandboxBackend,
        assumptions: context.assumptions ?? [],
    };
}
