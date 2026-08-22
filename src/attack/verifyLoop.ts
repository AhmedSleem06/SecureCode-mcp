import * as path from 'path';
import { runLocalTest, type LocalTestResult } from '../utils/localTestRunner';
import { detectRuntime, computeRelativeImportPath, type ProjectRuntime } from '../utils/runtimeDetect';
import type { ApiClient } from '../api/client';
import type { VerifyGenerateResponse, VerifyAnalyzeResponse } from '../api/types';
import {
    VerifyBudgetTracker,
    defaultVerifyBudget,
    type VerifyBudget,
} from './agentScanProtocol';
import { validateVerifyGenerateResponse, validateVerifyAnalyzeResponse } from './protocolValidator';
import { parseProofMarker } from './proofTypes';
import { evaluateProofGate, buildProofEvidence } from './proofGate';

export interface VerifyFinding {
    type: string;
    line: number;
    lineEnd?: number;
    evidence: string;
    why: string;
    severity: string;
}

export interface VerifyLoopOptions {
    finding: VerifyFinding;
    filePath: string;
    code: string;
    relatedFiles: Array<{ filePath: string; content: string; relationship: string }>;
    workspaceRoot: string;
    language: string;
    client: ApiClient;
    onProgress?: (round: number, maxRounds: number, message: string) => void;
    /** Aggregate budget tracker shared across all findings in one scan. */
    budgetTracker?: VerifyBudgetTracker;
    /** AbortSignal — aborts the loop and any running test. */
    signal?: AbortSignal;
    /**
     * Distinguishes initial vulnerability verification from fix re-verification.
     * - 'original' (default): verifying the original code for a vulnerability.
     * - 'fix': re-verifying the proposed fixed code to see if the exploit still works.
     * Passed to the API so the verifier prompt can be adjusted accordingly.
     */
    verificationPhase?: 'original' | 'fix';
}

export interface VerifyLoopResult {
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    reason: string;
    roundsUsed: number;
    testScript: string;
    testOutput: string;
    /** Why the loop stopped early, when verdict is INCONCLUSIVE due to budget. */
    budgetExhaustedReason?: string;
    /** Backend that executed the test (docker, deno, etc.). Empty when none ran. */
    backend?: string;
    /** Structured proof evidence from the proof marker, if present. */
    proofEvidence?: import('./proofTypes').ProofEvidence;
    /** Result of the deterministic proof gate evaluation. */
    proofGateResult?: import('./proofTypes').ProofGateResult;
    /** Proof-specific sub-verdict for strict gate failures. */
    proofSubVerdict?: import('./proofTypes').ProofSubVerdict;
    /**
     * Machine-readable sub-verdict so callers (toolAgentScan) can detect the
     * INCONCLUSIVE reason without string-matching `reason`. Distinct from
     * `verdict` because all of these collapse to INCONCLUSIVE at the top
     * level — the difference is what the user should do about it.
     *
     *   - 'analyzed'         : the analyze LLM ran and returned INCONCLUSIVE
     *                          (couldn't decide after exhausting rounds).
     *   - 'cannot-test'       : /verify/generate returned canTest:false — the
     *                          vuln type/framework can't be tested locally.
     *   - 'sandbox-unavailable': no Docker/Deno on the user's machine. The
     *                          caller should surface an install hint.
     *   - 'blocked'           : the static safety check rejected the script.
     *   - 'budget-exhausted'  : the aggregate VerifyBudget ran out.
     *   - 'aborted'           : the AbortSignal fired.
     *   - 'cancelled'         : the user cancelled the scan mid-test.
     *   - 'runtime-blocked'   : detectRuntime said canRunLocally:false.
     *   - undefined           : PROVEN or UNPROVEN (no sub-verdict needed).
     */
    subVerdict?: 'analyzed'
        | 'cannot-test'
        | 'sandbox-unavailable'
        | 'blocked'
        | 'budget-exhausted'
        | 'aborted'
        | 'cancelled'
        | 'runtime-blocked';
}

const PER_FINDING_MAX_ROUNDS = 12;

export async function runVerifyLoop(opts: VerifyLoopOptions): Promise<VerifyLoopResult> {
    const { finding, filePath, code, relatedFiles, workspaceRoot, language, client, onProgress } = opts;
    const tracker = opts.budgetTracker;
    const verificationPhase = opts.verificationPhase ?? 'original';
    const previousErrors: string[] = [];
    let lastTestScript = '';
    let lastTestOutput = '';

    // Per-finding round cap = min(per-finding default, budget's per-finding cap).
    const maxRounds = tracker
        ? Math.min(PER_FINDING_MAX_ROUNDS, tracker.budget.maxRoundsPerFinding)
        : PER_FINDING_MAX_ROUNDS;

    const runtimeInfo = detectRuntime(workspaceRoot, filePath || undefined);
    const testFileDir = path.join(workspaceRoot, '.securecode');
    const relativeImportPath = filePath
        ? computeRelativeImportPath(testFileDir, path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath))
        : '';

    if (!runtimeInfo.canRunLocally) {
        return {
            verdict: 'INCONCLUSIVE',
            reason: runtimeInfo.skipReason || 'Detected framework cannot run a local exploit test.',
            roundsUsed: 0,
            testScript: '',
            testOutput: '',
            subVerdict: 'runtime-blocked',
        };
    }

    // Pre-flight: if the aggregate budget is already exhausted at finding entry,
    // skip without spending any LLM calls. The caller (toolAgentScan) should
    // also check this before calling, but we double-enforce here.
    if (tracker && !tracker.canAttemptFinding()) {
        return {
            verdict: 'INCONCLUSIVE',
            reason: `Verification budget exhausted before this finding (findings=${tracker.findingsAttempted}/${tracker.budget.maxFindings}, llmCalls=${tracker.llmCallsUsed}/${tracker.budget.maxLlmCalls}, wallClock=${tracker.wallClockElapsedMs}ms/${tracker.budget.maxWallClockMs}ms).`,
            roundsUsed: 0,
            testScript: '',
            testOutput: '',
            budgetExhaustedReason: 'aggregate',
            subVerdict: 'budget-exhausted',
        };
    }
    if (tracker) tracker.findingsAttempted += 1;

    for (let round = 1; round <= maxRounds; round++) {
        // Per-round budget check (need at least generate + analyze = 2 calls).
        if (tracker && !tracker.canAttemptRound()) {
            return {
                verdict: 'INCONCLUSIVE',
                reason: `Verification budget exhausted mid-finding (llmCalls=${tracker.llmCallsUsed}/${tracker.budget.maxLlmCalls}, wallClock=${tracker.wallClockElapsedMs}ms/${tracker.budget.maxWallClockMs}ms).`,
                roundsUsed: round - 1,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                budgetExhaustedReason: 'aggregate',
                subVerdict: 'budget-exhausted',
            };
        }
        if (tracker) tracker.roundsUsed += 1;

        if (opts.signal?.aborted) {
            return {
                verdict: 'INCONCLUSIVE',
                reason: 'Cancelled by user.',
                roundsUsed: round - 1,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                subVerdict: 'aborted',
            };
        }

        onProgress?.(round, maxRounds, `Round ${round}: generating test...`);

        const genRespRaw = await client.postJson<VerifyGenerateResponse>('/verify/generate', {
            code,
            language,
            vulnerabilityType: finding.type,
            line: finding.line,
            lineEnd: finding.lineEnd,
            evidence: finding.evidence,
            why: finding.why,
            filePath,
            relatedFiles,
            previousErrors: previousErrors.length > 0 ? previousErrors : undefined,
            projectRuntime: runtimeInfo.runtime,
            suggestedRunner: runtimeInfo.runner,
            framework: runtimeInfo.framework,
            frameworkVersion: runtimeInfo.frameworkVersion,
            testabilityTier: runtimeInfo.testabilityTier,
            packageManager: runtimeInfo.packageManager,
            testFileDir: '.securecode',
            relativeImportPath,
            depsInstalled: runtimeInfo.depsInstalled,
            verificationPhase,
        });
        if (tracker) tracker.recordLlmCall((genRespRaw as any).costUsd ?? 0);

        const genValidation = validateVerifyGenerateResponse(genRespRaw);
        if (!genValidation.ok) {
            return {
                verdict: 'INCONCLUSIVE',
                reason: `API returned a malformed verify/generate response: ${genValidation.error}`,
                roundsUsed: round,
                testScript: '',
                testOutput: '',
                subVerdict: 'analyzed',
            };
        }
        const genResp = genValidation.value;

        if (!genResp.canTest || !genResp.testScript) {
            return {
                verdict: 'INCONCLUSIVE',
                reason: genResp.skipReason || 'Could not generate a test for this vulnerability type.',
                roundsUsed: round,
                testScript: '',
                testOutput: '',
                subVerdict: 'cannot-test',
            };
        }

        lastTestScript = genResp.testScript;
        const runner = genResp.runner || runtimeInfo.runner || (language === 'typescript' ? 'tsx' : 'node');

        onProgress?.(round, maxRounds, `Round ${round}: running test...`);

        // Cap the local test timeout at the remaining verify-budget wall-clock.
        const testTimeoutMs = tracker
            ? Math.min(30_000, tracker.remainingWallClockMs())
            : 30_000;

        const testResult: LocalTestResult = await runLocalTest(
            genResp.testScript,
            runner,
            workspaceRoot,
            {
                setupScript: genResp.setupScript || null,
                timeoutMs: testTimeoutMs,
                signal: opts.signal,
            },
        );

        lastTestOutput = testResult.output;

        // Handle non-LLM-judged verdicts that should short-circuit the loop.
        if (testResult.verdict === 'sandbox-unavailable') {
            // No isolation backend on the user's machine. We must NOT run
            // the script with host privileges — return INCONCLUSIVE so the
            // finding keeps its non-PROVEN status but isn't buried as UNPROVEN.
            return {
                verdict: 'INCONCLUSIVE',
                reason: testResult.output,
                roundsUsed: round,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                backend: testResult.backend || '',
                subVerdict: 'sandbox-unavailable',
            };
        }
        if (testResult.verdict === 'blocked') {
            // Static safety check rejected the script. Don't retry — the
            // LLM would have to emit a less dangerous script, but anything
            // that trips the blocklist is almost certainly trying to do
            // something we don't want.
            return {
                verdict: 'INCONCLUSIVE',
                reason: `Test script rejected by safety check: ${testResult.output}`,
                roundsUsed: round,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                subVerdict: 'blocked',
            };
        }
        if (testResult.verdict === 'cancelled') {
            // User aborted the scan. Do NOT retry — return immediately so the
            // cancellation propagates up to toolAgentScan, which stops the loop.
            return {
                verdict: 'INCONCLUSIVE',
                reason: `Verification cancelled by user at round ${round}.`,
                roundsUsed: round,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                subVerdict: 'cancelled',
            };
        }
        if (testResult.verdict === 'timeout') {
            // Treat as a retryable error — feed it back to the LLM.
            previousErrors.push(`Round ${round}: timed out — ${testResult.output.slice(0, 500)}`);
            if (round >= maxRounds) {
                return {
                    verdict: 'INCONCLUSIVE',
                    reason: `Test timed out after ${round} round(s).`,
                    roundsUsed: round,
                    testScript: lastTestScript,
                    testOutput: lastTestOutput,
                    subVerdict: 'analyzed',
                };
            }
            continue;
        }

        onProgress?.(round, maxRounds, `Round ${round}: analyzing result...`);

        const analyzeRespRaw = await client.postJson<VerifyAnalyzeResponse>('/verify/analyze', {
            vulnerabilityType: finding.type,
            line: finding.line,
            evidence: finding.evidence,
            why: finding.why,
            testScript: genResp.testScript,
            stdout: testResult.output,
            stderr: '',
            exitCode: testResult.exitCode,
            round,
            maxRounds,
            verificationPhase,
        });
        if (tracker) tracker.recordLlmCall((analyzeRespRaw as any).costUsd ?? 0);

        const analyzeValidation = validateVerifyAnalyzeResponse(analyzeRespRaw);
        if (!analyzeValidation.ok) {
            return {
                verdict: 'INCONCLUSIVE',
                reason: `API returned a malformed verify/analyze response: ${analyzeValidation.error}`,
                roundsUsed: round,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                backend: testResult.backend || '',
                subVerdict: 'analyzed',
            };
        }
        const analyzeResp = analyzeValidation.value;

        const proofMarker = parseProofMarker(lastTestOutput);
        const gateResult = evaluateProofGate(proofMarker, {
            sandboxBackend: testResult.backend || 'unknown',
            targetFile: filePath || '',
            targetLine: finding.line,
            repeatedRuns: 1,
            repeatPasses: proofMarker.found && proofMarker.exploit === 'pass' ? 1 : 0,
            llmVerdict: analyzeResp.verdict,
            sourceMode: proofMarker.sourceMode,
        });

        const proofEvidence = proofMarker.found
            ? buildProofEvidence(proofMarker, {
                  sandboxBackend: testResult.backend || 'unknown',
                  targetFile: filePath || '',
                  targetLine: finding.line,
                  repeatedRuns: 1,
                  repeatPasses: proofMarker.found && proofMarker.exploit === 'pass' ? 1 : 0,
              })
            : undefined;

        if (analyzeResp.verdict === 'PROVEN') {
            if (gateResult.eligibleForProven) {
                return {
                    verdict: 'PROVEN',
                    reason: analyzeResp.reason,
                    roundsUsed: round,
                    testScript: lastTestScript,
                    testOutput: lastTestOutput,
                    backend: testResult.backend || '',
                    proofEvidence,
                    proofGateResult: gateResult,
                    proofSubVerdict: 'gate-passed',
                };
            }
            console.warn(`[Verify Loop] LLM said PROVEN but proof gate rejected: ${gateResult.failedGates.join(', ')}`);
            return {
                verdict: gateResult.downgradedVerdict === 'UNPROVEN' ? 'UNPROVEN' : 'INCONCLUSIVE',
                reason: `Proof gate rejected: ${gateResult.failedGates.join(', ')}. ${gateResult.warnings.join(' ')}. LLM reason: ${analyzeResp.reason}`,
                roundsUsed: round,
                testScript: lastTestScript,
                testOutput: lastTestOutput,
                backend: testResult.backend || '',
                proofEvidence,
                proofGateResult: gateResult,
                proofSubVerdict: 'gate-rejected',
                subVerdict: gateResult.downgradedVerdict === 'UNPROVEN' ? undefined : 'analyzed',
            };
        }
        if (analyzeResp.verdict === 'UNPROVEN') {
            return { verdict: 'UNPROVEN', reason: analyzeResp.reason, roundsUsed: round, testScript: lastTestScript, testOutput: lastTestOutput, backend: testResult.backend || '', proofEvidence, proofGateResult: gateResult };
        }

        if (!analyzeResp.shouldRetry || round >= maxRounds) {
            return { verdict: 'INCONCLUSIVE', reason: analyzeResp.reason || `Could not verify after ${round} round(s).`, roundsUsed: round, testScript: lastTestScript, testOutput: lastTestOutput, backend: testResult.backend || '', subVerdict: 'analyzed', proofEvidence, proofGateResult: gateResult };
        }

        previousErrors.push(`Round ${round}: ${testResult.verdict} — ${testResult.output.slice(0, 500)}`);
    }

    return { verdict: 'INCONCLUSIVE', reason: `Exhausted all ${maxRounds} rounds.`, roundsUsed: maxRounds, testScript: lastTestScript, testOutput: lastTestOutput, subVerdict: 'analyzed' };
}

export { VerifyBudgetTracker, defaultVerifyBudget, type VerifyBudget };
