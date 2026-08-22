/**
 * Fix verification loop — re-runs the exploit verification against the
 * proposed fixed code to prove the fix actually closed the vulnerability.
 *
 * After the fixer generates `fixed_code` + `replace_range`, we:
 *   1. Merge the fixed code into the original file (in memory).
 *   2. Run local syntax validation (if available).
 *   3. Call /verify/generate with the FIXED code and the same vulnerability context.
 *   4. Execute the generated test in the existing sandbox.
 *   5. Call /verify/analyze.
 *   6. Compare the original and fixed verdicts to determine if the fix closed the issue.
 *
 * Closure semantics (conservative by default):
 *   - Original PROVEN + Fixed UNPROVEN  → closed
 *   - Original PROVEN + Fixed PROVEN    → still-vulnerable
 *   - Original PROVEN + Fixed INCONCLUSIVE → inconclusive
 *   - Anything else → inconclusive (don't claim closure without proof)
 *
 * The loop uses a SEPARATE, smaller budget (FIX_VERIFY_DEFAULTS) so a single
 * fix verification cannot consume the entire original scan verification budget.
 */

import * as path from 'path';
import * as crypto from 'crypto';
import { runLocalTest, type LocalTestResult } from '../utils/localTestRunner';
import { detectRuntime, computeRelativeImportPath } from '../utils/runtimeDetect';
import type { ApiClient } from '../api/client';
import type { VerifyGenerateResponse, VerifyAnalyzeResponse } from '../api/types';
import {
    VerifyBudgetTracker,
    defaultFixVerifyBudget,
    type VerifyBudget,
    type FixVerificationStatus,
} from './agentScanProtocol';
import { validateVerifyGenerateResponse, validateVerifyAnalyzeResponse } from './protocolValidator';
import { mergeFixedCode, type ReplaceRange } from './fixCodeMerge';
import { runVerifyLoop, type VerifyFinding } from './verifyLoop';

export interface FixVerifyLoopOptions {
    finding: VerifyFinding;
    originalCode: string;
    fixedCode: string;
    replaceRange: ReplaceRange;
    filePath: string;
    relatedFiles: Array<{ filePath: string; content: string; relationship: string }>;
    workspaceRoot: string;
    language: string;
    client: ApiClient;
    originalVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'SKIPPED';
    signal?: AbortSignal;
    budgetTracker?: VerifyBudgetTracker;
    onProgress?: (round: number, maxRounds: number, message: string) => void;
}

export interface FixVerifyLoopResult {
    status: FixVerificationStatus;
    reason: string;
    originalVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'SKIPPED';
    fixedVerdict?: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    roundsUsed: number;
    fixedCodeHash: string;
    testOutput?: string;
}

const PER_FIX_MAX_ROUNDS = 3;

export async function runFixVerifyLoop(opts: FixVerifyLoopOptions): Promise<FixVerifyLoopResult> {
    const fixedCodeHash = crypto.createHash('sha256').update(opts.fixedCode).digest('hex').slice(0, 16);

    // 1. Merge the fixed code into the original file.
    const mergeResult = mergeFixedCode(opts.originalCode, opts.fixedCode, opts.replaceRange);
    if (!mergeResult.ok) {
        return {
            status: 'syntax-invalid',
            reason: `Fixed code merge failed: ${mergeResult.error}`,
            originalVerdict: opts.originalVerdict,
            roundsUsed: 0,
            fixedCodeHash,
        };
    }
    const mergedCode = mergeResult.mergedCode;

    // 2. Use a dedicated fix verification budget if none provided.
    const tracker = opts.budgetTracker ?? new VerifyBudgetTracker(defaultFixVerifyBudget());

    // 3. Abort check.
    if (opts.signal?.aborted) {
        return {
            status: 'cancelled',
            reason: 'Fix verification cancelled by user before starting.',
            originalVerdict: opts.originalVerdict,
            roundsUsed: 0,
            fixedCodeHash,
        };
    }

    // 4. Run the verify loop against the MERGED (fixed) code.
    //    Pass verificationPhase: 'fix' so the API knows this is a fix-verification
    //    call, not an initial finding verification.
    const maxRounds = Math.min(PER_FIX_MAX_ROUNDS, tracker.budget.maxRoundsPerFinding);

    const result = await runVerifyLoop({
        finding: opts.finding,
        filePath: opts.filePath,
        code: mergedCode,
        relatedFiles: opts.relatedFiles,
        workspaceRoot: opts.workspaceRoot,
        language: opts.language,
        client: opts.client,
        budgetTracker: tracker,
        signal: opts.signal,
        verificationPhase: 'fix',
        onProgress: opts.onProgress,
    });

    // 5. Map the verify loop result to a fix verification status.
    const fixedVerdict = result.verdict;

    // Handle special sub-verdicts that short-circuit the closure decision.
    if (result.subVerdict === 'sandbox-unavailable') {
        return {
            status: 'sandbox-unavailable',
            reason: `Fix verification could not run: no local sandbox (Docker or Deno) available. ${result.reason}`,
            originalVerdict: opts.originalVerdict,
            fixedVerdict,
            roundsUsed: result.roundsUsed,
            fixedCodeHash,
            testOutput: result.testOutput,
        };
    }
    if (result.subVerdict === 'cancelled' || result.subVerdict === 'aborted') {
        return {
            status: 'cancelled',
            reason: 'Fix verification cancelled by user.',
            originalVerdict: opts.originalVerdict,
            fixedVerdict,
            roundsUsed: result.roundsUsed,
            fixedCodeHash,
            testOutput: result.testOutput,
        };
    }

    // 6. Determine closure based on original vs fixed verdicts.
    //    Conservative: only claim "closed" when the original was PROVEN and the
    //    fixed code is UNPROVEN. Everything else is inconclusive or still-vulnerable.
    return determineClosureStatus(opts.originalVerdict, fixedVerdict, result.reason, result.roundsUsed, fixedCodeHash, result.testOutput);
}

function determineClosureStatus(
    originalVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'SKIPPED',
    fixedVerdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE',
    reason: string,
    roundsUsed: number,
    fixedCodeHash: string,
    testOutput?: string,
): FixVerifyLoopResult {
    // Original was PROVEN — the exploit reproduced against the original code.
    if (originalVerdict === 'PROVEN') {
        if (fixedVerdict === 'UNPROVEN') {
            return {
                status: 'closed',
                reason: `Original exploit reproduced; the same exploit did NOT reproduce against the proposed fixed code. ${reason}`,
                originalVerdict,
                fixedVerdict,
                roundsUsed,
                fixedCodeHash,
                testOutput,
            };
        }
        if (fixedVerdict === 'PROVEN') {
            return {
                status: 'still-vulnerable',
                reason: `The exploit still reproduced against the proposed fixed code. ${reason}`,
                originalVerdict,
                fixedVerdict,
                roundsUsed,
                fixedCodeHash,
                testOutput,
            };
        }
        // fixedVerdict === 'INCONCLUSIVE'
        return {
            status: 'inconclusive',
            reason: `Fix verification was inconclusive — could not determine if the fix closed the vulnerability. ${reason}`,
            originalVerdict,
            fixedVerdict,
            roundsUsed,
            fixedCodeHash,
            testOutput,
        };
    }

    // Original was UNPROVEN or INCONCLUSIVE or SKIPPED — we can't claim the fix
    // closed anything because we never proved the original was exploitable.
    return {
        status: 'inconclusive',
        reason: `Cannot determine fix closure: the original finding was ${originalVerdict} (not PROVEN). Fix verification ran ${roundsUsed} round(s) and returned ${fixedVerdict}. ${reason}`,
        originalVerdict,
        fixedVerdict,
        roundsUsed,
        fixedCodeHash,
        testOutput,
    };
}

export { mergeFixedCode, defaultFixVerifyBudget, type VerifyBudget };
