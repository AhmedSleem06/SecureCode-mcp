import * as path from 'path';
import { runLocalTest, type LocalTestResult } from '../utils/localTestRunner';
import { detectRuntime, computeRelativeImportPath, type ProjectRuntime } from '../utils/runtimeDetect';
import type { ApiClient } from '../api/client';
import type { VerifyGenerateResponse, VerifyAnalyzeResponse } from '../api/types';

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
}

export interface VerifyLoopResult {
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    reason: string;
    roundsUsed: number;
    testScript: string;
    testOutput: string;
}

const MAX_ROUNDS = 8;

export async function runVerifyLoop(opts: VerifyLoopOptions): Promise<VerifyLoopResult> {
    const { finding, filePath, code, relatedFiles, workspaceRoot, language, client, onProgress } = opts;
    const previousErrors: string[] = [];
    let lastTestScript = '';
    let lastTestOutput = '';

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
        };
    }

    for (let round = 1; round <= MAX_ROUNDS; round++) {
        onProgress?.(round, MAX_ROUNDS, `Round ${round}: generating test...`);

        const genResp = await client.postJson<VerifyGenerateResponse>('/verify/generate', {
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
        });

        if (!genResp.canTest || !genResp.testScript) {
            return {
                verdict: 'INCONCLUSIVE',
                reason: genResp.skipReason || 'Could not generate a test for this vulnerability type.',
                roundsUsed: round,
                testScript: '',
                testOutput: '',
            };
        }

        lastTestScript = genResp.testScript;
        const runner = genResp.runner || runtimeInfo.runner || (language === 'typescript' ? 'tsx' : 'node');

        onProgress?.(round, MAX_ROUNDS, `Round ${round}: running test...`);

        const testResult: LocalTestResult = await runLocalTest(
            genResp.testScript,
            runner,
            workspaceRoot,
        );

        lastTestOutput = testResult.output;

        onProgress?.(round, MAX_ROUNDS, `Round ${round}: analyzing result...`);

        const analyzeResp = await client.postJson<VerifyAnalyzeResponse>('/verify/analyze', {
            vulnerabilityType: finding.type,
            line: finding.line,
            evidence: finding.evidence,
            why: finding.why,
            testScript: genResp.testScript,
            stdout: testResult.output,
            stderr: '',
            exitCode: testResult.exitCode,
            round,
            maxRounds: MAX_ROUNDS,
        });

        if (analyzeResp.verdict === 'PROVEN') {
            return { verdict: 'PROVEN', reason: analyzeResp.reason, roundsUsed: round, testScript: lastTestScript, testOutput: lastTestOutput };
        }
        if (analyzeResp.verdict === 'UNPROVEN') {
            return { verdict: 'UNPROVEN', reason: analyzeResp.reason, roundsUsed: round, testScript: lastTestScript, testOutput: lastTestOutput };
        }

        if (!analyzeResp.shouldRetry || round >= MAX_ROUNDS) {
            return { verdict: 'INCONCLUSIVE', reason: analyzeResp.reason || `Could not verify after ${round} round(s).`, roundsUsed: round, testScript: lastTestScript, testOutput: lastTestOutput };
        }

        previousErrors.push(`Round ${round}: ${testResult.verdict} — ${testResult.output.slice(0, 500)}`);
    }

    return { verdict: 'INCONCLUSIVE', reason: `Exhausted all ${MAX_ROUNDS} rounds.`, roundsUsed: MAX_ROUNDS, testScript: lastTestScript, testOutput: lastTestOutput };
}
