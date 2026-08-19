#!/usr/bin/env tsx
/**
 * Regression gate CLI — compares a candidate eval result against the
 * stored baseline and exits 1 on regression.
 *
 * Usage:
 *   npx tsx tooling/checkAgentRegression.ts --result <path-to-eval-result.json>
 *   npx tsx tooling/checkAgentRegression.ts --result results.json --baseline tooling/agent-testset/baseline.json
 *   npx tsx tooling/checkAgentRegression.ts --update-baseline --result results.json
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { AGENT_SCAN_CACHE_VERSION } from '../src/project-map/scanCache';
import { checkRegression, formatRegressionResult, type AgentEvalReport } from '../src/tooling/agentRegression';

const TOOLING_DIR = __dirname;
const DEFAULT_BASELINE = path.join(TOOLING_DIR, 'agent-testset', 'baseline.json');

function log(msg: string): void { console.log('[regression] ' + msg); }

function parseArgs(): { resultPath: string; baselinePath: string; updateBaseline: boolean } {
    const args = process.argv.slice(2);
    let resultPath = '';
    let baselinePath = DEFAULT_BASELINE;
    let updateBaseline = false;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--result') resultPath = args[++i];
        else if (args[i] === '--baseline') baselinePath = args[++i];
        else if (args[i] === '--update-baseline') updateBaseline = true;
        else if (args[i] === '--help' || args[i] === '-h') {
            console.log('Usage: npx tsx tooling/checkAgentRegression.ts --result <path> [--baseline <path>] [--update-baseline]');
            process.exit(0);
        }
    }

    if (!resultPath && !updateBaseline) {
        console.error('Error: --result is required (or use --update-baseline with --result)');
        process.exit(1);
    }

    return { resultPath, baselinePath, updateBaseline };
}

function getCommitSha(): string {
    try {
        return execSync('git rev-parse HEAD', { encoding: 'utf8', windowsHide: true }).trim();
    } catch {
        return 'unknown';
    }
}

function main(): void {
    const { resultPath, baselinePath, updateBaseline } = parseArgs();

    if (!fs.existsSync(resultPath)) {
        console.error(`Error: result file not found: ${resultPath}`);
        process.exit(1);
    }

    const candidate: AgentEvalReport = JSON.parse(fs.readFileSync(resultPath, 'utf8'));
    candidate.cacheVersion = candidate.cacheVersion ?? AGENT_SCAN_CACHE_VERSION;
    candidate.commitSha = candidate.commitSha ?? getCommitSha();

    if (updateBaseline) {
        fs.writeFileSync(baselinePath, JSON.stringify(candidate, null, 2));
        log(`Baseline updated at ${baselinePath}`);
        log(`  Precision: ${candidate.metrics.precision.toFixed(4)}`);
        log(`  Recall: ${candidate.metrics.recall.toFixed(4)}`);
        log(`  Completion: ${candidate.metrics.completionRate.toFixed(4)}`);
        log(`  Cache version: ${candidate.cacheVersion}`);
        log(`  Commit: ${candidate.commitSha?.slice(0, 8)}`);
        process.exit(0);
    }

    if (!fs.existsSync(baselinePath)) {
        console.error(`Error: baseline file not found: ${baselinePath}`);
        console.error('Run with --update-baseline first to establish the baseline.');
        process.exit(1);
    }

    const baseline: AgentEvalReport = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));

    const result = checkRegression(baseline, candidate);
    console.log(formatRegressionResult(result));

    if (!result.passed) {
        log('FAIL — regression detected. Do not deploy until the gate passes.');
        process.exit(1);
    } else {
        log('PASS — no regression detected.');
        process.exit(0);
    }
}

main();
