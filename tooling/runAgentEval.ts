#!/usr/bin/env tsx
/**
 * Agent Scan Golden Eval Runner — runs the full Pipeline 2 against a
 * labeled testset and reports precision, recall, FPR, verify verdicts,
 * cost and latency.
 *
 * Usage:
 *   npx tsx tooling/runAgentEval.ts --api-url http://localhost:3000 --api-token <JWT>
 *   npx tsx tooling/runAgentEval.ts --limit 2          # pilot run
 *   npx tsx tooling/runAgentEval.ts --markdown        # Markdown output
 *   npx tsx tooling/runAgentEval.ts --output results.json
 *
 * Requires a running API + valid API token. The runner calls toolAgentScan
 * directly (no MCP server, no credits) — but it DOES hit the real API for
 * the LLM brain, so it costs real tokens.
 */

import * as fs from 'fs';
import * as path from 'path';
import { toolAgentScan } from '../src/tools/agentScan';
import type { ServerContext } from '../src/mcp/types';
import {
    scoreCase,
    aggregateMetrics,
    formatMetricsMarkdown,
    type AgentEvalFixture,
    type AgentEvalCaseResult,
    type AgentEvalFinding,
    type AgentEvalMetrics,
} from '../src/tooling/agentEvalScoring';

interface Manifest {
    schema_version: number;
    total: number;
    targets: { recall_min: number; precision_min: number; fpr_max: number; completion_rate_min: number };
    classes: { name: string; total: number }[];
    fixtures: AgentEvalFixture[];
}

const TOOLING_DIR = __dirname;
const TESTSET_DIR = path.join(TOOLING_DIR, 'agent-testset');
const MANIFEST_PATH = path.join(TESTSET_DIR, 'manifest.json');

function log(msg: string): void { console.log('[eval] ' + msg); }

function parseArgs(): { apiUrl: string; apiToken: string; limit?: number; markdown: boolean; output?: string } {
    const args = process.argv.slice(2);
    let apiUrl = process.env.SECURECODE_API_URL || 'http://localhost:3000';
    let apiToken = process.env.SECURECODE_API_TOKEN || '';
    let limit: number | undefined;
    let markdown = false;
    let output: string | undefined;

    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--api-url') apiUrl = args[++i];
        else if (args[i] === '--api-token') apiToken = args[++i];
        else if (args[i] === '--limit') limit = parseInt(args[++i], 10);
        else if (args[i] === '--markdown') markdown = true;
        else if (args[i] === '--output') output = args[++i];
        else if (args[i] === '--help' || args[i] === '-h') {
            console.log('Usage: npx tsx tooling/runAgentEval.ts --api-url URL --api-token TOKEN [--limit N] [--markdown] [--output FILE]');
            process.exit(0);
        }
    }
    return { apiUrl, apiToken, limit, markdown, output };
}

async function runFixture(
    fixture: AgentEvalFixture,
    ctx: ServerContext,
): Promise<AgentEvalCaseResult> {
    const fixturePath = path.join(TESTSET_DIR, fixture.file);
    const startTime = Date.now();

    try {
        const code = fs.readFileSync(fixturePath, 'utf8');
        const result = await toolAgentScan(ctx, {
            filePath: fixture.file,
            language: fixture.language,
            _noCache: true,
        }) as any;

        const latencyMs = Date.now() - startTime;
        const findings: AgentEvalFinding[] = (result.agentFindings || []).map((f: any) => ({
            line: f.line,
            type: f.type,
            severity: f.severity,
            confidence: f.confidence,
            proven: f.proven || 'SKIPPED',
            evidenceLevel: f.evidenceLevel,
        }));

        const infraFailure = result.status === 'spawn_failed';
        const infraError = infraFailure ? result.error : undefined;

        return scoreCase(
            fixture, findings, infraFailure, infraError,
            result.stepsUsed || 0, result.costSpentUsd || 0, latencyMs,
        );
    } catch (err: any) {
        const latencyMs = Date.now() - startTime;
        return scoreCase(
            fixture, [], true, err.message,
            0, 0, latencyMs,
        );
    }
}

async function main(): Promise<void> {
    const { apiUrl, apiToken, limit, markdown, output } = parseArgs();

    if (!apiToken) {
        console.error('Error: API token required. Set SECURECODE_API_TOKEN or use --api-token.');
        process.exit(1);
    }

    const manifest: Manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
    let fixtures = manifest.fixtures;
    if (limit) fixtures = fixtures.slice(0, limit);

    log(`Running ${fixtures.length} fixture(s) against ${apiUrl}`);

    const ctx: ServerContext = {
        apiUrl,
        apiToken,
        workspaceRoot: TESTSET_DIR,
    };

    const results: AgentEvalCaseResult[] = [];
    for (let i = 0; i < fixtures.length; i++) {
        const f = fixtures[i];
        log(`[${i + 1}/${fixtures.length}] ${f.id} (${f.class}, ${f.verdict})...`);
        const result = await runFixture(f, ctx);
        results.push(result);
        if (result.infraFailure) {
            log(`  INFRA FAILURE: ${result.infraError}`);
        } else {
            log(`  found=${result.found} strict=${result.strictFound} findings=${result.findingCount} proven=${result.provenCount} steps=${result.stepsUsed} cost=$${result.costSpentUsd.toFixed(4)} ${result.latencyMs}ms`);
        }
    }

    const metrics = aggregateMetrics(results);

    if (markdown) {
        console.log('\n' + formatMetricsMarkdown(metrics));
    }

    const report = {
        timestamp: new Date().toISOString(),
        manifest_version: manifest.schema_version,
        fixtureCount: fixtures.length,
        metrics,
        results,
        targets: manifest.targets,
        pass: metrics.recall >= manifest.targets.recall_min
            && metrics.precision >= manifest.targets.precision_min
            && metrics.fpr <= manifest.targets.fpr_max
            && metrics.completionRate >= manifest.targets.completion_rate_min,
    };

    if (output) {
        fs.writeFileSync(output, JSON.stringify(report, null, 2));
        log(`Report written to ${output}`);
    } else {
        console.log(JSON.stringify(report, null, 2));
    }

    if (!report.pass) {
        log('FAIL — targets not met');
        process.exit(1);
    } else {
        log('PASS — all targets met');
    }
}

main().catch(err => {
    console.error('Eval runner failed:', err);
    process.exit(1);
});
