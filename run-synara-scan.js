/**
 * Real Pipeline 2 test — runs securecode.agent-scan against the Synara
 * test_lab project's most security-critical server file.
 *
 * Prerequisites:
 *   - SECURECODE_API_TOKEN env var (minted on Vultr)
 *   - Docker (for local sandbox verification)
 *   - Built MCP dist/ (npm run build)
 */
import { toolAgentScan } from './dist/tools/agentScan.js';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const API_TOKEN = process.env.SECURECODE_API_TOKEN;
if (!API_TOKEN || API_TOKEN.length < 10) {
    console.error('SECURECODE_API_TOKEN is required');
    process.exit(1);
}

const SYNARA_ROOT = path.resolve(__dirname, '..', 'test_lab', 'synara');
const TARGET_FILE = 'apps/server/src/agentGateway/httpRoute.ts';
const TARGET_PATH = path.join(SYNARA_ROOT, TARGET_FILE);

if (!fs.existsSync(TARGET_PATH)) {
    console.error('Target file not found: ' + TARGET_PATH);
    process.exit(1);
}

const ctx = {
    workspaceRoot: SYNARA_ROOT,
    apiUrl: 'https://api.usesecurecode.tech',
    apiToken: API_TOKEN,
};

console.log('=== SecureCode Agent Scan — Synara Real Test ===');
console.log('Target:', TARGET_FILE);
console.log('Workspace:', SYNARA_ROOT);
console.log('API:', ctx.apiUrl);
console.log('');

(async () => {
    const startTime = Date.now();
    try {
        const result = await toolAgentScan(ctx, {
            filePath: TARGET_FILE,
            language: 'typescript',
            _progress: (progress, total, message) => {
                console.log(`  [${progress}/${total}] ${message}`);
            },
        });

        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log('');
        console.log(`=== Scan completed in ${elapsed}s ===`);
        console.log('Status:', result.status || 'completed');
        console.log('Steps:', result.stepsUsed || 0);
        console.log('Cost: $' + (result.costSpentUsd || 0).toFixed(4));
        console.log('');

        const findings = result.agentFindings || result.findings || [];
        console.log(`=== Findings (${findings.length}) ===`);
        for (const f of findings) {
            console.log('');
            console.log(`  Type: ${f.type || f.vulnerabilityType || 'unknown'}`);
            console.log(`  Severity: ${f.severity || 'unknown'}`);
            console.log(`  Line: ${f.line || '?'}`);
            console.log(`  Confidence: ${(f.confidence || 0).toFixed(0)}%`);
            console.log(`  Proven: ${f.proven || 'SKIPPED'}`);
            console.log(`  Reason: ${(f.provenReason || f.why || '').slice(0, 200)}`);
            console.log(`  Evidence: ${(f.evidence || '').slice(0, 150)}`);
        }

        console.log('');
        console.log('=== Summary ===');
        console.log('Proven:', result.provenCount || 0);
        console.log('Unproven:', result.unprovenCount || 0);
        console.log('Inconclusive:', result.inconclusiveCount || 0);
        console.log('Skipped:', result.skippedCount || 0);
        if (result.verifyHint) {
            console.log('');
            console.log('Verify Hint:', result.verifyHint);
        }
        if (result.cached) console.log('(Result was cached)');
    } catch (err) {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.error(`Scan failed after ${elapsed}s:`, err.message);
        if (err.stack) console.error(err.stack);
        process.exit(1);
    }
})();
