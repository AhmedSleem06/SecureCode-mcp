/**
 * Synara discovery scan — runs the REAL MCP toolAgentScan on security-critical
 * files from the Synara project. No ground truth — just raw findings.
 *
 * Usage:
 *   $token = "<JWT>"
 *   node tests/benchmark-synara.js $token
 */

const path = require('path');
const fs = require('fs');
const { toolAgentScan } = require('../dist/tools/agentScan');

const SYNARA = path.resolve(__dirname, '..', '..', 'test_lab', 'synara');
const API_URL = process.env.SECURECODE_API_URL || 'https://api.usesecurecode.tech';

const FILES = [
    // HTTP route handlers
    { path: 'apps/server/src/http.ts', language: 'typescript' },
    { path: 'apps/server/src/agentGateway/httpRoute.ts', language: 'typescript' },
    { path: 'apps/server/src/externalMcp/httpRoute.ts', language: 'typescript' },

    // WebSocket handlers
    { path: 'apps/server/src/wsRpc.ts', language: 'typescript' },
    { path: 'apps/server/src/wsRequestAdmission.ts', language: 'typescript' },

    // Authentication / Authorization
    { path: 'apps/server/src/auth/Layers/ServerAuth.ts', language: 'typescript' },
    { path: 'apps/server/src/auth/Layers/AuthControlPlane.ts', language: 'typescript' },
    { path: 'apps/server/src/auth/Layers/SessionCredentialService.ts', language: 'typescript' },
    { path: 'apps/server/src/auth/Layers/BootstrapCredentialService.ts', language: 'typescript' },
    { path: 'apps/server/src/agentGateway/Services/AgentGatewayCredentials.ts', language: 'typescript' },
    { path: 'apps/server/src/trustedOrigins.ts', language: 'typescript' },
    { path: 'apps/server/src/startupAccess.ts', language: 'typescript' },

    // Database
    { path: 'apps/server/src/persistence/Layers/AuthSessions.ts', language: 'typescript' },
    { path: 'apps/server/src/persistence/Layers/AuthPairingLinks.ts', language: 'typescript' },
    { path: 'apps/server/src/persistence/NodeSqliteClient.ts', language: 'typescript' },

    // Config / Secrets
    { path: 'apps/server/src/config.ts', language: 'typescript' },
    { path: 'apps/server/src/auth/Layers/ServerSecretStore.ts', language: 'typescript' },
];

async function main() {
    const token = process.argv[2] || process.env.SECURECODE_API_TOKEN;
    if (!token) {
        console.error('Usage: node tests/benchmark-synara.js <JWT_TOKEN>');
        process.exit(1);
    }

    console.log('=== Synara Discovery Scan (Real MCP) ===');
    console.log(`Workspace: ${SYNARA}`);
    console.log(`API: ${API_URL}`);
    console.log(`Files: ${FILES.length}\n`);

    const ctx = {
        apiUrl: API_URL,
        apiToken: token,
        workspaceRoot: SYNARA,
    };

    let totalElapsed = 0;
    let totalCost = 0;
    let totalSteps = 0;
    let totalProven = 0;
    let totalFindings = 0;
    const perFile = [];

    for (let i = 0; i < FILES.length; i++) {
        const f = FILES[i];
        const fullPath = path.join(SYNARA, f.path);
        if (!fs.existsSync(fullPath)) {
            console.log(`[${i + 1}/${FILES.length}] ${f.path} — SKIP (not found)`);
            continue;
        }

        const lines = fs.readFileSync(fullPath, 'utf8').split('\n').length;
        console.log(`[${i + 1}/${FILES.length}] ${f.path} (${lines} lines)`);

        const args = {
            filePath: f.path,
            language: f.language,
            _progress: (progress, total, msg) => {
                process.stdout.write(`  [${progress}/${total}] ${msg}\r`);
            },
        };

        const start = Date.now();
        let result;
        try {
            result = await toolAgentScan(ctx, args);
        } catch (err) {
            console.log(`  ERROR: ${err.message}`);
            result = { agentFindings: [], status: 'error' };
        }
        const elapsed = (Date.now() - start) / 1000;

        const findings = (result.agentFindings || []).map(ft => ({
            line: ft.line,
            lineEnd: ft.lineEnd,
            type: ft.type,
            severity: ft.severity,
            confidence: ft.confidence,
            proven: ft.proven || 'N/A',
            why: (ft.why || '').slice(0, 150),
        }));

        totalElapsed += elapsed;
        totalCost += (result.costSpentUsd || 0);
        totalSteps += (result.stepsUsed || 0);
        totalProven += (result.provenCount || 0);
        totalFindings += findings.length;

        console.log(`  Found: ${findings.length} | ${elapsed.toFixed(1)}s | steps: ${result.stepsUsed || '?'} | cost: $${(result.costSpentUsd || 0).toFixed(4)} | status: ${result.status || 'ok'}`);

        for (const ft of findings) {
            console.log(`    [${ft.severity}] ${ft.type} L${ft.line}${ft.lineEnd ? '-' + ft.lineEnd : ''} | conf: ${ft.confidence} | proven: ${ft.proven}`);
            console.log(`      ${ft.why}`);
        }
        console.log('');

        perFile.push({
            path: f.path,
            lines,
            found: findings.length,
            elapsed: elapsed.toFixed(1),
            steps: result.stepsUsed,
            cost: (result.costSpentUsd || 0).toFixed(4),
            status: result.status || 'ok',
        });
    }

    console.log('=== SUMMARY ===');
    console.log(`Files scanned:  ${perFile.length}`);
    console.log(`Total findings: ${totalFindings}`);
    console.log(`Total time:     ${totalElapsed.toFixed(1)}s`);
    console.log(`Total cost:     $${totalCost.toFixed(4)}`);
    console.log(`Total steps:    ${totalSteps}`);
    console.log(`Avg per file:   ${(totalElapsed / perFile.length).toFixed(1)}s, ${(totalSteps / perFile.length).toFixed(1)} steps`);
    console.log('');

    console.log('| File | Lines | Findings | Time | Steps | Cost | Status |');
    console.log('|---|---|---|---|---|---|---|');
    for (const f of perFile) {
        console.log(`| ${f.path} | ${f.lines} | ${f.found} | ${f.elapsed}s | ${f.steps || '?'} | $${f.cost} | ${f.status} |`);
    }
}

main().catch(err => { console.error('Scan failed:', err.message); console.error(err.stack); process.exit(1); });
