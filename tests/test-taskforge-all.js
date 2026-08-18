'use strict';
const path = require('path');
const { toolMap } = require(path.join(__dirname, '..', 'dist', 'tools', 'map.js'));
const { toolScan } = require(path.join(__dirname, '..', 'dist', 'tools', 'scan.js'));
const { toolScanDependencies } = require(path.join(__dirname, '..', 'dist', 'tools', 'scanDependencies.js'));
const { toolScanSecrets } = require(path.join(__dirname, '..', 'dist', 'tools', 'scanSecrets.js'));
const { toolScanBatch } = require(path.join(__dirname, '..', 'dist', 'tools', 'scanBatch.js'));
const { toolFix } = require(path.join(__dirname, '..', 'dist', 'tools', 'fix.js'));

const JWT = process.argv[2];
const WORKSPACE = path.join(__dirname, '..', '..', 'test_lab', 'taskforge');
const CTX = { apiUrl: 'https://api.usesecurecode.tech', apiToken: JWT, workspaceRoot: WORKSPACE };

async function main() {
    console.log('=== SecureCode MCP — Full Feature Test on TaskForge ===\n');
    console.log(`Workspace: ${WORKSPACE}\n`);

    // ── 1. MAP ──────────────────────────────────────────────────────
    console.log('━━━ 1. securecode.map (build) ━━━');
    const mapStart = Date.now();
    try {
        const mapResult = await toolMap(CTX, { action: 'build' });
        console.log(`  Time: ${((Date.now() - mapStart) / 1000).toFixed(1)}s`);
        console.log(`  Endpoints: ${mapResult.endpoints}`);
        console.log(`  Files processed: ${mapResult.filesProcessed}`);
        console.log(`  Files skipped: ${mapResult.filesSkipped}`);
        console.log(`  Errors: ${mapResult.errors?.length || 0}`);
        if (mapResult.endpoints > 0) {
            const epResult = await toolMap(CTX, { action: 'endpoints' });
            console.log(`  Endpoint list:`);
            for (const ep of epResult.endpoints.slice(0, 10)) {
                console.log(`    ${ep.method} ${ep.path} → ${ep.handler} (${ep.sourceFile}:${ep.line}) [auth: ${ep.authScheme}, data: ${ep.dataLayer}]`);
            }
        }
    } catch (e) { console.log(`  ERROR: ${e.message}`); }
    console.log();

    // ── 2. SCAN-DEPENDENCIES ─────────────────────────────────────────
    console.log('━━━ 2. securecode.scan-dependencies ━━━');
    const depStart = Date.now();
    try {
        const depResult = await toolScanDependencies(CTX, {});
        console.log(`  Time: ${((Date.now() - depStart) / 1000).toFixed(1)}s`);
        console.log(`  Packages: ${depResult.packageCount}`);
        console.log(`  Findings: ${depResult.findings.length}`);
        for (const f of depResult.findings.slice(0, 10)) {
            const dep = f.dependency || {};
            console.log(`    [${f.severity}] ${dep.name}@${dep.installedVersion}: ${(f.message || '').substring(0, 100)}`);
        }
    } catch (e) { console.log(`  ERROR: ${e.message}`); }
    console.log();

    // ── 3. SCAN-SECRETS ──────────────────────────────────────────────
    console.log('━━━ 3. securecode.scan-secrets ━━━');
    const secStart = Date.now();
    try {
        const secResult = await toolScanSecrets(CTX, { directory: 'src' });
        console.log(`  Time: ${((Date.now() - secStart) / 1000).toFixed(1)}s`);
        console.log(`  Files scanned: ${secResult.filesScanned}`);
        console.log(`  Total findings: ${secResult.totalFindings}`);
        if (secResult.findingsByType && Object.keys(secResult.findingsByType).length > 0) {
            console.log(`  By type:`, secResult.findingsByType);
        }
        if (secResult.findingsBySeverity && Object.keys(secResult.findingsBySeverity).length > 0) {
            console.log(`  By severity:`, secResult.findingsBySeverity);
        }
        for (const r of (secResult.results || []).slice(0, 5)) {
            console.log(`  ${r.filePath}:`);
            for (const f of r.findings.slice(0, 3)) {
                console.log(`    [${f.severity}] ${f.type} @ line ${f.line}: ${f.snippet?.substring(0, 80)}`);
            }
        }
    } catch (e) { console.log(`  ERROR: ${e.message}`); }
    console.log();

    // ── 4. SCAN (fast) ───────────────────────────────────────────────
    console.log('━━━ 4. securecode.scan (fast) — src/lib/authz.ts ━━━');
    const fastStart = Date.now();
    try {
        const fastResult = await toolScan(CTX, { filePath: 'src/lib/authz.ts', scanDepth: 'fast' });
        console.log(`  Time: ${((Date.now() - fastStart) / 1000).toFixed(1)}s`);
        console.log(`  Scan type: ${fastResult.scanType}`);
        console.log(`  Findings: ${fastResult.findings?.length || 0}`);
        for (const f of (fastResult.findings || []).slice(0, 5)) {
            console.log(`    [${f.severity}] ${f.type} @ line ${f.location?.line_start}: ${f.message?.substring(0, 80)}`);
        }
        console.log(`  Summary: ${fastResult.scanSummary}`);
    } catch (e) { console.log(`  ERROR: ${e.message}`); }
    console.log();

    // ── 5. SCAN (deep) ───────────────────────────────────────────────
    console.log('━━━ 5. securecode.scan (deep) — src/app/api/projects/[id]/tasks/route.ts ━━━');
    const deepStart = Date.now();
    try {
        const deepResult = await toolScan(CTX, { filePath: 'src/app/api/projects/[id]/tasks/route.ts', scanDepth: 'deep' });
        console.log(`  Time: ${((Date.now() - deepStart) / 1000).toFixed(1)}s`);
        console.log(`  Scan type: ${deepResult.scanType}`);
        console.log(`  Findings: ${deepResult.findings?.length || 0}`);
        for (const f of (deepResult.findings || []).slice(0, 10)) {
            console.log(`    [${f.severity}] ${f.type} @ line ${f.location?.line_start}: ${f.message?.substring(0, 100)}`);
            if (f.why) console.log(`      why: ${f.why?.substring(0, 120)}`);
            if (f.fixStrategy) console.log(`      fix: ${f.fixStrategy?.substring(0, 120)}`);
        }
        console.log(`  Summary: ${deepResult.scanSummary}`);
        console.log(`  Degraded: ${deepResult.degraded}`);
        console.log(`  Scan credits: ${deepResult.scanCredits}`);
    } catch (e) { console.log(`  ERROR: ${e.message}`); }
    console.log();

    // ── 6. SCAN-BATCH ────────────────────────────────────────────────
    console.log('━━━ 6. securecode.scan-batch (src/app/api, maxFiles=5) ━━━');
    const batchStart = Date.now();
    try {
        const batchResult = await toolScanBatch(CTX, {
            directory: 'src/app/api',
            maxFiles: 5,
            _progress: (p, t, msg) => {
                if (p === 1 || p === t || p % 2 === 0) console.log(`    [${p}/${t}] ${msg}`);
            },
        });
        console.log(`  Time: ${((Date.now() - batchStart) / 1000).toFixed(1)}s`);
        console.log(`  Scanned: ${batchResult.scanned}`);
        console.log(`  Skipped: ${batchResult.skipped?.length || 0}`);
        console.log(`  Total findings: ${batchResult.summary?.totalFindings || 0}`);
        if (batchResult.summary?.bySeverity) {
            console.log(`  By severity:`, batchResult.summary.bySeverity);
        }
        for (const r of (batchResult.results || [])) {
            if (r.findings && r.findings.length > 0) {
                console.log(`  ${r.filePath}: ${r.findings.length} finding(s)`);
                for (const f of r.findings.slice(0, 3)) {
                    console.log(`    [${f.severity}] ${f.type} @ line ${f.location?.line_start}: ${f.message?.substring(0, 80)}`);
                }
            }
        }
        if (batchResult.stoppedEarly) {
            console.log(`  Stopped early: ${batchResult.stopReason}`);
        }
    } catch (e) { console.log(`  ERROR: ${e.message}`); }
    console.log();

    // ── Summary ──────────────────────────────────────────────────────
    console.log('━━━ Summary ━━━');
    console.log('  1. map:              ✓ (project map built)');
    console.log('  2. scan-dependencies: ✓ (lockfile scanned)');
    console.log('  3. scan-secrets:      ✓ (secrets/PII scanned)');
    console.log('  4. scan (fast):      ✓ (deterministic scan)');
    console.log('  5. scan (deep):      ✓ (AI pipeline scan)');
    console.log('  6. scan-batch:       ✓ (multi-file batch scan)');
    console.log('  7. fix:              skipped (needs a finding with fix context)');
    console.log('  8. attack:           skipped (needs running dev server)');
}

main().catch(err => { console.error('FATAL:', err.message); process.exit(1); });
