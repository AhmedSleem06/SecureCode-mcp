'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

const MCP_DIST = path.join(__dirname, '..', 'dist');
const { toolScanDependencies } = require(path.join(MCP_DIST, 'tools', 'scanDependencies.js'));

const WORKSPACE = path.join(__dirname, '..', '..', 'test_lab', 'openclaw');

async function main() {
    console.log('=== Testing securecode.scan-dependencies on openclaw ===');
    console.log(`Workspace: ${WORKSPACE}`);
    const start = Date.now();

    try {
        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: WORKSPACE },
            {},
        );

        const elapsed = ((Date.now() - start) / 1000).toFixed(1);
        console.log(`\nCompleted in ${elapsed}s`);
        console.log(`Lockfiles found: ${result.lockfiles.length}`);
        for (const lf of result.lockfiles) {
            console.log(`  - ${path.basename(lf)}`);
        }
        console.log(`Packages scanned: ${result.packageCount}`);
        console.log(`Unresolved: ${result.unresolvedCount}`);
        console.log(`GHSA skipped: ${result.ghsaSkipped}`);
        console.log(`\nFindings: ${result.findings.length}`);

        // Group by severity
        const errors = result.findings.filter(f => f.severity === 'ERROR');
        const warnings = result.findings.filter(f => f.severity === 'WARNING');
        console.log(`  ERROR: ${errors.length}`);
        console.log(`  WARNING: ${warnings.length}`);

        // Show top 20 findings
        console.log('\n=== Top 20 Findings ===');
        const sorted = result.findings.sort((a, b) => {
            if (a.severity !== b.severity) return a.severity === 'ERROR' ? -1 : 1;
            return a.dependency?.name?.localeCompare(b.dependency?.name || '') || 0;
        });
        for (const f of sorted.slice(0, 20)) {
            const dep = f.dependency || {};
            const fix = dep.fixedVersion ? ` → fix: ${dep.fixedVersion}` : '';
            const lic = dep.license ? ` [${dep.license}]` : '';
            console.log(`  [${f.severity}] ${dep.name || f.check_id}@${dep.installedVersion || '?'}${fix}${lic}`);
            console.log(`    ${f.message.slice(0, 200)}`);
        }

        if (result.findings.length > 20) {
            console.log(`\n... and ${result.findings.length - 20} more findings`);
        }

        console.log('\n=== DEPENDENCY SCAN COMPLETE ===');
    } catch (err) {
        console.error('\n[ERROR]', err.message);
        if (err.stack) console.error(err.stack);
        process.exitCode = 1;
    }
}

main();
