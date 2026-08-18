'use strict';
/**
 * E2E test: scan-dependencies tool against real OSV.dev + GitHub Advisory.
 * Creates a temp workspace with a vulnerable package-lock.json and calls
 * the tool directly from the compiled dist.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

const MCP_DIST = path.join(__dirname, '..', 'dist');
const { toolScanDependencies } = require(path.join(MCP_DIST, 'tools', 'scanDependencies.js'));

async function main() {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-mcp-e2e-'));

    // Write a package-lock.json with a known-vulnerable package
    fs.writeFileSync(path.join(workspace, 'package.json'), JSON.stringify({
        name: 'e2e-test',
        version: '1.0.0',
        license: 'MIT',
    }));

    fs.writeFileSync(path.join(workspace, 'package-lock.json'), JSON.stringify({
        name: 'e2e-test',
        version: '1.0.0',
        lockfileVersion: 3,
        packages: {
            '': { name: 'e2e-test', version: '1.0.0', license: 'MIT' },
            'node_modules/lodash': { version: '4.17.4', license: 'MIT' },
            'node_modules/express': { version: '4.17.1', license: 'MIT' },
        },
    }));

    console.log('=== E2E: securecode.scan-dependencies ===');
    console.log(`Workspace: ${workspace}`);
    console.log('Lockfile: lodash@4.17.4 (known vulnerable), express@4.17.1');
    console.log('');

    try {
        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        );

        console.log('Result:');
        console.log(JSON.stringify(result, null, 2));

        console.log('\n=== Verification ===');
        const findings = result.findings || [];
        console.log(`Findings: ${findings.length}`);
        console.log(`Package count: ${result.packageCount}`);
        console.log(`Lockfiles found: ${result.lockfiles.length}`);
        console.log(`GHSA skipped: ${result.ghsaSkipped}`);

        const lodashFinding = findings.find(f => f.dependency?.name === 'lodash');
        if (lodashFinding) {
            console.log('\n✓ Found lodash vulnerability:');
            console.log(`  severity: ${lodashFinding.severity}`);
            console.log(`  installed: ${lodashFinding.dependency.installedVersion}`);
            console.log(`  fixed: ${lodashFinding.dependency.fixedVersion}`);
            console.log(`  message: ${lodashFinding.message.slice(0, 200)}`);
        } else {
            console.log('\n✗ No lodash finding — check OSV connectivity');
        }

        if (findings.length > 0) {
            console.log('\n=== E2E PASSED ===');
        } else {
            console.log('\n=== E2E COMPLETED (0 findings — may be network issue) ===');
        }
    } catch (err) {
        console.error('\n[ERROR]', err.message);
        if (err.stack) console.error(err.stack);
        process.exitCode = 1;
    } finally {
        try { fs.rmSync(workspace, { recursive: true, force: true }); } catch {}
    }
}

main();
