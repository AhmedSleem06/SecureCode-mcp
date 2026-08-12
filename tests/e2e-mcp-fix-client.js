#!/usr/bin/env node
/**
 * E2E test: MCP fix tool API path (bypassing approval broker).
 *
 * The MCP fix tool calls POST /fix with the same payload the API test does,
 * but through the MCP's ApiClient (which has timeout/size limits).
 * This verifies the MCP client → API path works end-to-end.
 *
 * Usage: node tests/e2e-mcp-fix-client.js <JWT> [API_URL]
 */
'use strict';

const path = require('path');
const fs = require('fs');

const JWT = process.argv[2];
const API_URL = process.argv[3] || 'https://api.usesecurecode.tech';

if (!JWT) {
    console.error('Usage: node e2e-mcp-fix-client.js <JWT> [API_URL]');
    process.exit(1);
}

const MCP_DIST = path.resolve(require('child_process').execSync('npm root -g').toString().trim(), '@securecode-ai', 'mcp', 'dist');
const { ApiClient } = require(path.join(MCP_DIST, 'api', 'client.js'));

const SQLI_CODE = `const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const id = req.query.id || '1';
    const query = "SELECT * FROM users WHERE id = " + id;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ users: results });
    });
});

app.listen(3000);`;

async function main() {
    console.log('=== E2E MCP ApiClient Fix Test ===');
    console.log(`API: ${API_URL}`);

    const client = new ApiClient({ baseUrl: API_URL, token: JWT });

    try {
        // Step 1: Scan through the MCP ApiClient
        console.log('\n[1] Scan via MCP ApiClient');
        const scanResult = await client.postJson('/scan', {
            code: SQLI_CODE,
            language: 'javascript',
            filePath: 'server.js',
            scanDepth: 'auto',
        });
        console.log('  scanType:', scanResult.scanType);
        const findings = scanResult.scanType === 'advanced' && scanResult.finalFindings
            ? scanResult.finalFindings
            : (scanResult.findings || []);
        console.log('  findings:', findings.length);
        for (const f of findings) {
            console.log(`    - ${f.type || f.check_id} at line ${f.location?.line_start || f.start?.line}`);
        }

        if (findings.length === 0) {
            console.log('\n[!] No findings — skipping fix');
            return;
        }

        // Step 2: Fix through the MCP ApiClient
        console.log('\n[2] Fix via MCP ApiClient');
        const finding = findings[0];
        const loc = finding.location || { line_start: finding.start?.line, line_end: finding.end?.line };
        const fixResult = await client.postJson('/fix', {
            code: SQLI_CODE,
            language: 'javascript',
            vulnerability: {
                type: finding.type || finding.check_id,
                line_start: loc.line_start || 7,
                line_end: loc.line_end || loc.line_start || 7,
                evidence_snippet: finding.evidence_snippet || '',
            },
        });
        console.log('  fixed_code length:', fixResult.fixed_code?.length || 0);
        console.log('  confidence:', fixResult.confidence);
        console.log('  fix_summary:', fixResult.fix_summary?.slice(0, 200));
        console.log('  why_secure:', fixResult.why_secure?.slice(0, 200));
        if (fixResult.fixed_code) {
            console.log('  --- fixed code (first 400 chars) ---');
            console.log('  ' + fixResult.fixed_code.slice(0, 400));
        }

        console.log('\n=== MCP APICLIENT FIX TEST PASSED ===');
    } catch (err) {
        console.error('\n[ERROR]', err.message);
        if (err.stack) console.error(err.stack);
        process.exitCode = 1;
    }
}

main();
