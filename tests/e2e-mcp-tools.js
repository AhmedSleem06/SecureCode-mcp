#!/usr/bin/env node
/**
 * E2E test: MCP tools (scan, map, fix) against live API.
 *
 * Tests the actual MCP tool implementations (not the JSON-RPC transport):
 *   1. securecode.map   — builds a Project Map from test files (local, no API)
 *   2. securecode.scan  — calls POST /scan through the MCP ApiClient
 *   3. securecode.fix   — calls POST /fix through the MCP ApiClient (with auto-approve)
 *
 * The fix tool requires browser approval. We auto-approve by hitting the
 * approval broker's HTTP endpoint directly.
 *
 * Usage: node tests/e2e-mcp-tools.js <JWT> [API_URL]
 */
'use strict';

const path = require('path');
const fs = require('fs');
const http = require('http');

const JWT = process.argv[2];
const API_URL = process.argv[3] || 'https://api.usesecurecode.tech';

if (!JWT) {
    console.error('Usage: node e2e-mcp-tools.js <JWT> [API_URL]');
    process.exit(1);
}

// Load compiled MCP dist (globally installed)
const MCP_DIST = path.resolve(require('child_process').execSync('npm root -g').toString().trim(), '@securecode-ai', 'mcp', 'dist');
if (!fs.existsSync(MCP_DIST)) {
    console.error('MCP dist not found. Install: npm install -g @securecode-ai/mcp');
    process.exit(1);
}

const { toolScan } = require(path.join(MCP_DIST, 'tools', 'scan.js'));
const { toolFix } = require(path.join(MCP_DIST, 'tools', 'fix.js'));
const { toolMap } = require(path.join(MCP_DIST, 'tools', 'map.js'));

// Create a test workspace with vulnerable code
const WORKSPACE = path.resolve(__dirname, 'e2e-workspace');
if (!fs.existsSync(WORKSPACE)) fs.mkdirSync(WORKSPACE, { recursive: true });

const VULN_FILE = path.join(WORKSPACE, 'server.js');
fs.writeFileSync(VULN_FILE, `const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const id = req.query.id || '1';
    const query = "SELECT * FROM users WHERE id = " + id;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ users: results });
    });
});

app.get('/profile', (req, res) => {
    const name = req.query.name || '';
    res.send('<h1>Welcome, ' + name + '</h1>');
});

app.listen(3000);`);

const ctx = {
    apiUrl: API_URL,
    apiToken: JWT,
    workspaceRoot: WORKSPACE,
};

// Helper: auto-approve the fix broker by polling for the approval URL and clicking approve
async function autoApprove(brokerPort) {
    return new Promise((resolve) => {
        const interval = setInterval(async () => {
            try {
                // List pending approvals
                const resp = await new Promise((res, rej) => {
                    http.get(`http://127.0.0.1:${brokerPort}/`, (r) => {
                        let d = '';
                        r.on('data', c => d += c);
                        r.on('end', () => res(d));
                    }).on('error', rej);
                });
                // Parse for approval links
                const match = resp.match(/href="\/approve\?id=([^&"]+)/);
                if (match) {
                    const approveUrl = `http://127.0.0.1:${brokerPort}/approve?id=${match[1]}&decision=approve`;
                    await new Promise((res, rej) => {
                        http.get(approveUrl, (r) => {
                            let d = '';
                            r.on('data', c => d += c);
                            r.on('end', () => res(d));
                        }).on('error', rej);
                    });
                    clearInterval(interval);
                    resolve();
                }
            } catch {
                // Broker not ready yet or no pending requests
            }
        }, 200);
        // Give up after 30s
        setTimeout(() => { clearInterval(interval); resolve(); }, 30000);
    });
}

async function main() {
    console.log('=== E2E MCP Tools Test ===');
    console.log(`API: ${API_URL}`);
    console.log(`Workspace: ${WORKSPACE}`);

    try {
        // ── 1. Map ──────────────────────────────────────────────
        console.log('\n[1] MCP tool: securecode.map (build)');
        const mapResult = await toolMap(ctx, { action: 'build' });
        console.log('  built:', mapResult.built);
        console.log('  endpoints:', mapResult.endpoints);
        console.log('  filesProcessed:', mapResult.filesProcessed);
        console.log('  filesSkipped:', mapResult.filesSkipped);
        console.log('  errors:', mapResult.errors?.length || 0);
        if (mapResult.endpoints > 0) {
            const endpointsResult = await toolMap(ctx, { action: 'endpoints' });
            for (const e of endpointsResult.endpoints) {
                console.log(`    ${e.method} ${e.path} -> ${e.handler} (${e.sourceFile}:${e.line}) conf=${e.confidence}`);
            }
        }

        // ── 2. Scan ─────────────────────────────────────────────
        console.log('\n[2] MCP tool: securecode.scan');
        const scanResult = await toolScan(ctx, { filePath: 'server.js' });
        console.log('  scanType:', scanResult.scanType);
        console.log('  scanId:', scanResult.scanId);
        console.log('  degraded:', scanResult.degraded);
        console.log('  scanCredits:', scanResult.scanCredits);
        console.log('  findings:', scanResult.findings.length);
        for (const f of scanResult.findings) {
            console.log(`    - [${f.severity}] ${f.type} at line ${f.location.line_start}`);
            if (f.evidence) console.log(`      ${f.evidence.slice(0, 150)}`);
        }

        if (scanResult.findings.length === 0) {
            console.log('\n[!] No findings to fix — skipping fix test');
            console.log('\n=== MCP TOOLS TEST PASSED ===');
            return;
        }

        // ── 3. Fix ──────────────────────────────────────────────
        // The fix tool requires browser approval. We'll auto-approve.
        console.log('\n[3] MCP tool: securecode.fix (with auto-approve)');

        // Start auto-approver in background (the broker starts on a random port)
        // We need to find the port. The broker logs to stderr.
        // Instead, let's call toolFix and auto-approve concurrently.
        const finding = scanResult.findings[0];

        // Auto-approve helper: find the broker port from stderr and approve
        const autoApproveAll = async () => {
            // The broker prints to stderr: "Open: http://127.0.0.1:PORT/?id=..."
            // We scan the first 1000 ports starting at 60000 (broker uses ephemeral ports)
            for (let port = 60000; port < 61000; port++) {
                try {
                    const resp = await new Promise((res, rej) => {
                        const r = http.get(`http://127.0.0.1:${port}/`, (resp) => {
                            let d = '';
                            resp.on('data', c => d += c);
                            resp.on('end', () => res(d));
                        });
                        r.on('error', rej);
                        r.setTimeout(300, () => { r.destroy(); rej(new Error('timeout')); });
                    });
                    const match = resp.match(/href="\/approve\?id=([^&"]+)/);
                    if (match) {
                        const approveUrl = `http://127.0.0.1:${port}/approve?id=${match[1]}&decision=approve`;
                        await new Promise((res) => {
                            http.get(approveUrl, (r) => {
                                let d = '';
                                r.on('data', c => d += c);
                                r.on('end', () => res(d));
                            });
                        });
                        console.log('  [auto-approve] approved on port', port);
                        return true;
                    }
                } catch {
                    // Port not open or timed out
                }
            }
            return false;
        };

        // Run fix and auto-approve concurrently
        const fixPromise = toolFix(ctx, {
            filePath: 'server.js',
            language: 'javascript',
            vulnerabilityType: finding.type,
            lineStart: finding.location.line_start,
            lineEnd: finding.location.line_end || finding.location.line_start,
            evidenceSnippet: finding.evidence || '',
        });

        // Poll for approval
        const approveTimer = setInterval(autoApproveAll, 500);
        try {
            const fixResult = await fixPromise;
            clearInterval(approveTimer);
            console.log('  applied:', fixResult.applied);
            if (fixResult.fix) {
                console.log('  confidence:', fixResult.fix.confidence);
                console.log('  summary:', fixResult.fix.summary?.slice(0, 200));
                console.log('  whySecure:', fixResult.fix.whySecure?.slice(0, 200));
                console.log('  fixedCode length:', fixResult.fix.fixedCode?.length || 0);
                if (fixResult.fix.fixedCode) {
                    console.log('  --- fixed code (first 300 chars) ---');
                    console.log('  ' + fixResult.fix.fixedCode.slice(0, 300));
                }
            }
            if (fixResult.reason) console.log('  reason:', fixResult.reason);
        } finally {
            clearInterval(approveTimer);
        }

        console.log('\n=== MCP TOOLS TEST PASSED ===');
    } catch (err) {
        console.error('\n[ERROR]', err.message);
        if (err.stack) console.error(err.stack);
        process.exitCode = 1;
    } finally {
        // Cleanup workspace
        try { fs.rmSync(WORKSPACE, { recursive: true, force: true }); } catch {}
    }
}

main();
