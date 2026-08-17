/**
 * REAL Test Lab Benchmark — uses the actual MCP toolAgentScan with real tools.
 *
 * Unlike the API-side benchmark (which simulates tool execution), this runs
 * the REAL MCP code: real tree-sitter taint tracking, real guard evaluation,
 * real filesystem reads, real ripgrep search, real endpoint policy checker.
 *
 * Usage:
 *   node tests/benchmark-real.js <JWT_TOKEN>
 *
 * Or set SECURECODE_API_TOKEN env var.
 */

const path = require('path');
const fs = require('fs');

// Import the REAL MCP tool (compiled dist/)
const { toolAgentScan } = require('../dist/tools/agentScan');

const PROJECT = process.argv[3] && !process.argv[3].startsWith('eyJ') ? process.argv[3] : 'taskforge';
const TEST_LAB = path.resolve(__dirname, '..', '..', 'test_lab', PROJECT);
const GROUND_TRUTH_PATH = path.join(TEST_LAB, 'ground-truth.json');
const API_URL = process.env.SECURECODE_API_URL || 'https://api.usesecurecode.tech';

// ── Types ───────────────────────────────────────────────────────────────────

const LINE_TOLERANCE = 5;

const TYPE_ALIASES = {
    'access_control': 'broken_access_control',
    'access-control': 'broken_access_control',
    'authorization': 'broken_access_control',
    'privilege_escalation': 'broken_access_control',
    'privilege-escalation': 'broken_access_control',
    'missing_authorization': 'broken_access_control',
    'missing_ownership': 'broken_access_control',
    'missing-ownership': 'broken_access_control',
    'missing-ownership-update': 'broken_access_control',
    'missing-ownership-delete': 'broken_access_control',
    'idor': 'broken_access_control',
    'missing_auth': 'broken_access_control',
    'missing-auth': 'broken_access_control',
    'info_disclosure': 'information_disclosure',
    'information-disclosure': 'information_disclosure',
    'pii_leak': 'information_disclosure',
    'pii-leak': 'information_disclosure',
    'data_exposure': 'information_disclosure',
    'enum': 'user_enumeration',
    'enumeration': 'user_enumeration',
    'user-enum': 'user_enumeration',
    'email_enumeration': 'user_enumeration',
    'timing': 'user_enumeration',
    'timing_attack': 'user_enumeration',
    'timing-side-channel': 'user_enumeration',
    'rate_limit': 'missing_rate_limiting',
    'rate-limiting': 'missing_rate_limiting',
    'no_rate_limit': 'missing_rate_limiting',
    'brute_force': 'missing_rate_limiting',
    'secret': 'hardcoded_secret',
    'hardcoded-secret': 'hardcoded_secret',
    'api_key': 'hardcoded_secret',
    'sensitive_data': 'hardcoded_secret',
    'sqli': 'sql_injection',
    'xss': 'xss',
    'command_injection': 'command_injection',
    'ssrf': 'ssrf',
    'path_traversal': 'path_traversal',
    'prototype_pollution': 'prototype_pollution',
    'open_redirect': 'open_redirect',
    'ssti': 'ssti',
    'ldap_injection': 'ldap_injection',
    'header_injection': 'header_injection',
    'nosql_injection': 'nosql_injection',
};

function normalizeType(t) {
    const lower = (t || '').toLowerCase().replace(/[\s-]+/g, '_');
    return TYPE_ALIASES[lower] || TYPE_ALIASES[lower.replace(/^ai\./, '')] || lower;
}

function typeMatches(expected, reported) {
    const e = normalizeType(expected);
    const r = normalizeType(reported);
    if (e === r) return true;
    // Partial match (same family)
    if (e.includes(r) || r.includes(e)) return true;
    return false;
}

function lineMatches(expectedLine, reportedLine) {
    return Math.abs(reportedLine - expectedLine) <= LINE_TOLERANCE;
}

function matchFindings(expected, reported) {
    const results = [];
    const usedReported = new Set();

    const sortedExpected = [...expected].sort((a, b) => {
        const rank = { critical: 0, high: 1, medium: 2, low: 3 };
        return (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4);
    });

    for (const exp of sortedExpected) {
        let bestIdx = -1;
        let bestScore = -1;

        for (let i = 0; i < reported.length; i++) {
            if (usedReported.has(i)) continue;
            const rep = reported[i];
            let score = 0;
            if (typeMatches(exp.type, rep.type)) score += 10;
            const lineDiff = Math.abs(rep.line - exp.line);
            if (lineDiff <= LINE_TOLERANCE) score += 5 + (LINE_TOLERANCE - lineDiff);
            if (score > bestScore) { bestScore = score; bestIdx = i; }
        }

        if (bestIdx >= 0 && bestScore >= 5) {
            usedReported.add(bestIdx);
            results.push({ expected: exp, reported: reported[bestIdx], match: 'tp' });
        } else {
            results.push({ expected: exp, reported: null, match: 'fn' });
        }
    }

    for (let i = 0; i < reported.length; i++) {
        if (!usedReported.has(i)) {
            results.push({ expected: null, reported: reported[i], match: 'fp' });
        }
    }

    return results;
}

// ── Main ───────────────────────────────────────────────────────────────────

async function main() {
    const token = process.argv[2] || process.env.SECURECODE_API_TOKEN;
    if (!token) {
        console.error('Usage: node tests/benchmark-real.js <JWT_TOKEN> [project]');
        console.error('   or: SECURECODE_API_TOKEN=<token> node tests/benchmark-real.js [project]');
        console.error('   project: taskforge (default) | openclaw | synara | ...');
        process.exit(1);
    }

    const groundTruth = JSON.parse(fs.readFileSync(GROUND_TRUTH_PATH, 'utf8'));
    console.log('=== REAL MCP Agent Benchmark ===');
    console.log(`Workspace: ${TEST_LAB}`);
    console.log(`API: ${API_URL}`);
    console.log(`Files: ${groundTruth.files.length}, Expected findings: ${groundTruth.files.reduce((a, f) => a + f.expectedFindings.length, 0)}\n`);

    const ctx = {
        apiUrl: API_URL,
        apiToken: token,
        workspaceRoot: TEST_LAB,
    };

    let tp = 0, fp = 0, fn = 0, tn = 0;
    let totalElapsed = 0;
    let totalProven = 0;
    let totalCost = 0;
    let totalSteps = 0;
    const perFile = [];

    for (let i = 0; i < groundTruth.files.length; i++) {
        const gtFile = groundTruth.files[i];
        console.log(`[${i + 1}/${groundTruth.files.length}] ${gtFile.path} (${gtFile.expectedFindings.length} expected)`);

        const args = {
            filePath: gtFile.path,
            language: gtFile.language,
            _noCache: process.argv.includes('--no-cache'),
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

        // Extract agent findings (with proven stamps + fixes)
        const findings = (result.agentFindings || []).map(f => ({
            line: f.line,
            lineEnd: f.lineEnd,
            type: f.type,
            severity: f.severity,
            confidence: f.confidence,
            proven: f.proven || 'N/A',
            why: f.why || '',
            evidence: f.evidence || '',
            hasFix: !!(f.fix && f.fix.fixedCode),
            fixSummary: f.fix?.fixSummary || '',
        }));

        const matches = matchFindings(gtFile.expectedFindings, findings);
        const fileTp = matches.filter(m => m.match === 'tp').length;
        const fileFp = matches.filter(m => m.match === 'fp').length;
        const fileFn = matches.filter(m => m.match === 'fn').length;
        const isClean = gtFile.expectedFindings.length === 0;
        const isTn = isClean && findings.length === 0;

        tp += fileTp;
        fp += fileFp;
        fn += fileFn;
        if (isTn) tn++;
        totalElapsed += elapsed;
        totalProven += (result.provenCount || 0);
        totalCost += (result.costSpentUsd || 0);
        totalSteps += (result.stepsUsed || 0);

        const cachedTag = result.cached ? ' [CACHED]' : '';
        console.log(`  Found: ${findings.length} | TP: ${fileTp} FP: ${fileFp} FN: ${fileFn} | ${elapsed.toFixed(1)}s | steps: ${result.stepsUsed || '?'} | proven: ${result.provenCount || 0}/${findings.filter(f => f.severity === 'high' || f.severity === 'critical').length} | fixes: ${findings.filter(f => f.hasFix).length}/${findings.length}${cachedTag}`);

        // Print per-finding details
        for (const f of findings) {
            const match = matches.find(m => m.reported === f);
            const status = match ? match.match.toUpperCase() : '?';
            const fixTag = f.hasFix ? ' [+FIX]' : '';
            console.log(`    [${f.severity}] ${f.type} L${f.line} | ${status} | proven: ${f.proven}${fixTag} | ${f.why.slice(0, 100)}`);
        }
        for (const m of matches.filter(m => m.match === 'fn')) {
            console.log(`    MISSED: [${m.expected.severity}] ${m.expected.type} L${m.expected.line} — ${m.expected.description.slice(0, 100)}`);
        }

        perFile.push({
            path: gtFile.path,
            expected: gtFile.expectedFindings.length,
            found: findings.length,
            tp: fileTp, fp: fileFp, fn: fileFn,
            elapsed: elapsed.toFixed(1),
            steps: result.stepsUsed,
            proven: result.provenCount,
        });
        console.log('');
    }

    // Compute metrics
    const totalRealVuln = tp + fn;
    const totalFindings = tp + fp;
    const totalCleanFiles = groundTruth.files.filter(f => f.expectedFindings.length === 0).length;
    const totalSafe = tn + fp;
    const recall = totalRealVuln ? tp / totalRealVuln : 0;
    const precision = totalFindings ? tp / totalFindings : 1;
    const fpr = totalSafe ? fp / totalSafe : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;

    console.log('=== RESULTS ===');
    console.log(`Recall:      ${(recall * 100).toFixed(1)}% (${tp}/${totalRealVuln})`);
    console.log(`Precision:   ${(precision * 100).toFixed(1)}% (${tp}/${totalFindings})`);
    console.log(`FPR:         ${(fpr * 100).toFixed(1)}% (${fp}/${totalSafe})`);
    console.log(`F1:          ${(f1 * 100).toFixed(1)}%`);
    console.log(`Confusion:   TP=${tp} FP=${fp} FN=${fn} TN=${tn}`);
    console.log(`Avg time:    ${(totalElapsed / groundTruth.files.length).toFixed(1)}s`);
    console.log(`Total cost:  $${totalCost.toFixed(4)}`);
    console.log(`Proven:      ${totalProven}`);
    console.log('');

    console.log('| File | Expected | Found | TP | FP | FN | Time | Steps | Proven |');
    console.log('|---|---|---|---|---|---|---|---|---|');
    for (const f of perFile) {
        console.log(`| ${f.path} | ${f.expected} | ${f.found} | ${f.tp} | ${f.fp} | ${f.fn} | ${f.elapsed}s | ${f.steps || '?'} | ${f.proven || 0} |`);
    }
}

main().catch(err => { console.error('Benchmark failed:', err.message); console.error(err.stack); process.exit(1); });
