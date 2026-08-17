/**
 * Demo: Full agent scan + FP dismissal + memory-informed re-scan.
 *
 * Uses a REAL false positive (not a real vulnerability) to demonstrate
 * how the agent learns. We scan a file from openclaw that has intentional
 * security design (CSP headers) — the agent reports it as a vuln, but
 * it's actually safe by design.
 *
 * Run: node tests/demo-memory-workflow.js <TOKEN>
 */
const path = require('path');
const fs = require('fs');
const os = require('os');
const { toolAgentScan } = require('../dist/tools/agentScan');
const { toolRecordFalsePositive, toolGetAgentMemory, toolClearAgentMemory } = require('../dist/tools/agentMemoryTools');
const { loadAgentMemory, clearAgentMemory } = require('../dist/project-map/agentMemory');

const TOKEN = process.argv[2] || process.env.SECURECODE_API_TOKEN;
if (!TOKEN) {
    console.error('Usage: node tests/demo-memory-workflow.js <JWT_TOKEN>');
    process.exit(1);
}

const OPENCLAW = path.resolve(__dirname, '..', '..', 'test_lab', 'openclaw');

async function main() {
    const ctx = {
        apiUrl: 'https://api.usesecurecode.tech',
        apiToken: TOKEN,
        workspaceRoot: OPENCLAW,
    };

    // Clean memory at start
    clearAgentMemory(OPENCLAW);
    console.log('=== Step 0: Memory cleared ===\n');

    // Step 1: Scan control-ui-csp.ts — agent typically reports csp_bypass as FP
    const TARGET = 'src/gateway/control-ui-csp.ts';
    console.log('=== Step 1: First scan (no memory) ===');
    console.log(`Target: ${TARGET}`);
    console.log('This file builds CSP headers for a gateway. The agent often reports');
    console.log('csp_bypass on frame-src/connect-src directives that are INTENTIONAL.\n');

    const scan1 = await toolAgentScan(ctx, {
        filePath: TARGET,
        _noCache: true,
        _progress: (p, t, msg) => process.stdout.write(`  ${msg}\r`),
    });

    const findings1 = scan1.agentFindings || [];
    console.log(`\n  Found ${findings1.length} finding(s):`);
    findings1.forEach((f, i) => {
        console.log(`  [${i}] ${f.type} L${f.line} (${f.severity}, confidence ${f.confidence})`);
        console.log(`      ${f.evidence?.slice(0, 100)}...`);
        console.log(`      proven: ${f.proven || 'N/A'}`);
    });

    if (findings1.length === 0) {
        console.log('\n  Agent found 0 findings on this scan — no FP to dismiss.');
        console.log('  Run again (cache was bypassed, results may vary).');
        clearAgentMemory(OPENCLAW);
        return;
    }

    // Step 2: View memory (should be empty)
    console.log('\n=== Step 2: View memory (should be empty) ===');
    const mem1 = await toolGetAgentMemory(ctx, {});
    console.log(`  False positives: ${mem1.falsePositives.count}`);
    console.log(`  Known facts: ${mem1.knownFacts.count}`);

    // Step 3: Dismiss the FIRST finding as false positive
    // (This is a REAL FP — CSP directives allowing http:/ws: are intentional
    // gateway design, not a vulnerability)
    const fp = findings1[0];
    console.log(`\n=== Step 3: Dismiss finding #0 as false positive ===`);
    console.log(`  Type: ${fp.type}`);
    console.log(`  Line: ${fp.line}`);
    console.log(`  Reason: "Intentional design — gateway CSP allows these directives by design"`);
    console.log(`  (This is a REAL false positive, unlike the taskforge PII example)\n`);

    await toolRecordFalsePositive(ctx, {
        filePath: TARGET,
        findingType: fp.type,
        line: fp.line,
        evidence: fp.evidence || '',
        reason: 'Intentional design — gateway CSP allows these directives by design',
        pattern: fp.evidence?.slice(0, 200),
    });

    console.log('  Recorded. The agent will not report this CSP pattern again.\n');

    // Step 4: View memory (should have 1 FP)
    console.log('=== Step 4: View memory (should have 1 FP) ===');
    const mem2 = await toolGetAgentMemory(ctx, {});
    console.log(`  False positives: ${mem2.falsePositives.count}`);
    console.log(`  Known facts: ${mem2.knownFacts.count}`);
    if (mem2.falsePositives.entries.length > 0) {
        const fpEntry = mem2.falsePositives.entries[0];
        console.log(`  First FP:`);
        console.log(`    Type: ${fpEntry.findingType}`);
        console.log(`    Pattern: ${fpEntry.pattern?.slice(0, 80)}...`);
        console.log(`    Reason: ${fpEntry.reason}`);
    }
    console.log(`\n  Formatted (what the agent sees on next scan):`);
    console.log('  ' + (mem2.formatted || '(empty)').split('\n').join('\n  '));

    // Step 5: Re-scan — agent should see memory and skip the FP
    console.log('\n=== Step 5: Second scan (with memory) ===');
    console.log('  The agent now sees the FP memory and should not report the dismissed CSP pattern.\n');

    const scan2 = await toolAgentScan(ctx, {
        filePath: TARGET,
        _noCache: true,
        _progress: (p, t, msg) => process.stdout.write(`  ${msg}\r`),
    });

    const findings2 = scan2.agentFindings || [];
    console.log(`\n  Found ${findings2.length} finding(s):`);
    findings2.forEach((f, i) => {
        console.log(`  [${i}] ${f.type} L${f.line} (${f.severity})`);
    });

    // Summary
    console.log('\n=== Summary ===');
    console.log(`  Scan 1 (no memory):  ${findings1.length} finding(s)`);
    console.log(`  Scan 2 (with memory): ${findings2.length} finding(s)`);
    console.log(`  Memory entries: ${mem2.falsePositives.count} FP(s), ${mem2.knownFacts.count} fact(s)`);
    if (findings2.length < findings1.length) {
        console.log(`  → Agent learned! Reported ${findings1.length - findings2.length} fewer finding(s).`);
    } else if (findings2.length === findings1.length) {
        console.log(`  → Agent reported same count (may not have matched the FP pattern exactly).`);
    } else {
        console.log(`  → Agent reported MORE findings (memory didn't suppress this one).`);
    }

    // Cleanup
    clearAgentMemory(OPENCLAW);
    console.log('\n  Memory cleaned up.');
}

main().catch(e => {
    console.error('Error:', e.message);
    process.exit(1);
});


main().catch(e => {
    console.error('Error:', e.message);
    process.exit(1);
});
