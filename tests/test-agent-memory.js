/**
 * Test the agent memory store and transcript compression.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');

// Test in a temp workspace
const tmpDir = path.join(os.tmpdir(), 'securecode-memory-test-' + Date.now());
fs.mkdirSync(tmpDir, { recursive: true });

const {
    loadAgentMemory,
    recordFalsePositive,
    removeFalsePositive,
    addKnownFact,
    clearAgentMemory,
    formatMemoryForPrompt,
} = require('../dist/project-map/agentMemory');

let pass = 0, fail = 0;
function check(name, cond) {
    if (cond) { pass++; console.log('PASS: ' + name); }
    else { fail++; console.log('FAIL: ' + name); }
}

async function main() {
    console.log('=== Agent Memory Tests ===\n');

    // Test 1: Empty memory on fresh workspace
    console.log('Test 1: Empty memory on fresh workspace');
    const mem1 = loadAgentMemory(tmpDir);
    check('version is 1', mem1.version === 1);
    check('no false positives', mem1.falsePositives.length === 0);
    check('no known facts', mem1.knownFacts.length === 0);

    // Test 2: Record a false positive
    console.log('\nTest 2: Record a false positive');
    const fp1 = recordFalsePositive(tmpDir, {
        filePath: 'src/gateway/rate-limit.ts',
        findingType: 'missing_rate_limiting',
        line: 42,
        evidence: 'if (operatorConfig.enableRateLimit) { ... }',
        reason: 'Operator opt-in feature, not a vulnerability',
    });
    check('fp recorded with id', fp1 && fp1.id.startsWith('fp_'));
    check('fp has correct type', fp1.findingType === 'missing_rate_limiting');
    check('fp has evidenceHash', fp1.evidenceHash.length === 16);

    // Test 3: Memory persisted to disk
    console.log('\nTest 3: Memory persisted to disk');
    const mem2 = loadAgentMemory(tmpDir);
    check('1 false positive loaded', mem2.falsePositives.length === 1);
    check('fp type matches', mem2.falsePositives[0].findingType === 'missing_rate_limiting');

    // Test 4: Dedup — same evidence + type should not create duplicate
    console.log('\nTest 4: Dedup false positives');
    const fp2 = recordFalsePositive(tmpDir, {
        filePath: 'src/gateway/rate-limit.ts',
        findingType: 'missing_rate_limiting',
        line: 42,
        evidence: 'if (operatorConfig.enableRateLimit) { ... }',
        reason: 'Updated reason for same FP',
    });
    const mem3 = loadAgentMemory(tmpDir);
    check('still only 1 false positive', mem3.falsePositives.length === 1);
    check('reason was updated', mem3.falsePositives[0].reason === 'Updated reason for same FP');

    // Test 5: Different evidence creates new entry
    console.log('\nTest 5: Different evidence creates new entry');
    recordFalsePositive(tmpDir, {
        filePath: 'src/app/api/users/route.ts',
        findingType: 'information_disclosure',
        line: 25,
        evidence: 'res.json({ user: { email: true } })',
        reason: 'Team tool — emails intentionally shared',
    });
    const mem4 = loadAgentMemory(tmpDir);
    check('2 false positives now', mem4.falsePositives.length === 2);

    // Test 6: Add known fact
    console.log('\nTest 6: Add known fact');
    const fact1 = addKnownFact(tmpDir, 'Project uses requireMembership for auth', 'src/lib/authz.ts:12');
    check('fact recorded with id', fact1 && fact1.id.startsWith('fact_'));
    const mem5 = loadAgentMemory(tmpDir);
    check('1 known fact', mem5.knownFacts.length === 1);

    // Test 7: Dedup known facts
    console.log('\nTest 7: Dedup known facts');
    const fact2 = addKnownFact(tmpDir, 'Project uses requireMembership for auth', 'src/lib/authz.ts:12');
    check('duplicate fact returns null', fact2 === null);
    const mem6 = loadAgentMemory(tmpDir);
    check('still 1 known fact', mem6.knownFacts.length === 1);

    // Test 8: formatMemoryForPrompt
    console.log('\nTest 8: formatMemoryForPrompt');
    const mem7 = loadAgentMemory(tmpDir);
    const formatted = formatMemoryForPrompt(mem7);
    check('formatted contains "Workspace memory"', formatted.includes('Workspace memory'));
    check('formatted contains false positive type', formatted.includes('missing_rate_limiting'));
    check('formatted contains known fact', formatted.includes('requireMembership'));
    check('formatted contains "DO NOT report"', formatted.includes('DO NOT report'));

    // Test 9: Empty memory formats to empty string
    console.log('\nTest 9: Empty memory formats to empty string');
    const emptyFormatted = formatMemoryForPrompt({ version: 1, falsePositives: [], knownFacts: [] });
    check('empty memory = empty string', emptyFormatted === '');

    // Test 10: Remove false positive by ID
    console.log('\nTest 10: Remove false positive by ID');
    const mem8 = loadAgentMemory(tmpDir);
    const firstFpId = mem8.falsePositives[0].id;
    const removed = removeFalsePositive(tmpDir, firstFpId);
    check('remove returns true', removed === true);
    const mem9 = loadAgentMemory(tmpDir);
    check('1 false positive after removal', mem9.falsePositives.length === 1);
    check('correct one was removed', !mem9.falsePositives.find(fp => fp.id === firstFpId));

    // Test 11: Remove non-existent ID returns false
    console.log('\nTest 11: Remove non-existent ID');
    const removed2 = removeFalsePositive(tmpDir, 'fp_nonexistent');
    check('remove non-existent returns false', removed2 === false);

    // Test 12: Clear all memory
    console.log('\nTest 12: Clear all memory');
    const cleared = clearAgentMemory(tmpDir);
    check('clear returns true', cleared === true);
    const mem10 = loadAgentMemory(tmpDir);
    check('memory is empty after clear', mem10.falsePositives.length === 0 && mem10.knownFacts.length === 0);

    // Test 13: Clear when no file exists
    console.log('\nTest 13: Clear when no file exists');
    const cleared2 = clearAgentMemory(tmpDir);
    check('clear returns false when no file', cleared2 === false);

    // Test 14: Invalid input returns null
    console.log('\nTest 14: Invalid input returns null');
    const invalid = recordFalsePositive(tmpDir, {
        filePath: '',
        findingType: 'sql_injection',
        line: 1,
        evidence: 'test',
        reason: 'test',
    });
    check('empty filePath returns null', invalid === null);

    // Cleanup
    try { fs.rmSync(tmpDir, { recursive: true }); } catch { /* best effort */ }

    console.log('\n=== Results: ' + pass + ' pass, ' + fail + ' fail ===');
    process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => {
    console.error('Fatal:', e);
    process.exit(1);
});
