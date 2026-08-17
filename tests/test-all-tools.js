/**
 * Verify each agent tool works through the real executor.
 * Tests: read_file, search_code, trace_flow, trace_flow_cross_file,
 *        check_guard, check_policy (API call), get_endpoints, list_imports,
 *        list_files, finish.
 */
const path = require('path');
const fs = require('fs');
const { executeAction } = require('../dist/attack/agentScanExecutor');
const { discoverEndpoints, formatEndpoints } = require('../dist/project-map/endpointDiscovery');
const { listImports, formatImports } = require('../dist/utils/listImports');
const { listFiles, formatFileList } = require('../dist/utils/listFiles');

const WORKSPACE = path.resolve(__dirname, '..');
const TASKFORGE = path.resolve(__dirname, '..', '..', 'test_lab', 'taskforge');

// Mock ServerContext
const ctx = {
    workspaceRoot: TASKFORGE,
    apiUrl: 'https://api.usesecurecode.tech',
    apiToken: 'test',
};

// Mock ApiClient (for check_policy — we'll skip it since it needs a real API call)
const mockClient = {
    postJson: async () => { throw new Error('Mock — check_policy needs real API'); },
};

const mockTarget = {
    filePath: 'test.ts',
    language: 'typescript',
    fileContent: '',
};

var pass = 0, fail = 0;
function check(name, cond, detail) {
    if (cond) { pass++; console.log('PASS: ' + name + (detail ? ' — ' + detail : '')); }
    else { fail++; console.log('FAIL: ' + name + (detail ? ' — ' + detail : '')); }
}

async function main() {
    console.log('=== Agent Tool Verification ===\n');

    // 1. read_file
    console.log('Test 1: read_file');
    try {
        const obs = await executeAction(
            { type: 'read_file', path: 'src/lib/authz.ts', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('read_file returns content', obs.includes('File: src/lib/authz.ts'));
        check('read_file has line numbers', /^\d+: /m.test(obs));
    } catch (e) { check('read_file', false, e.message); }

    // 2. search_code
    console.log('\nTest 2: search_code');
    try {
        const obs = await executeAction(
            { type: 'search_code', pattern: 'requireMembership', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('search_code finds matches', obs.includes('requireMembership') || obs.includes('No matches'));
    } catch (e) { check('search_code', false, e.message); }

    // 3. trace_flow
    console.log('\nTest 3: trace_flow');
    try {
        const obs = await executeAction(
            { type: 'trace_flow', filePath: 'src/app/api/projects/[id]/route.ts', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('trace_flow returns result', obs.includes('taint') || obs.includes('No taint flows'));
    } catch (e) { check('trace_flow', false, e.message); }

    // 4. trace_flow_cross_file
    console.log('\nTest 4: trace_flow_cross_file');
    try {
        const obs = await executeAction(
            { type: 'trace_flow_cross_file', filePath: 'src/app/api/projects/[id]/route.ts', maxDepth: 3, rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('trace_flow_cross_file returns result', obs.includes('cross-file') || obs.includes('No cross-file taint'));
    } catch (e) { check('trace_flow_cross_file', false, e.message); }

    // 5. check_guard
    console.log('\nTest 5: check_guard');
    try {
        const obs = await executeAction(
            { type: 'check_guard', filePath: 'src/lib/authz.ts', guardName: 'requireMembership', attackType: 'broken_access_control', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('check_guard returns verdict', obs.includes('EFFECTIVE') || obs.includes('NOT EFFECTIVE') || obs.includes('not found'));
    } catch (e) { check('check_guard', false, e.message); }

    // 6. check_policy — needs real API, skip but verify it's wired
    console.log('\nTest 6: check_policy (wiring only — needs real API)');
    try {
        const obs = await executeAction(
            { type: 'check_policy', filePath: 'src/app/api/projects/[id]/route.ts', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        // Will fail with mock client — that's expected
        check('check_policy is wired (fails on mock client)', obs.includes('Error') || obs.includes('error'));
    } catch (e) { check('check_policy wiring', false, e.message); }

    // 7. get_endpoints
    console.log('\nTest 7: get_endpoints');
    try {
        const obs = await executeAction(
            { type: 'get_endpoints', glob: '*.ts', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('get_endpoints finds routes', obs.includes('endpoint') && obs.includes('nextjs'));
        check('get_endpoints finds PATCH', obs.includes('PATCH'));
        check('get_endpoints finds DELETE', obs.includes('DELETE'));
    } catch (e) { check('get_endpoints', false, e.message); }

    // 8. list_imports
    console.log('\nTest 8: list_imports');
    try {
        const obs = await executeAction(
            { type: 'list_imports', filePath: 'src/lib/authz.ts', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('list_imports returns imports', obs.includes('Imports') || obs.includes('No imports'));
    } catch (e) { check('list_imports', false, e.message); }

    // 9. list_files
    console.log('\nTest 9: list_files');
    try {
        const obs = await executeAction(
            { type: 'list_files', path: 'src/lib', glob: '*.ts', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('list_files returns files', obs.includes('source file') || obs.includes('No source files'));
        check('list_files found .ts files', obs.includes('.ts'));
    } catch (e) { check('list_files', false, e.message); }

    // 10. finish — handled by loop, not executor, just verify it returns empty
    console.log('\nTest 10: finish (executor returns empty)');
    try {
        const obs = await executeAction(
            { type: 'finish', findings: [], summary: 'test', rationale: 'test' },
            ctx, 'run1', mockClient, mockTarget
        );
        check('finish returns empty string', obs === '');
    } catch (e) { check('finish', false, e.message); }

    // 11-14. Memory tools
    console.log('\nTest 11: record_false_positive (via agentMemory module)');
    const {
        recordFalsePositive, loadAgentMemory, clearAgentMemory, addKnownFact, formatMemoryForPrompt
    } = require('../dist/project-map/agentMemory');
    const tmpDir = path.join(require('os').tmpdir(), 'securecode-tool-test-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });
    try {
        const fp = recordFalsePositive(tmpDir, {
            filePath: 'test.ts', findingType: 'xss', line: 10,
            evidence: 'test evidence', reason: 'test reason'
        });
        check('record_false_positive works', fp && fp.id.startsWith('fp_'));
    } catch (e) { check('record_false_positive', false, e.message); }

    console.log('\nTest 12: get_agent_memory (via loadAgentMemory)');
    try {
        const mem = loadAgentMemory(tmpDir);
        check('get_agent_memory has 1 FP', mem.falsePositives.length === 1);
    } catch (e) { check('get_agent_memory', false, e.message); }

    console.log('\nTest 13: add_known_fact');
    try {
        const fact = addKnownFact(tmpDir, 'Test fact', 'test.ts:1');
        check('add_known_fact works', fact && fact.id.startsWith('fact_'));
    } catch (e) { check('add_known_fact', false, e.message); }

    console.log('\nTest 14: clear_agent_memory');
    try {
        const cleared = clearAgentMemory(tmpDir);
        check('clear_agent_memory works', cleared === true);
        const memAfter = loadAgentMemory(tmpDir);
        check('memory is empty after clear', memAfter.falsePositives.length === 0);
    } catch (e) { check('clear_agent_memory', false, e.message); }

    try { fs.rmSync(tmpDir, { recursive: true }); } catch {}

    console.log('\n=== Results: ' + pass + ' pass, ' + fail + ' fail ===');
    process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => {
    console.error('Fatal:', e);
    process.exit(1);
});
