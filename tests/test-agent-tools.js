/**
 * Test the 3 new agent tools: get_endpoints, list_imports, list_files.
 */
const { discoverEndpoints, formatEndpoints } = require('../dist/project-map/endpointDiscovery');
const { listImports, formatImports } = require('../dist/utils/listImports');
const { listFiles, formatFileList } = require('../dist/utils/listFiles');

async function main() {
    const workspaceRoot = process.argv[2] || '.';
    var pass = 0, fail = 0;

    // Test 1: get_endpoints
    console.log('=== Test 1: get_endpoints ===');
    try {
        var endpoints = await discoverEndpoints(workspaceRoot);
        console.log(formatEndpoints(endpoints));
        if (endpoints.length > 0) {
            console.log('PASS: Found ' + endpoints.length + ' endpoints');
            pass++;
        } else {
            console.log('PASS: No endpoints found (expected for non-web projects)');
            pass++;
        }
    } catch (e) {
        console.log('FAIL: ' + e.message);
        fail++;
    }

    // Test 2: list_imports
    console.log('\n=== Test 2: list_imports ===');
    try {
        var testFile = 'src/attack/agentScanExecutor.ts';
        var imports = await listImports(workspaceRoot, testFile);
        console.log(formatImports(imports, testFile));
        if (imports.length >= 5) {
            console.log('PASS: Found ' + imports.length + ' imports');
            pass++;
        } else {
            console.log('FAIL: Expected >= 5 imports, got ' + imports.length);
            fail++;
        }
    } catch (e) {
        console.log('FAIL: ' + e.message);
        fail++;
    }

    // Test 3: list_files
    console.log('\n=== Test 3: list_files ===');
    try {
        var files = listFiles(workspaceRoot, { glob: '*.ts' });
        var lines = formatFileList(files).split('\n');
        console.log(lines.slice(0, 10).join('\n') + '\n  ...');
        if (files.length > 0) {
            console.log('PASS: Found ' + files.length + ' .ts files');
            pass++;
        } else {
            console.log('FAIL: No files found');
            fail++;
        }
    } catch (e) {
        console.log('FAIL: ' + e.message);
        fail++;
    }

    // Test 4: list_files with directory filter
    console.log('\n=== Test 4: list_files (dir=src/utils) ===');
    try {
        var files = listFiles(workspaceRoot, { dir: 'src/utils' });
        console.log(formatFileList(files));
        if (files.length > 0) {
            console.log('PASS: Found ' + files.length + ' files in src/utils');
            pass++;
        } else {
            console.log('FAIL: No files found in src/utils');
            fail++;
        }
    } catch (e) {
        console.log('FAIL: ' + e.message);
        fail++;
    }

    console.log('\n=== Results: ' + pass + ' pass, ' + fail + ' fail ===');
    process.exit(fail > 0 ? 1 : 0);
}

main().catch(function (e) {
    console.error('Fatal:', e);
    process.exit(1);
});
