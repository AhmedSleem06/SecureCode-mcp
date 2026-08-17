const { trackTaintCrossFile } = require('../dist/project-map/crossFileTaintTracker');
const path = require('path');

const WORKSPACE = 'C:\\Users\\Cyber\\AppData\\Local\\Temp\\opencode\\crossfile-test';

async function main() {
    console.log('=== Cross-File Taint Tracking Test ===\n');

    const results = await trackTaintCrossFile({
        workspaceRoot: WORKSPACE,
        filePath: 'src/route.ts',
        maxDepth: 3,
    });

    if (results.length === 0) {
        console.log('No cross-file taint flows found.');
    } else {
        for (const r of results) {
            console.log(`Flow: ${r.source} (${r.sourceFile}:${r.sourceLine}) → ${r.sink} (${r.sinkFile}:${r.sinkLine}) [${r.canonicalType}]`);
            for (const step of r.crossFileSteps) {
                console.log(`  ${step.file}:${step.line} ${step.operation}: ${step.description}`);
            }
            console.log('');
        }
    }

    const hasSqli = results.some(r => r.canonicalType === 'sql_injection');
    if (hasSqli) {
        console.log('PASS: Found SQLi cross-file flow');
    } else {
        console.log('FAIL: No SQLi cross-file flow found');
    }
}

main().catch(e => { console.error('Error:', e.message); console.error(e.stack); process.exit(1); });
