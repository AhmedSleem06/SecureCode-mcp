const path = require('path');
const { toolMap } = require('./dist/tools/map');

const WORKSPACE = path.resolve(__dirname, '..', 'test_lab', 'synara');
const ctx = { workspaceRoot: WORKSPACE, apiUrl: '', apiToken: '' };

(async () => {
    if (process.argv.includes('--build')) {
        console.log('=== REBUILDING DETERMINISTIC MAP ===');
        const t0 = Date.now();
        const built = await toolMap(ctx, { action: 'build' });
        console.log(`Rebuilt in ${((Date.now() - t0) / 1000).toFixed(1)}s — endpoints=${built.endpoints} websockets=${built.websockets} files=${built.filesProcessed}`);
    }

    const status = await toolMap(ctx, { action: 'status' });
    console.log('=== CACHE STATUS ===');
    console.log(JSON.stringify(status, null, 2));

    const map = await toolMap(ctx, {});
    console.log('\n=== SUMMARY ===');
    console.log(JSON.stringify(map.summary, null, 2));

    console.log('\n=== ENDPOINTS (all) ===');
    for (const e of map.endpoints) {
        console.log(`  ${e.method.padEnd(6)} ${e.path}  ->  ${e.handler} (${e.sourceFile}:${e.line}) auth=${e.authScheme || 'none'} conf=${e.confidence}`);
    }

    console.log('\n=== WEBSOCKETS ===');
    for (const w of map.websockets) {
        console.log(`  ${w.event} -> ${w.handler} (${w.sourceFile}:${w.line})`);
    }
})();
