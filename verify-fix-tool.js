const path = require('path');
const fs = require('fs');
const { toolFix } = require('./dist/tools/fix');

const creds = JSON.parse(fs.readFileSync(path.join(require('os').homedir(), '.securecode', 'credentials.json'), 'utf8'));
const SYNARA = path.resolve(__dirname, '..', 'test_lab', 'synara');

const ctx = {
    apiUrl: creds.apiUrl,
    apiToken: creds.apiToken,
    workspaceRoot: SYNARA,
};

(async () => {
    console.log('FIX_TEST_STARTING');
    const result = await toolFix(ctx, {
        filePath: 'apps/server/src/agentGateway/httpRoute.ts',
        language: 'typescript',
        vulnerabilityType: 'broken_access_control',
        lineStart: 123,
        lineEnd: 150,
        evidenceSnippet: 'stdioBootstrapRouteLayer (POST /mcp/bootstrap) exchanges a bootstrap token for a full session bearer token without verifying the caller identity',
    });
    console.log('FIX_RESULT_JSON_START');
    console.log(JSON.stringify(result, (k, v) => typeof v === 'string' && v.length > 900 ? v.slice(0, 900) + '...[truncated]' : v, 1));
    console.log('FIX_TEST_DONE');
    process.exit(0);
})().catch((e) => { console.error('FIX_TEST_FAILED:', e.message); process.exit(1); });
