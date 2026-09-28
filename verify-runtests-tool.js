const path = require('path');
const fs = require('fs');
const { toolRunTests } = require('./dist/tools/runTests');

const creds = JSON.parse(fs.readFileSync(path.join(require('os').homedir(), '.securecode', 'credentials.json'), 'utf8'));
const ctx = {
    apiUrl: creds.apiUrl,
    apiToken: creds.apiToken,
    workspaceRoot: 'C:/Users/Cyber/AppData/Local/Temp/securecode-attack-ws',
};

(async () => {
    console.log('RUNTESTS_TEST_STARTING');
    const result = await toolRunTests(ctx, {
        mode: 'generated',
        runner: 'deno',
        script: `
import assert from 'node:assert';
assert.strictEqual(1 + 1, 2, 'basic arithmetic works');
console.log('PASS: basic arithmetic works');
`,
    });
    console.log('RUNTESTS_RESULT_JSON_START');
    console.log(JSON.stringify(result, (k, v) => typeof v === 'string' && v.length > 1000 ? v.slice(0, 1000) + '...[truncated]' : v, 1));
    console.log('RUNTESTS_TEST_DONE');
    process.exit(0);
})().catch((e) => { console.error('RUNTESTS_TEST_FAILED:', e.message); process.exit(1); });
