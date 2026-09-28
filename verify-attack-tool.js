const path = require('path');
const fs = require('fs');
const { toolAttack } = require('./dist/tools/attack');

const creds = JSON.parse(fs.readFileSync(path.join(require('os').homedir(), '.securecode', 'credentials.json'), 'utf8'));
const ctx = {
    apiUrl: creds.apiUrl,
    apiToken: creds.apiToken,
    workspaceRoot: 'C:/Users/Cyber/AppData/Local/Temp/securecode-attack-ws',
};

(async () => {
    console.log('ATTACK_TEST_STARTING');
    const result = await toolAttack(ctx, {
        filePath: 'server.js',
        port: 3111,
        vulnerabilityType: 'sql_injection',
    });
    console.log('ATTACK_RESULT_JSON_START');
    console.log(JSON.stringify(result, (k, v) => typeof v === 'string' && v.length > 1200 ? v.slice(0, 1200) + '...[truncated]' : v, 1));
    console.log('ATTACK_TEST_DONE');
    process.exit(0);
})().catch((e) => { console.error('ATTACK_TEST_FAILED:', e.message); process.exit(1); });
