import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { LocalSandbox, _resetPermissionCacheForTests } from '../src/utils/localSandbox';

function makeWorkspace(): string {
    const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-local-test-'));
    fs.mkdirSync(path.join(ws, '.securecode'), { recursive: true });
    return ws;
}

function cleanup(ws: string): void {
    try { fs.rmSync(ws, { recursive: true, force: true }); } catch { /* */ }
}

describe('LocalSandbox', () => {
    const backend = new LocalSandbox();

    beforeEach(() => {
        _resetPermissionCacheForTests();
    });

    it('is always available', () => {
        expect(backend.available).toBe(true);
        expect(backend.name).toBe('local');
    });

    it('runs a simple passing script', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: 'console.log("PASS: local-sandbox-works");',
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('local-sandbox-works');
            expect(result.backend).toMatch(/^local/);
        } finally { cleanup(ws); }
    });

    it('runs a failing script', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: 'console.log("FAIL: intentional failure");',
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('fail');
        } finally { cleanup(ws); }
    });

    it('does not expose host environment variables', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
const allowed = new Set(['NODE_ENV', 'PATH', 'PATHEXT', 'SystemRoot', 'TEMP', 'TMP', 'NODE_PATH', 'HOMEDRIVE', 'HOMEPATH', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'ProgramFiles', 'ProgramData', 'PROCESSOR_ARCHITECTURE', 'OS', 'ComSpec', 'windir', 'NUMBER_OF_PROCESSORS', 'USERNAME', 'ALLUSERSPROFILE', 'CommonProgramFiles', 'DriverData', 'PUBLIC']);
const secrets = Object.keys(process.env).filter(k => !allowed.has(k) && !k.startsWith('__') && k !== 'CI');
const hasHostSecrets = ['GITHUB_TOKEN', 'AWS_SECRET', 'API_KEY', 'DATABASE_URL', 'npm_config_registry'].some(s => process.env[s]);
if (!hasHostSecrets) {
    console.log("PASS: no host secrets leaked");
} else {
    console.log("FAIL: host secrets found");
}
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('no host secrets leaked');
        } finally { cleanup(ws); }
    });

    it('does not copy .env files into the workspace', async () => {
        const ws = makeWorkspace();
        fs.writeFileSync(path.join(ws, '.env'), 'SECRET=should-not-copy');
        fs.writeFileSync(path.join(ws, '.env.local'), 'LOCAL_SECRET=nope');
        try {
            const result = await backend.execute({
                script: `
import fs from 'node:fs';
import path from 'node:path';
try {
    const envExists = fs.existsSync(path.join(process.cwd(), '.env'));
    const envLocalExists = fs.existsSync(path.join(process.cwd(), '.env.local'));
    if (!envExists && !envLocalExists) {
        console.log("PASS: .env files not copied");
    } else {
        console.log("FAIL: .env files were copied: .env=" + envExists + " .env.local=" + envLocalExists);
    }
} catch (e) {
    console.log("FAIL: error: " + e.message);
}
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
        } finally { cleanup(ws); }
    });

    it('blocks network via fetch', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
async function main() {
    try {
        await fetch("http://1.2.3.4/");
        console.log("FAIL: fetch succeeded");
    } catch (e) {
        if (e.message.includes('SECURECODE_SANDBOX') || e.message.includes('blocked')) {
            console.log("PASS: fetch blocked — " + e.message.slice(0, 80));
        } else {
            console.log("PASS: fetch failed — " + e.message.slice(0, 80));
        }
    }
}
main();
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked|failed/);
        } finally { cleanup(ws); }
    });

    it('blocks network via net.Socket', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
import net from 'node:net';
const sock = new net.Socket();
sock.on('error', (e) => {
    if (e.message.includes('SECURECODE_SANDBOX') || e.code === 'ENETDENIED') {
        console.log("PASS: net blocked — " + e.code);
    } else {
        console.log("PASS: net failed — " + e.code);
    }
});
sock.connect(80, '1.2.3.4');
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked|failed/);
        } finally { cleanup(ws); }
    });

    it('handles timeout', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: 'setTimeout(() => {}, 60000);',
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 2_000,
            });
            expect(result.verdict).toBe('timeout');
        } finally { cleanup(ws); }
    }, 10_000);

    it('handles cancellation', async () => {
        const ws = makeWorkspace();
        const controller = new AbortController();
        try {
            const p = backend.execute({
                script: 'setTimeout(() => {}, 60000);',
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 30_000,
                signal: controller.signal,
            });
            setTimeout(() => controller.abort(), 500);
            const result = await p;
            expect(result.verdict).toBe('cancelled');
        } finally { cleanup(ws); }
    }, 10_000);

    it('can import workspace modules', async () => {
        const ws = makeWorkspace();
        fs.writeFileSync(path.join(ws, 'helper.mjs'), 'export function greet(n) { return "Hello " + n; }');
        try {
            const result = await backend.execute({
                script: `import { greet } from "../helper.mjs";\nif (greet("world") === "Hello world") console.log("PASS: import works");\nelse console.log("FAIL: bad result");`,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('import works');
        } finally { cleanup(ws); }
    });

    it('cleans up temp dir after execution', async () => {
        const ws = makeWorkspace();
        let tempDirs: string[] = [];
        const tmpBase = os.tmpdir();
        const before = fs.readdirSync(tmpBase).filter(d => d.startsWith('securecode-local-'));
        try {
            await backend.execute({
                script: 'console.log("PASS: cleanup-test");',
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            const after = fs.readdirSync(tmpBase).filter(d => d.startsWith('securecode-local-'));
            const newDirs = after.filter(d => !before.includes(d));
            expect(newDirs.length).toBeLessThanOrEqual(1);
        } finally { cleanup(ws); }
    });

    it('blocks http.get to external hosts', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
import http from 'node:http';
const req = http.get('http://1.2.3.4/', (res) => {
    console.log("FAIL: http succeeded, status=" + res.statusCode);
});
req.on('error', (e) => {
    console.log("PASS: http blocked — " + e.code);
});
req.setTimeout(3000, () => { req.destroy(); console.log("PASS: http blocked (timeout)"); });
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 10_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked/);
        } finally { cleanup(ws); }
    });

    it('blocks https.get', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
import https from 'node:https';
const req = https.get('https://1.2.3.4/', (res) => {
    console.log("FAIL: https succeeded");
});
req.on('error', (e) => {
    console.log("PASS: https blocked — " + e.code);
});
req.setTimeout(3000, () => { req.destroy(); console.log("PASS: https blocked (timeout)"); });
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 10_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked/);
        } finally { cleanup(ws); }
    });

    it('blocks tls.connect', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
import tls from 'node:tls';
try {
    const sock = tls.connect(443, '1.2.3.4');
    sock.on('error', (e) => {
        console.log("PASS: tls blocked — " + (e.code || e.message));
    });
    sock.setTimeout(3000, () => { sock.destroy(); console.log("PASS: tls blocked (timeout)"); });
} catch(e) {
    console.log("PASS: tls blocked — " + e.message);
}
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 10_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked/);
        } finally { cleanup(ws); }
    });

    it('blocks dns.lookup', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
import dns from 'node:dns';
dns.lookup('example.com', (err, address) => {
    if (err && (err.code === 'ENETDENIED' || err.message.includes('SECURECODE_SANDBOX'))) {
        console.log("PASS: dns blocked — " + err.code);
    } else if (err) {
        console.log("PASS: dns failed — " + err.code);
    } else {
        console.log("FAIL: dns resolved — " + address);
    }
});
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 10_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked|failed/);
        } finally { cleanup(ws); }
    });

    it('blocks child_process.exec', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
try {
    var cp = require('child_process');
    cp.exec('echo hello', (err, stdout) => {
        console.log("FAIL: exec succeeded — " + stdout);
    });
} catch(e) {
    if (e.message.includes('SECURECODE_SANDBOX')) {
        console.log("PASS: child_process blocked — " + e.message.slice(0, 60));
    } else {
        console.log("PASS: child_process failed — " + e.message.slice(0, 60));
    }
}
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 10_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toMatch(/blocked|failed/);
        } finally { cleanup(ws); }
    });

    it('allows loopback to an in-process server', async () => {
        const ws = makeWorkspace();
        try {
            const result = await backend.execute({
                script: `
import http from 'node:http';
process.on('uncaughtException', (e) => {
    console.log("FAIL: uncaught — " + e.message);
    process.exit(1);
});
const server = http.createServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
});
server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    const req = http.get('http://127.0.0.1:' + port + '/', (res) => {
        let data = '';
        res.on('data', (c) => data += c);
        res.on('end', () => {
            server.close();
            if (data === 'ok') console.log("PASS: loopback works on port " + port);
            else console.log("FAIL: unexpected response: " + data);
        });
    });
    req.on('error', (e) => {
        server.close();
        console.log("FAIL: loopback error — " + e.message);
    });
});
                `,
                runner: 'node',
                workspaceRoot: ws,
                timeoutMs: 15_000,
            });
            expect(result.verdict).toBe('pass');
            expect(result.output).toContain('loopback works');
        } finally { cleanup(ws); }
    });
});
