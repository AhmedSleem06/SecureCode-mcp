import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as http from 'http';
import { spawnSync } from 'child_process';

import { testValidity as testValidityFn } from '../src/attack/testValidity';

const EXPRESS_ALIASES: Record<string, string> = { '4': 'express4', '5': 'express5' };

function makeTargetDir(alias: string): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fidelity-'));
    const nm = path.join(tmpDir, 'node_modules', 'express');
    fs.mkdirSync(nm, { recursive: true });
    const pkgJsonPath = require.resolve(alias + '/package.json');
    const absAlias = path.dirname(pkgJsonPath);
    fs.writeFileSync(path.join(nm, 'index.js'), `module.exports = require(${JSON.stringify(absAlias)});`, 'utf8');
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    fs.writeFileSync(path.join(nm, 'package.json'), JSON.stringify({ name: 'express', version: pkg.version }), 'utf8');
    return tmpDir;
}

function runHelper(targetDir: string, scriptBody: string, fixtureFiles?: Record<string, string>): { stdout: string; stderr: string; exitCode: number } {
    const harnessSource = path.resolve(__dirname, '../src/assurance/harness/expressRunner.cjs');
    fs.copyFileSync(harnessSource, path.join(targetDir, 'expressRunner.cjs'));
    if (fixtureFiles) {
        for (const [name, content] of Object.entries(fixtureFiles)) {
            const fp = path.join(targetDir, name);
            fs.mkdirSync(path.dirname(fp), { recursive: true });
            fs.writeFileSync(fp, content, 'utf8');
        }
    }
    const testFile = path.join(targetDir, 'test.cjs');
    fs.writeFileSync(testFile, scriptBody, 'utf8');
    const r = spawnSync(process.execPath, [testFile], {
        cwd: targetDir,
        timeout: 15_000,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { NODE_ENV: 'test', PATH: process.env.PATH || '', PATHEXT: process.env.PATHEXT || '', SystemRoot: process.env.SystemRoot || '' },
    });
    return { stdout: r.stdout?.toString('utf8') || '', stderr: r.stderr?.toString('utf8') || '', exitCode: r.status ?? -1 };
}

function parseJson(stdout: string): any {
    for (const line of stdout.trim().split('\n')) {
        const t = line.trim();
        if (t.startsWith('{') || t.startsWith('[')) { try { return JSON.parse(t); } catch {} }
    }
    throw new Error('No JSON in stdout: ' + stdout.slice(0, 500));
}

function parseLog(stdout: string): any {
    const m = stdout.match(/SECURECODE_HARNESS_LOG:(\{.*?\}):SECURECODE_HARNESS_END/);
    return m ? JSON.parse(m[1]) : null;
}

function listen(app: any): Promise<{ server: http.Server; port: number }> {
    return new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve({ server: s, port: (s.address() as any).port }));
    });
}

function httpReq(port: number, method: string, urlPath: string, body?: unknown, headers?: Record<string, string>): Promise<{ status: number; body: any }> {
    return new Promise((resolve, reject) => {
        let bodyBuf: Buffer | undefined;
        const h: Record<string, string> = { ...(headers || {}) };
        if (body !== undefined && body !== null && typeof body === 'object' && !Buffer.isBuffer(body)) {
            bodyBuf = Buffer.from(JSON.stringify(body));
            if (!h['content-type']) h['content-type'] = 'application/json';
            h['content-length'] = String(bodyBuf.length);
        }
        const req = http.request({ hostname: '127.0.0.1', port, method, path: urlPath, headers: h }, (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => {
                const raw = Buffer.concat(chunks).toString('utf8');
                let parsed: any = raw;
                try { parsed = JSON.parse(raw); } catch {}
                resolve({ status: res.statusCode!, body: parsed });
            });
        });
        req.on('error', reject);
        if (bodyBuf) req.write(bodyBuf);
        req.end();
    });
}

for (const [ver, alias] of Object.entries(EXPRESS_ALIASES)) {
    const ex = require(alias);

    describe(`fidelity — express ${ver} (real engine)`, () => {
        let targetDir: string;
        beforeAll(() => { targetDir = makeTargetDir(alias); });
        afterAll(() => { try { fs.rmSync(targetDir, { recursive: true, force: true }); } catch {} });

        it('wildcard use guard blocks anonymous requests', async () => {
            const wildcard = ver === '4' ? '/admin/*' : '/admin/*path';
            const appCode = `
                const express = require('express');
                const app = express();
                const router = express.Router();
                router.use('${wildcard}', (req, res, next) => {
                    if (!req.headers.authorization) return res.status(401).json({ error: 'unauthorized' });
                    next();
                });
                app.use(router);
                app.get('/admin/config', (req, res) => { res.json({ ok: true }); });
                module.exports = { app };
            `;
            const app = ex();
            const r = ex.Router();
            r.use(wildcard, (req: any, res: any, next: any) => {
                if (!req.headers.authorization) return res.status(401).json({ error: 'unauthorized' });
                next();
            });
            app.use(r);
            app.get('/admin/config', (req: any, res: any) => res.json({ ok: true }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/admin/config');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/admin/config');
                        console.log(JSON.stringify({ status: res.status, body: res.body }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.status).toBe(401);
                expect(parseLog(out.stdout).engine).toMatch(/^express@/);
            } finally { server.close(); }
        });

        it('mounted router with prefix stripping', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                const apiRouter = express.Router();
                apiRouter.get('/config', (req, res) => { res.json({ data: 'config' }); });
                app.use('/api', apiRouter);
                module.exports = { app };
            `;
            const app = ex();
            const apiRouter = ex.Router();
            apiRouter.get('/config', (req: any, res: any) => res.json({ data: 'config' }));
            app.use('/api', apiRouter);
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/api/config');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/api/config');
                        console.log(JSON.stringify({ status: res.status, body: res.body }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.body).toEqual(real.body);
            } finally { server.close(); }
        });

        it('express.json() real body parsing', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.use(express.json());
                app.post('/echo', (req, res) => { res.json({ received: req.body }); });
                module.exports = { app };
            `;
            const app = ex();
            app.use(ex.json());
            app.post('/echo', (req: any, res: any) => res.json({ received: req.body }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'POST', '/echo', { key: 'value' });
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('POST', '/echo', { body: { key: 'value' } });
                        console.log(JSON.stringify({ status: res.status, body: res.body }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.body).toEqual(real.body);
            } finally { server.close(); }
        });

        it('error middleware catches thrown errors', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.get('/boom', (req, res) => { throw new Error('kaboom'); });
                app.use((err, req, res, next) => { res.status(500).json({ error: err.message }); });
                module.exports = { app };
            `;
            const app = ex();
            app.get('/boom', () => { throw new Error('kaboom'); });
            app.use((err: any, _req: any, res: any, _next: any) => res.status(500).json({ error: err.message }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/boom');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/boom');
                        console.log(JSON.stringify({ status: res.status, body: res.body }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(500);
                expect(h.body).toEqual(real.body);
            } finally { server.close(); }
        });

        it('router.route() chaining', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.route('/item/:id')
                    .get((req, res) => { res.json({ action: 'get', id: req.params.id }); })
                    .delete((req, res) => { res.json({ action: 'delete', id: req.params.id }); });
                module.exports = { app };
            `;
            const app = ex();
            app.route('/item/:id')
                .get((req: any, res: any) => res.json({ action: 'get', id: req.params.id }))
                .delete((req: any, res: any) => res.json({ action: 'delete', id: req.params.id }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'DELETE', '/item/42');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('DELETE', '/item/42');
                        console.log(JSON.stringify({ status: res.status, body: res.body }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.body).toEqual(real.body);
            } finally { server.close(); }
        });

        it('matched: true when route reached, true when auth mw blocks, false when no route', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.use((req, res, next) => {
                    if (req.path.startsWith('/secret') && !req.headers.authorization)
                        return res.status(401).json({ error: 'no auth' });
                    next();
                });
                app.get('/secret/data', (req, res) => { res.json({ ok: true }); });
                app.get('/public', (req, res) => { res.json({ public: true }); });
                module.exports = { app };
            `;
            const out = runHelper(targetDir, `
                const sc = require('./expressRunner.cjs');
                sc.load('./app.cjs');
                (async () => {
                    const r1 = await sc.invoke('GET', '/public');
                    const r2 = await sc.invoke('GET', '/secret/data');
                    const r3 = await sc.invoke('GET', '/nope');
                    console.log(JSON.stringify({
                        public: { status: r1.status, matched: r1.matched },
                        secret: { status: r2.status, matched: r2.matched },
                        nope: { status: r3.status, matched: r3.matched }
                    }));
                })();
            `, { 'app.cjs': appCode });
            expect(out.exitCode).toBe(0);
            const h = parseJson(out.stdout);
            expect(h.public.matched).toBe(true);
            expect(h.public.status).toBe(200);
            expect(h.secret.matched).toBe(true);
            expect(h.secret.status).toBe(401);
            expect(h.nope.matched).toBe(false);
            expect(h.nope.status).toBe(404);
        });

        it('unknown route returns 404 with sent=false', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.get('/exists', (req, res) => { res.json({ ok: true }); });
                module.exports = { app };
            `;
            const app = ex();
            app.get('/exists', (req: any, res: any) => res.json({ ok: true }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/nope');
                expect(real.status).toBe(404);
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/nope');
                        console.log(JSON.stringify({ status: res.status, sent: res.sent, matched: res.matched }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(404);
                expect(h.sent).toBe(false);
                expect(h.matched).toBe(false);
            } finally { server.close(); }
        });

        it('nested routers', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                const outer = express.Router();
                const inner = express.Router();
                inner.get('/deep', (req, res) => { res.json({ level: 'deep' }); });
                outer.use('/inner', inner);
                app.use('/outer', outer);
                module.exports = { app };
            `;
            const app = ex();
            const outer = ex.Router();
            const inner = ex.Router();
            inner.get('/deep', (req: any, res: any) => res.json({ level: 'deep' }));
            outer.use('/inner', inner);
            app.use('/outer', outer);
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/outer/inner/deep');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/outer/inner/deep');
                        console.log(JSON.stringify({ status: res.status, body: res.body, matched: res.matched }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.body).toEqual(real.body);
                expect(h.matched).toBe(true);
            } finally { server.close(); }
        });

        it('array middleware in app.use', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                function mw1(req, res, next) { req.tags = ['mw1']; next(); }
                function mw2(req, res, next) { req.tags.push('mw2'); next(); }
                app.use('/x', [mw1, mw2], (req, res, next) => { req.tags.push('mw3'); next(); });
                app.get('/x/data', (req, res) => { res.json({ tags: req.tags }); });
                module.exports = { app };
            `;
            const app = ex();
            function mw1(req: any, res: any, next: any) { req.tags = ['mw1']; next(); }
            function mw2(req: any, res: any, next: any) { req.tags.push('mw2'); next(); }
            app.use('/x', [mw1, mw2], (req: any, res: any, next: any) => { req.tags.push('mw3'); next(); });
            app.get('/x/data', (req: any, res: any) => res.json({ tags: req.tags }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/x/data');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/x/data');
                        console.log(JSON.stringify({ status: res.status, body: res.body, matched: res.matched }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.body).toEqual(real.body);
                expect(h.matched).toBe(true);
            } finally { server.close(); }
        });

        it('app.param guard', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.param('id', (req, res, next, id) => {
                    if (!/^\\d+$/.test(id)) return res.status(400).json({ error: 'bad id' });
                    req.itemId = Number(id);
                    next();
                });
                app.get('/item/:id', (req, res) => { res.json({ id: req.itemId }); });
                module.exports = { app };
            `;
            const app = ex();
            app.param('id', (req: any, res: any, next: any, id: string) => {
                if (!/^\d+$/.test(id)) return res.status(400).json({ error: 'bad id' });
                req.itemId = Number(id);
                next();
            });
            app.get('/item/:id', (req: any, res: any) => res.json({ id: req.itemId }));
            const { server, port } = await listen(app);
            try {
                const realGood = await httpReq(port, 'GET', '/item/42');
                const realBad = await httpReq(port, 'GET', '/item/abc');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const r1 = await sc.invoke('GET', '/item/42');
                        const r2 = await sc.invoke('GET', '/item/abc');
                        console.log(JSON.stringify({
                            good: { status: r1.status, body: r1.body },
                            bad: { status: r2.status, body: r2.body }
                        }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.good.status).toBe(realGood.status);
                expect(h.good.body).toEqual(realGood.body);
                expect(h.bad.status).toBe(realBad.status);
                expect(h.bad.body).toEqual(realBad.body);
            } finally { server.close(); }
        });

        it('next("route") in route-level middleware', async () => {
            const appCode = `
                const express = require('express');
                const app = express();
                app.get('/test', (req, res, next) => {
                    if (!req.query.admin) return next('route');
                    next();
                }, (req, res) => {
                    res.json({ handler: 'admin' });
                });
                app.get('/test', (req, res) => {
                    res.json({ handler: 'default' });
                });
                module.exports = { app };
            `;
            const app = ex();
            app.get('/test', (req: any, res: any, next: any) => {
                if (!req.query.admin) return next('route');
                next();
            }, (req: any, res: any) => res.json({ handler: 'admin' }));
            app.get('/test', (req: any, res: any) => res.json({ handler: 'default' }));
            const { server, port } = await listen(app);
            try {
                const realDefault = await httpReq(port, 'GET', '/test');
                const realAdmin = await httpReq(port, 'GET', '/test?admin=1');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const r1 = await sc.invoke('GET', '/test');
                        const r2 = await sc.invoke('GET', '/test', { query: { admin: '1' } });
                        console.log(JSON.stringify({
                            def: { status: r1.status, body: r1.body },
                            admin: { status: r2.status, body: r2.body }
                        }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.def.status).toBe(realDefault.status);
                expect(h.def.body).toEqual(realDefault.body);
                expect(h.admin.status).toBe(realAdmin.status);
                expect(h.admin.body).toEqual(realAdmin.body);
            } finally { server.close(); }
        });

        it('async rejection caught by error middleware (v4+v5)', async () => {
            if (ver === '4') return;
            const appCode = `
                const express = require('express');
                const app = express();
                app.get('/async-fail', async (req, res) => {
                    throw new Error('async boom');
                });
                app.use((err, req, res, next) => {
                    res.status(500).json({ error: err.message });
                });
                module.exports = { app };
            `;
            const app = ex();
            app.get('/async-fail', async () => { throw new Error('async boom'); });
            app.use((err: any, _req: any, res: any, _next: any) => res.status(500).json({ error: err.message }));
            const { server, port } = await listen(app);
            try {
                const real = await httpReq(port, 'GET', '/async-fail');
                const out = runHelper(targetDir, `
                    const sc = require('./expressRunner.cjs');
                    sc.load('./app.cjs');
                    (async () => {
                        const res = await sc.invoke('GET', '/async-fail');
                        console.log(JSON.stringify({ status: res.status, body: res.body }));
                    })();
                `, { 'app.cjs': appCode });
                expect(out.exitCode).toBe(0);
                const h = parseJson(out.stdout);
                expect(h.status).toBe(real.status);
                expect(h.body).toEqual(real.body);
            } finally { server.close(); }
        });
    });
}

describe('fidelity — emulated engine (no express)', () => {
    let targetDir: string;
    beforeAll(() => { targetDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fidelity-emu-')); });
    afterAll(() => { try { fs.rmSync(targetDir, { recursive: true, force: true }); } catch {} });

    it('wildcard use path is flagged as unsupported', () => {
        const out = runHelper(targetDir, `
            const sc = require('./expressRunner.cjs');
            sc.load('./app.cjs');
            (async () => { await sc.invoke('GET', '/admin/config'); })();
        `, {
            'app.cjs': `
                const express = require('express');
                const app = express();
                const router = express.Router();
                router.use('/admin/*path', (req, res, next) => { next(); });
                app.use(router);
                app.get('/admin/config', (req, res) => { res.json({ ok: true }); });
                app.listen(3000);
            `
        });
        expect(out.exitCode).toBe(0);
        const log = parseLog(out.stdout);
        expect(log.engine).toBe('emulated');
        expect(log.unsupported.some((s: string) => s.includes('wildcard'))).toBe(true);
    });

    it('mounted router is flagged as unsupported', () => {
        const out = runHelper(targetDir, `
            const sc = require('./expressRunner.cjs');
            sc.load('./app.cjs');
            (async () => { await sc.invoke('GET', '/api/config'); })();
        `, {
            'app.cjs': `
                const express = require('express');
                const app = express();
                const router = express.Router();
                router.get('/config', (req, res) => { res.json({ ok: true }); });
                app.use('/api', router);
                app.listen(3000);
            `
        });
        expect(out.exitCode).toBe(0);
        const log = parseLog(out.stdout);
        expect(log.engine).toBe('emulated');
        expect(log.unsupported.some((s: string) => s.includes('mounted router'))).toBe(true);
    });

    it('app.param is flagged as unsupported', () => {
        const out = runHelper(targetDir, `
            const sc = require('./expressRunner.cjs');
            sc.load('./app.cjs');
            (async () => { await sc.invoke('GET', '/users/42'); })();
        `, {
            'app.cjs': `
                const express = require('express');
                const app = express();
                app.param('id', (req, res, next, id) => { req.userId = id; next(); });
                app.get('/users/:id', (req, res) => { res.json({ id: req.userId }); });
                app.listen(3000);
            `
        });
        expect(out.exitCode).toBe(0);
        const log = parseLog(out.stdout);
        expect(log.unsupported.some((s: string) => s.includes('app.param'))).toBe(true);
    });

    it('simple routes with no unsupported → engine emulated, unsupported empty', () => {
        const out = runHelper(targetDir, `
            const sc = require('./expressRunner.cjs');
            sc.load('./app.cjs');
            (async () => {
                const res = await sc.invoke('GET', '/hello');
                console.log(JSON.stringify({ status: res.status, body: res.body }));
            })();
        `, {
            'app.cjs': `
                const express = require('express');
                const app = express();
                app.get('/hello', (req, res) => { res.json({ ok: true }); });
                app.listen(3000);
            `
        });
        expect(out.exitCode).toBe(0);
        const log = parseLog(out.stdout);
        expect(log.engine).toBe('emulated');
        expect(log.unsupported).toEqual([]);
    });

    it('testValidity invalid for emulated + unsupported', () => {
        const output = `\nSECURECODE_HARNESS_LOG:${JSON.stringify({ calls: [], engine: 'emulated', unsupported: ['wildcard path /admin/*path'] })}:SECURECODE_HARNESS_END\n`;
        const result = testValidityFn(output, { kind: 'proof' });
        expect(result.valid).toBe(false);
        expect(result.reason).toContain('cannot model');
    });
});
