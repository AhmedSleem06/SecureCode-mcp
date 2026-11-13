import { describe, it, expect } from 'vitest';
import * as vm from 'node:vm';
import * as ts from 'typescript';
import { applyMutation } from '../src/attack/mutationOperators';

function compiles(code: string): boolean {
    try {
        new vm.Script(`(function (require, module, exports, res, req) {\n${code}\n})`);
        return true;
    } catch {
        return false;
    }
}

function runWith(code: string, sandbox: Record<string, unknown>): void {
    vm.runInNewContext(code, sandbox);
}

describe('applyMutation', () => {
    it('adds auth guard for broken_access_control', () => {
        const code = 'function handler(req, res) {\n  res.json({ data });\n}';
        const result = applyMutation(code, 'broken_access_control', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('403');
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('adds auth guard for missing_auth that does not reference undeclared identifiers', () => {
        const code = 'function handler(req, res) {\n  return res.json({ data: "secret" });\n}\nmodule.exports.out = [];';
        const result = applyMutation(code, 'missing_auth', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).not.toContain('isAuthenticated');
        const calls: number[] = [];
        const res = { status: (c: number) => { calls.push(c); return { json: (b: unknown) => b }; }, json: () => 'leaked' };
        const sandbox: any = { module: { exports: {} } };
        runWith(`${result.mutatedCode}\nmodule.exports.r = handler({}, res);`, { ...sandbox, res });
        expect(calls).toEqual([403]);
    });

    it('adds ownership check for missing_ownership', () => {
        const code = 'async function getProject(req, res) {\n  return db.query();\n}';
        const result = applyMutation(code, 'missing_ownership', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('not owner');
        expect(result.mutatedCode).toContain('403');
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('replaces SQL interpolation with placeholders', () => {
        const code = 'const q = `SELECT * FROM users WHERE id = ${userId}`;';
        const result = applyMutation(code, 'sql_injection', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('?');
        expect(result.mutatedCode).toBe('const q = `SELECT * FROM users WHERE id = ?`;');
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('sanitizes user-controlled path segments for path_traversal using names from the target line', () => {
        const code = 'const filePath = path.join(baseDir, req.query.file);\nfs.readFile(filePath);';
        const result = applyMutation(code, 'path_traversal', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).not.toContain('userInput');
        expect(result.mutatedCode).toContain('String(req.query.file)');
        const sandbox: any = {
            path: { join: (...p: string[]) => p.join('/') },
            baseDir: '/srv/uploads',
            req: { query: { file: '../../etc/passwd' } },
            fs: { readFile: (p: string) => { sandbox.read = p; } },
        };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.read).toBe('/srv/uploads/etc/passwd');
    });

    it('wraps the file-access argument for path_traversal when no path.join is present', () => {
        const code = 'fs.readFileSync(filePath, "utf8");';
        const result = applyMutation(code, 'path_traversal', 1);
        expect(result.mutated).toBe(true);
        const sandbox: any = { filePath: '../../etc/passwd', fs: { readFileSync: (p: string) => { sandbox.read = p; } } };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.read).toBe('passwd');
    });

    it('HTML-escapes the output argument for xss without undeclared identifiers', () => {
        const code = 'res.send(name);';
        const result = applyMutation(code, 'xss', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).not.toContain('userInput');
        const sandbox: any = { name: '<script>alert(1)</script>', res: { send: (b: string) => { sandbox.sent = b; } } };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.sent).not.toContain('<script>');
    });

    it('HTML-escapes template interpolations for xss', () => {
        const code = 'res.send(`<h1>Hello ${req.query.name}</h1>`);';
        const result = applyMutation(code, 'xss', 1);
        expect(result.mutated).toBe(true);
        const sandbox: any = { req: { query: { name: '<img src=x onerror=alert(1)>' } }, res: { send: (b: string) => { sandbox.sent = b; } } };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.sent).toContain('<h1>Hello ');
        expect(sandbox.sent).not.toContain('<img');
    });

    it('mutates exec(`...`, cb) with trailing arguments for command_injection', () => {
        const code = "exec(`ls ${req.query.dir}`, (err, out) => res.send(out));";
        const result = applyMutation(code, 'command_injection', 1);
        expect(result.mutated).toBe(true);
        expect(compiles(result.mutatedCode)).toBe(true);
        const sandbox: any = {
            req: { query: { dir: 'docs; cat /etc/passwd' } },
            res: { send: () => {} },
            exec: (cmd: string, cb: (e: null, o: string) => void) => { sandbox.cmd = cmd; cb(null, ''); },
        };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.cmd).not.toContain(';');
        expect(sandbox.cmd.startsWith('ls ')).toBe(true);
    });

    it('mutates string concatenation passed to execSync for command_injection', () => {
        const code = 'const out = execSync("ping -c 1 " + host, { encoding: "utf8" });';
        const result = applyMutation(code, 'command_injection', 1);
        expect(result.mutated).toBe(true);
        const sandbox: any = { host: '127.0.0.1 && id', execSync: (cmd: string) => { sandbox.cmd = cmd; return ''; } };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.cmd).toBe('ping -c 1 127.0.0.1id');
    });

    it('finds the command on a nearby line when the reported line is off by one', () => {
        const code = 'function run(req, res) {\n  exec(`git log ${req.body.ref}`, cb);\n}';
        const result = applyMutation(code, 'command_injection', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('String(req.body.ref)');
    });

    it('adds a private-host blocklist for ssrf using the URL expression from the line', () => {
        const code = 'const resp = await fetch(req.query.url);';
        const result = applyMutation(code, 'ssrf', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('SSRF blocked');
        expect(result.mutatedCode).toContain('String(req.query.url)');
        expect(result.mutatedCode).not.toContain('targetUrl');
    });

    it('adds input validation for missing_input_validation', () => {
        const code = 'function process(input) {\n  return input.trim();\n}';
        const result = applyMutation(code, 'missing_input_validation', 2);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('invalid input');
    });

    it('replaces hardcoded secret with env var', () => {
        const code = 'const apiKey = "sk-1234567890abcdef";';
        const result = applyMutation(code, 'secrets_in_source', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).toContain('process.env.SECRET_KEY');
        expect(result.mutatedCode).not.toContain('sk-1234567890abcdef');
    });

    it('treats hardcoded_secret as an alias of secrets_in_source', () => {
        const code = 'const JWT_SECRET = "supersecretvalue123";';
        const result = applyMutation(code, 'hardcoded_secret', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).not.toContain('supersecretvalue123');
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('detects secrets by variable name even when the value has no marker', () => {
        const code = 'const dbPassword = "hunter2";';
        const result = applyMutation(code, 'hardcoded_secret', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).not.toContain('hunter2');
    });

    it('neutralizes eval for code_injection', () => {
        const code = 'const result = eval(req.body.expr);';
        const result = applyMutation(code, 'code_injection', 1);
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode).not.toMatch(/\beval\s*\(/);
        const sandbox: any = { req: { body: { expr: 'globalThis.pwned = 1' } } };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.pwned).toBeUndefined();
    });

    it('neutralizes new Function for code_injection aliases', () => {
        const code = 'const fn = new Function("a", req.body.code); fn(1);';
        const result = applyMutation(code, 'eval_injection', 1);
        expect(result.mutated).toBe(true);
        const sandbox: any = { req: { body: { code: 'globalThis.pwned = 1' } } };
        runWith(result.mutatedCode, sandbox);
        expect(sandbox.pwned).toBeUndefined();
    });

    it('returns not mutated for unknown vulnerability type', () => {
        const code = 'function handler() {}';
        const result = applyMutation(code, 'unknown_type', 1);
        expect(result.mutated).toBe(false);
        expect(result.description).toContain('No mutation operator');
    });

    it('returns not mutated when no SQL interpolation is found', () => {
        const code = 'const q = "SELECT * FROM users";';
        const result = applyMutation(code, 'sql_injection', 1);
        expect(result.mutated).toBe(false);
    });

    it('inserts the guard at the first body line of the enclosing handler with its indentation', () => {
        const code = 'function handler(req, res) {\n  if (true) {\n    doSomething();\n  }\n}';
        const result = applyMutation(code, 'missing_auth', 3);
        expect(result.mutated).toBe(true);
        const mutatedLines = result.mutatedCode.split('\n');
        expect(mutatedLines[0]).toBe('function handler(req, res) {');
        expect(mutatedLines[1].startsWith('  if (typeof res')).toBe(true);
        expect(mutatedLines[2]).toBe('  if (true) {');
        expect(compiles(result.mutatedCode)).toBe(true);
    });
});

const FIVE_BUG_FILE = [
    "const express = require('express');",
    "const { exec } = require('child_process');",
    "const fs = require('fs');",
    "const path = require('path');",
    "const db = require('./db');",
    '',
    'const app = express();',
    "const STRIPE_SECRET_KEY = 'sk_" + "live_" + "FAKEtestFIXTUREnotArealKEY0000';",
    '',
    "app.get('/user', (req, res) => {",
    '    const query = "SELECT * FROM users WHERE id = \'" + req.query.id + "\'";',
    '    db.query(query, (err, rows) => {',
    "        if (err) return res.status(500).send('error');",
    '        res.json(rows);',
    '    });',
    '});',
    '',
    "app.get('/ping', (req, res) => {",
    '    exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {',
    '        res.send(stdout);',
    '    });',
    '});',
    '',
    "app.get('/file', (req, res) => {",
    "    const filePath = path.join(__dirname, 'uploads', req.query.name);",
    "    res.send(fs.readFileSync(filePath, 'utf8'));",
    '});',
    '',
    "app.get('/calc', (req, res) => {",
    '    const result = eval(req.query.expr);',
    '    res.send(String(result));',
    '});',
    '',
    "app.get('/charge', (req, res) => {",
    '    res.json({ key: STRIPE_SECRET_KEY.slice(0, 7) });',
    '});',
    '',
    'module.exports = app;',
    '',
    'if (require.main === module) {',
    '    app.listen(3000);',
    '}',
].join('\n');

function tsParses(code: string, fileName: string): boolean {
    const sf = ts.createSourceFile(fileName, code, ts.ScriptTarget.Latest, true);
    return ((sf as any).parseDiagnostics as unknown[]).length === 0;
}

function loadFiveBugApp(code: string, modules: Record<string, unknown> = {}): Record<string, (req: unknown, res: unknown) => unknown> {
    const handlers: Record<string, (req: unknown, res: unknown) => unknown> = {};
    const app = { get: (p: string, h: (req: unknown, res: unknown) => unknown) => { handlers[p] = h; }, listen: () => {} };
    const stubRequire = (m: string) => (m === 'express' ? () => app : (modules[m] ?? {}));
    const mod = { exports: {} };
    const factory = vm.runInNewContext(`(function (require, module, exports, __dirname) {\n${code}\n})`, { process: { env: {} }, String });
    factory(stubRequire, mod, mod.exports, '/srv/app');
    return handlers;
}

describe('applyMutation on the real 5-bug file', () => {
    it('replaces the secret with a string so the /charge handler still runs', () => {
        const result = applyMutation(FIVE_BUG_FILE, 'hardcoded_secret', 8, 'test-vulnerable.js');
        expect(result.mutated).toBe(true);
        expect(result.syntaxCheck).toBe('typescript');
        expect(result.mutatedCode).not.toContain('sk_live_');
        expect(result.mutatedCode).toContain("process.env.SECRET_KEY ?? ''");
        expect(compiles(result.mutatedCode)).toBe(true);
        const handlers = loadFiveBugApp(result.mutatedCode);
        let sent: any;
        expect(() => handlers['/charge']({}, { json: (b: unknown) => { sent = b; } })).not.toThrow();
        expect(sent).toEqual({ key: '' });
    });

    it('keeps the path traversal mutation behaviour', () => {
        const result = applyMutation(FIVE_BUG_FILE, 'path_traversal', 25, 'test-vulnerable.js');
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode.split('\n')[24]).toBe(
            "    const filePath = path.join(__dirname, 'uploads', String(req.query.name).replace(/\\.\\.[\\/\\\\]?/g, '').replace(/^[\\/\\\\]+/, ''));",
        );
        let read = '';
        const handlers = loadFiveBugApp(result.mutatedCode, {
            path: { join: (...p: string[]) => p.join('/') },
            fs: { readFileSync: (p: string) => { read = p; return 'x'; } },
        });
        handlers['/file']({ query: { name: '../../etc/passwd' } }, { send: () => {} });
        expect(read).toBe('/srv/app/uploads/etc/passwd');
    });

    it('puts the access-control guard inside the Express arrow handler', () => {
        const result = applyMutation(FIVE_BUG_FILE, 'missing_auth', 35, 'test-vulnerable.js');
        expect(result.mutated).toBe(true);
        const lines = result.mutatedCode.split('\n');
        expect(lines[33]).toBe("app.get('/charge', (req, res) => {");
        expect(lines[34].startsWith("    if (typeof res !== 'undefined'")).toBe(true);
        const handlers = loadFiveBugApp(result.mutatedCode);
        const codes: number[] = [];
        handlers['/charge']({}, { status: (c: number) => { codes.push(c); return { json: () => 'denied' }; }, json: () => 'leaked' });
        expect(codes).toEqual([403]);
    });

    it('guards the outer handler when the finding is inside a callback without res', () => {
        const result = applyMutation(FIVE_BUG_FILE, 'missing_auth', 13, 'test-vulnerable.js');
        expect(result.mutated).toBe(true);
        const lines = result.mutatedCode.split('\n');
        expect(lines[9]).toBe("app.get('/user', (req, res) => {");
        expect(lines[10].startsWith("    if (typeof res !== 'undefined'")).toBe(true);
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('refuses an access-control mutation on a top-level statement', () => {
        const result = applyMutation(FIVE_BUG_FILE, 'broken_access_control', 7, 'test-vulnerable.js');
        expect(result.mutated).toBe(false);
        expect(result.mutatedCode).toBe(FIVE_BUG_FILE);
        expect(result.description).toContain('not inside a function');
    });
});

describe('applyMutation access control by function shape', () => {
    const HTTP_TS = [
        "import { timingSafeEqual } from 'node:crypto';",
        '',
        'export function isLegacyTokenAuthorized(input: {',
        '  token: string | undefined;',
        '  expected: string | undefined;',
        '  allowQueryToken: boolean;',
        '}): boolean {',
        '  if (!input.expected) return true;',
        "  const url = `/x?token=${input.token ?? ''}`;",
        '  return input.token === input.expected && url.length > 0;',
        '}',
        '',
        'export const other = 1;',
    ].join('\n');

    it('inserts return false as the first body line of a multi-line TS signature returning boolean', () => {
        for (const line of [3, 5, 8, 10]) {
            const result = applyMutation(HTTP_TS, 'broken_access_control', line, 'apps/server/src/http.ts');
            expect(result.mutated).toBe(true);
            const lines = result.mutatedCode.split('\n');
            expect(lines[6]).toBe('}): boolean {');
            expect(lines[7]).toBe('  return false;');
            expect(lines[8]).toBe('  if (!input.expected) return true;');
            expect(tsParses(result.mutatedCode, 'http.ts')).toBe(true);
        }
    });

    it('uses return false when the body returns booleans and there is no response parameter', () => {
        const code = 'function canEdit(user, doc) {\n  if (!user) return false;\n  return true;\n}\nmodule.exports = { canEdit };';
        const result = applyMutation(code, 'missing_ownership', 3, 'perm.js');
        expect(result.mutated).toBe(true);
        const sandbox: any = { module: { exports: {} } };
        vm.runInNewContext(result.mutatedCode, sandbox);
        expect(sandbox.module.exports.canEdit({ id: 1 }, {})).toBe(false);
    });

    it('uses a reply parameter for the deny guard', () => {
        const code = "fastify.get('/doc/:id', async (request, reply) => {\n  return db.doc(request.params.id);\n});";
        const result = applyMutation(code, 'missing_auth', 2, 'routes.ts');
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode.split('\n')[1]).toContain("typeof reply.status === 'function'");
        expect(tsParses(result.mutatedCode, 'routes.ts')).toBe(true);
    });

    it('handles a single-line body by inserting right after the opening brace', () => {
        const code = 'module.exports = function (req, res) { res.json(secret); };';
        const result = applyMutation(code, 'missing_auth', 1, 'one.js');
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode.startsWith('module.exports = function (req, res) { if (typeof res')).toBe(true);
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('ignores braces inside strings, comments, regexes and templates', () => {
        const code = [
            "app.post('/x', (req, res) => {",
            "  const a = '{'; // }",
            '  const b = /\\}/.test(req.body.s);',
            '  const c = `${req.body.t} }`;',
            '  res.json({ a, b, c });',
            '});',
        ].join('\n');
        const result = applyMutation(code, 'missing_auth', 5, 'x.js');
        expect(result.mutated).toBe(true);
        expect(result.mutatedCode.split('\n')[1].startsWith("  if (typeof res !== 'undefined'")).toBe(true);
        expect(compiles(result.mutatedCode)).toBe(true);
    });

    it('does not mutate a function with no response parameter and no boolean result', () => {
        const code = 'function loadProject(id) {\n  return db.find(id);\n}';
        const result = applyMutation(code, 'missing_ownership', 2, 'p.js');
        expect(result.mutated).toBe(false);
        expect(result.description).toBe('No safe access-control mutation for this function shape');
    });
});

describe('applyMutation syntax check', () => {
    it('skips a mutation that produces code that does not parse', () => {
        const code = "const re = /'/; const s = x + 'y';\nmodule.exports = s;";
        const result = applyMutation(code, 'sql_injection', 1, 'q.js');
        expect(result.mutated).toBe(false);
        expect(result.mutatedCode).toBe(code);
        expect(result.description.startsWith('Mutation produced invalid code — skipped')).toBe(true);
        expect(result.syntaxCheck).toBe('typescript');
    });

    it('does not reject a mutation because the original already had parse problems', () => {
        const code = 'const apiKey = "sk-1234567890abcdef";\nconst broken = ;';
        const result = applyMutation(code, 'secrets_in_source', 1, 'k.ts');
        expect(result.mutated).toBe(true);
    });

    it('skips the parser for Python files', () => {
        const code = 'API_KEY = "sk-1234567890abcdef"';
        const result = applyMutation(code, 'secrets_in_source', 1, 'app.py');
        expect(result.mutated).toBe(true);
        expect(result.syntaxCheck).toBe('none');
    });
});
