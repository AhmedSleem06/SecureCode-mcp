import { describe, it, expect } from 'vitest';
import * as vm from 'node:vm';
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
        expect(result.mutatedCode).not.toContain('${userId}');
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

    it('preserves indentation of the target line', () => {
        const code = 'function handler() {\n  if (true) {\n    doSomething();\n  }\n}';
        const result = applyMutation(code, 'missing_auth', 3);
        expect(result.mutated).toBe(true);
        const mutatedLines = result.mutatedCode.split('\n');
        const guardLine = mutatedLines[2];
        expect(guardLine.startsWith('    ')).toBe(true);
    });
});
