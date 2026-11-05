import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/utils/localTestRunner', () => ({
    runLocalTest: vi.fn(),
}));

import { runMutationTest, redirectImportSpecifier } from '../src/attack/mutationTest';
import { runLocalTest } from '../src/utils/localTestRunner';

const VULN = 'function handler(req, res) {\n  res.json({ data });\n}\nmodule.exports = { handler };';
const TEST_SCRIPT = [
    'const { handler } = require("../src/app.js");',
    'handler({}, { json() {} });',
    'console.log("PASS: leaked");',
].join('\n');

describe('runMutationTest', () => {
    let ws: string;

    beforeEach(() => {
        vi.clearAllMocks();
        ws = fs.mkdtempSync(path.join(os.tmpdir(), 'scmut-'));
        fs.mkdirSync(path.join(ws, 'src'));
        fs.writeFileSync(path.join(ws, 'src', 'app.js'), VULN, 'utf8');
    });

    afterEach(() => {
        fs.rmSync(ws, { recursive: true, force: true });
    });

    const baseOpts = () => ({
        vulnerableCode: VULN,
        testScript: TEST_SCRIPT,
        runner: 'node',
        workspaceRoot: ws,
        filePath: 'src/app.js',
        vulnerabilityType: 'missing_auth',
        line: 2,
        relativeImportPath: '../src/app.js',
    });

    it('returns not-run with skipCause no-operator when no mutation operator is available', async () => {
        const result = await runMutationTest({ ...baseOpts(), vulnerabilityType: 'unknown_type' });

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('not-run');
        expect(result.skipCause).toBe('no-operator');
        expect(result.reason).toContain('No mutation operator');
        expect(runLocalTest).not.toHaveBeenCalled();
    });

    it('runs the TEST SCRIPT (not the mutated source) with the import redirected to a mutated sibling file', async () => {
        let seenScript = '';
        let mutatedFileContent = '';
        let mutatedFilePath = '';
        (runLocalTest as any).mockImplementation(async (script: string) => {
            seenScript = script;
            const m = script.match(/require\("\.\.\/src\/(app\.__scmut_[a-z0-9]+\.js)"\)/);
            if (m) {
                mutatedFilePath = path.join(ws, 'src', m[1]);
                mutatedFileContent = fs.readFileSync(mutatedFilePath, 'utf8');
            }
            return { verdict: 'fail', output: 'FAIL: blocked', exitCode: 0 };
        });

        const result = await runMutationTest(baseOpts());

        expect(runLocalTest).toHaveBeenCalledTimes(1);
        const [script, runner, root] = (runLocalTest as any).mock.calls[0];
        expect(script).toBe(seenScript);
        expect(script).not.toBe(VULN);
        expect(script).not.toContain('res.json({ data })');
        expect(script).toContain('handler({}, { json() {} });');
        expect(script).not.toContain('"../src/app.js"');
        expect(script).toMatch(/require\("\.\.\/src\/app\.__scmut_[a-z0-9]+\.js"\)/);
        expect(runner).toBe('node');
        expect(root).toBe(ws);

        expect(mutatedFileContent).toContain('403');
        expect(mutatedFileContent).toContain('res.json({ data });');
        expect(fs.existsSync(mutatedFilePath)).toBe(false);
        expect(fs.readFileSync(path.join(ws, 'src', 'app.js'), 'utf8')).toBe(VULN);

        expect(result.discriminating).toBe(true);
        expect(result.mutatedVerdict).toBe('fail');
        expect(result.reason).toContain('discriminates');
    });

    it('redirects extensionless specifiers and passes setupScript/timeout/signal through', async () => {
        (runLocalTest as any).mockResolvedValue({ verdict: 'fail', output: 'FAIL', exitCode: 0 });
        const signal = new AbortController().signal;

        await runMutationTest({
            ...baseOpts(),
            testScript: 'import { handler } from "../src/app";\nconsole.log("PASS: x");',
            relativeImportPath: '../src/app',
            setupScript: 'console.log("setup")',
            timeoutMs: 1234,
            signal,
        });

        const [script, , , options] = (runLocalTest as any).mock.calls[0];
        expect(script).toMatch(/from "\.\.\/src\/app\.__scmut_[a-z0-9]+\.js"/);
        expect(options).toEqual({ setupScript: 'console.log("setup")', timeoutMs: 1234, signal });
    });

    it('returns not-run with skipCause import-not-found when the test does not import the target', async () => {
        const result = await runMutationTest({
            ...baseOpts(),
            testScript: 'const { handler } = require("../lib/other.js");\nconsole.log("PASS: x");',
        });

        expect(result.mutatedVerdict).toBe('not-run');
        expect(result.skipCause).toBe('import-not-found');
        expect(result.discriminating).toBe(false);
        expect(runLocalTest).not.toHaveBeenCalled();
    });

    it('returns not-run with skipCause import-not-found when no relativeImportPath is given', async () => {
        const { relativeImportPath: _omit, ...opts } = baseOpts();
        const result = await runMutationTest(opts);

        expect(result.mutatedVerdict).toBe('not-run');
        expect(result.skipCause).toBe('import-not-found');
        expect(runLocalTest).not.toHaveBeenCalled();
    });

    it('treats a blocked mutated run as not-run (skipCause blocked), not as non-discriminating', async () => {
        (runLocalTest as any).mockResolvedValue({
            verdict: 'blocked',
            output: 'Test script blocked: eval() executes arbitrary strings as code',
            exitCode: -1,
        });

        const result = await runMutationTest(baseOpts());

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('not-run');
        expect(result.skipCause).toBe('blocked');
        expect(result.reason).toContain('blocked');
        expect(result.reason).not.toContain('does not discriminate');
    });

    it('returns non-discriminating when mutation makes the test pass', async () => {
        (runLocalTest as any).mockResolvedValue({ verdict: 'pass', output: 'all tests passed', exitCode: 0 });

        const result = await runMutationTest(baseOpts());

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('pass');
        expect(result.reason).toContain('does not discriminate');
    });

    it('returns INCONCLUSIVE (not discriminating) when mutation errors', async () => {
        (runLocalTest as any).mockResolvedValue({ verdict: 'error', output: 'SyntaxError: unexpected token', exitCode: 1 });

        const result = await runMutationTest(baseOpts());

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('error');
        expect(result.reason).toContain('INCONCLUSIVE');
    });

    it('returns INCONCLUSIVE (not discriminating) when mutation times out', async () => {
        (runLocalTest as any).mockResolvedValue({ verdict: 'timeout', output: 'timed out after 30s', exitCode: -1 });

        const result = await runMutationTest(baseOpts());

        expect(result.discriminating).toBe(false);
        expect(result.mutatedVerdict).toBe('timeout');
        expect(result.reason).toContain('INCONCLUSIVE');
    });

    it('cleans up the mutated file even when the runner throws', async () => {
        (runLocalTest as any).mockRejectedValue(new Error('boom'));

        const result = await runMutationTest(baseOpts());

        expect(result.mutatedVerdict).toBe('error');
        expect(fs.readdirSync(path.join(ws, 'src'))).toEqual(['app.js']);
    });
});

describe('redirectImportSpecifier', () => {
    it('rewrites single, double and backtick quoted specifiers with or without extension', () => {
        const script = `import a from '../src/app';\nconst b = require("../src/app.js");\nconst c = await import(\`../src/app.ts\`);`;
        const out = redirectImportSpecifier(script, '../src/app.js', '../src/app.__scmut_x.js')!;
        expect(out).toContain(`'../src/app.__scmut_x.js'`);
        expect(out).toContain(`"../src/app.__scmut_x.js"`);
        expect(out).toContain('`../src/app.__scmut_x.js`');
    });

    it('does not rewrite specifiers that merely share a prefix', () => {
        const script = `import a from "../src/app-utils.js";`;
        expect(redirectImportSpecifier(script, '../src/app.js', '../src/app.__scmut_x.js')).toBeNull();
    });

    it('handles python paths with and without a leading ./', () => {
        const script = `spec = importlib.util.spec_from_file_location("mod", os.path.join(os.getcwd(), "src/handler.py"))`;
        const out = redirectImportSpecifier(script, './src/handler.py', './src/handler.__scmut_x.py')!;
        expect(out).toContain('"./src/handler.__scmut_x.py"');
    });
});
