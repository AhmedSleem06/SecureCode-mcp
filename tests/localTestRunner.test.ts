import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { runLocalTest } from '../src/utils/localTestRunner';

describe('runLocalTest', () => {
    let workspaceRoot: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-runner-'));
        fs.mkdirSync(path.join(workspaceRoot, '.securecode'), { recursive: true });
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    it('returns pass when script prints PASS:', async () => {
        const script = `console.log("PASS: command executed successfully");`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('PASS:');
    });

    it('returns fail when script prints FAIL:', async () => {
        const script = `console.log("FAIL: guard blocked the exploit");`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('fail');
        expect(result.output).toContain('FAIL:');
    });

    it('returns error when script crashes with no marker', async () => {
        const script = `throw new Error("test crash");`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('error');
        expect(result.exitCode).not.toBe(0);
    });

    it('returns error when script exits 0 with no marker', async () => {
        const script = `console.log("nothing relevant");`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('error');
        expect(result.output).toContain('did not print PASS: or FAIL:');
    });

    it('returns timeout when script hangs', async () => {
        const script = `setTimeout(() => {}, 60000);`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('timeout');
    }, 40000);

    it('cleans up the test file after running', async () => {
        const script = `console.log("PASS: done");`;
        await runLocalTest(script, 'node', workspaceRoot);
        const securecodeDir = path.join(workspaceRoot, '.securecode');
        const files = fs.readdirSync(securecodeDir).filter(f => f.startsWith('verify-test-'));
        expect(files.length).toBe(0);
    });
});
