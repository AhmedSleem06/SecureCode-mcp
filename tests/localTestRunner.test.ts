import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { runLocalTest } from '../src/utils/localTestRunner';
import { __UnsafeHostSandboxForTests, _setSandboxForTests } from '../src/utils/verificationSandbox';

// These tests exercise the runner's PASS/FAIL parsing, cleanup, and blocked
// paths. They use __UnsafeHostSandboxForTests to run scripts directly on the
// host — this is acceptable because the scripts are benign and we're
// testing the runner logic, not the sandbox boundary. Production code never
// uses this backend.
process.env.SECURECODE_TEST_MODE = '1';

describe('runLocalTest', () => {
    let workspaceRoot: string;
    let unsafeBackend: __UnsafeHostSandboxForTests;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-runner-'));
        fs.mkdirSync(path.join(workspaceRoot, '.securecode'), { recursive: true });
        unsafeBackend = new __UnsafeHostSandboxForTests();
        _setSandboxForTests(unsafeBackend);
    });

    afterEach(() => {
        _setSandboxForTests(null);
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
        const result = await runLocalTest(script, 'node', workspaceRoot, { timeoutMs: 2000 });
        expect(result.verdict).toBe('timeout');
    }, 20000);

    it('returns blocked when the static safety check rejects the script', async () => {
        // eval() is on the deny list.
        const script = `eval("console.log('hi')");`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('blocked');
        expect(result.output).toContain('blocked');
    });

    it('returns sandbox-unavailable when no backend is configured', async () => {
        _setSandboxForTests(null);
        const script = `console.log("PASS: done");`;
        const result = await runLocalTest(script, 'node', workspaceRoot);
        expect(result.verdict).toBe('sandbox-unavailable');
        // The message must point the user at a concrete install path.
        expect(result.output).toContain('docs.docker.com');
        expect(result.output).toContain('deno.com');
    });

    it('returns cancelled (not timeout) when the AbortSignal fires mid-test', async () => {
        // A script that hangs long enough for us to abort it before the timeout.
        const script = `setTimeout(() => {}, 60000);`;
        const controller = new AbortController();
        const resultP = runLocalTest(script, 'node', workspaceRoot, {
            timeoutMs: 30000,
            signal: controller.signal,
        });
        // Abort shortly after the test starts.
        setTimeout(() => controller.abort(), 300);
        const result = await resultP;
        expect(result.verdict).toBe('cancelled');
        expect(result.output).toContain('cancelled');
        // Must NOT be reported as a timeout — that would trigger a retry.
        expect(result.verdict).not.toBe('timeout');
    }, 20000);
});
