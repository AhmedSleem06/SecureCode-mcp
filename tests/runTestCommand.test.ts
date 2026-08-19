import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { runTestCommand } from '../src/utils/localTestRunner';
import { __UnsafeHostSandboxForTests, _setSandboxForTests } from '../src/utils/verificationSandbox';

process.env.SECURECODE_TEST_MODE = '1';

describe('runTestCommand', () => {
    let workspaceRoot: string;
    let unsafeBackend: __UnsafeHostSandboxForTests;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-cmd-runner-'));
        fs.mkdirSync(path.join(workspaceRoot, '.securecode'), { recursive: true });
        unsafeBackend = new __UnsafeHostSandboxForTests();
        _setSandboxForTests(unsafeBackend);
    });

    afterEach(() => {
        _setSandboxForTests(null);
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    it('returns pass when command exits 0', async () => {
        const result = await runTestCommand(
            process.platform === 'win32' ? 'cmd' : 'echo',
            process.platform === 'win32' ? ['/c', 'echo', 'hello'] : ['hello'],
            workspaceRoot,
        );
        expect(result.verdict).toBe('pass');
        expect(result.exitCode).toBe(0);
        expect(result.output).toContain('hello');
    });

    it('returns fail when command exits nonzero', async () => {
        const result = await runTestCommand(
            process.platform === 'win32' ? 'cmd' : 'false',
            process.platform === 'win32' ? ['/c', 'exit', '1'] : [],
            workspaceRoot,
        );
        expect(result.verdict).toBe('fail');
        expect(result.exitCode).not.toBe(0);
    });

    it('returns sandbox-unavailable when no backend is configured', async () => {
        _setSandboxForTests(null);
        const result = await runTestCommand('echo', ['test'], workspaceRoot);
        expect(result.verdict).toBe('sandbox-unavailable');
        expect(result.output).toContain('docs.docker.com');
    });

    it('returns timeout when command exceeds timeoutMs', async () => {
        // Use a command that definitely sleeps longer than the timeout.
        // On Windows: ping -n 10 127.0.0.1 > nul (sleeps ~9s)
        // On Unix: sleep 10
        const bin = process.platform === 'win32' ? 'ping' : 'sleep';
        const args = process.platform === 'win32' ? ['-n', '10', '127.0.0.1', '-w', '1000'] : ['10'];
        const result = await runTestCommand(bin, args, workspaceRoot, { timeoutMs: 1500 });
        expect(result.verdict).toBe('timeout');
    }, 15000);

    it('passes through the backend name', async () => {
        const result = await runTestCommand(
            process.platform === 'win32' ? 'cmd' : 'echo',
            process.platform === 'win32' ? ['/c', 'echo', 'ok'] : ['ok'],
            workspaceRoot,
        );
        expect(result.backend).toBeDefined();
        expect(result.backend).toBe('unsafe-host-tests-only');
    });
});
