import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { validateTestCommand, formatValidatedCommand } from '../src/utils/testCommandPolicy';

let workspaceRoot: string;

beforeEach(() => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-cmd-policy-'));
    fs.mkdirSync(path.join(workspaceRoot, 'tests'), { recursive: true });
    fs.writeFileSync(path.join(workspaceRoot, 'package.json'), '{}');
});

afterEach(() => {
    fs.rmSync(workspaceRoot, { recursive: true, force: true });
});

describe('validateTestCommand', () => {
    describe('npm', () => {
        it('accepts npm test with no files', () => {
            const result = validateTestCommand({ packageManager: 'npm' }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.executable).toBe('npm');
            expect(result.command!.args).toEqual(['test']);
        });

        it('accepts npm test with a specific file', () => {
            fs.writeFileSync(path.join(workspaceRoot, 'tests/auth.test.ts'), '');
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: ['tests/auth.test.ts'],
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.args).toEqual(['test', '--', 'tests/auth.test.ts']);
        });

        it('accepts npm test with multiple files and pattern', () => {
            fs.writeFileSync(path.join(workspaceRoot, 'tests/auth.test.ts'), '');
            fs.writeFileSync(path.join(workspaceRoot, 'tests/user.test.ts'), '');
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: ['tests/auth.test.ts', 'tests/user.test.ts'],
                testPattern: 'login',
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.args).toEqual(['test', '--', 'login', 'tests/auth.test.ts', 'tests/user.test.ts']);
        });
    });

    describe('pytest', () => {
        it('accepts pytest with test files', () => {
            fs.writeFileSync(path.join(workspaceRoot, 'tests/test_auth.py'), '');
            const result = validateTestCommand({
                packageManager: 'pytest',
                testFiles: ['tests/test_auth.py'],
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.executable).toBe('pytest');
            expect(result.command!.args).toEqual(['tests/test_auth.py']);
        });

        it('accepts pytest with pattern via -k', () => {
            const result = validateTestCommand({
                packageManager: 'pytest',
                testPattern: 'test_login',
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.args).toEqual(['-k', 'test_login']);
        });
    });

    describe('yarn', () => {
        it('accepts yarn test with files', () => {
            fs.writeFileSync(path.join(workspaceRoot, 'tests/auth.test.ts'), '');
            const result = validateTestCommand({
                packageManager: 'yarn',
                testFiles: ['tests/auth.test.ts'],
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.args).toEqual(['test', 'tests/auth.test.ts']);
        });
    });

    describe('bun', () => {
        it('accepts bun test with pattern', () => {
            const result = validateTestCommand({
                packageManager: 'bun',
                testPattern: 'auth',
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.args).toEqual(['test', 'auth']);
        });
    });

    describe('pnpm', () => {
        it('accepts pnpm test with files using --', () => {
            fs.writeFileSync(path.join(workspaceRoot, 'tests/auth.test.ts'), '');
            const result = validateTestCommand({
                packageManager: 'pnpm',
                testFiles: ['tests/auth.test.ts'],
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.args).toEqual(['test', '--', 'tests/auth.test.ts']);
        });
    });

    describe('security rejections', () => {
        it('rejects shell operators in testPattern', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                testPattern: 'auth && rm -rf /',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('shell operators');
        });

        it('rejects shell pipe in testFiles', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: ['tests/auth.test.ts | cat'],
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('shell operators');
        });

        it('rejects path traversal in testFiles', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: ['../../../etc/passwd'],
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('outside workspace');
        });

        it('rejects absolute paths in testFiles', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: ['/etc/passwd'],
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('outside workspace');
        });

        it('rejects unsupported package manager', () => {
            const result = validateTestCommand({
                packageManager: 'cargo',
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('Unsupported package manager');
        });

        it('rejects too many test files', () => {
            const files = Array.from({ length: 51 }, (_, i) => `tests/test_${i}.ts`);
            for (const f of files.slice(0, 51)) {
                fs.writeFileSync(path.join(workspaceRoot, f), '');
            }
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: files,
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('Too many test files');
        });

        it('rejects oversized testPattern', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                testPattern: 'a'.repeat(201),
            }, workspaceRoot);
            expect(result.ok).toBe(false);
            expect(result.error).toContain('too long');
        });
    });

    describe('timeout', () => {
        it('uses default timeout when not specified', () => {
            const result = validateTestCommand({ packageManager: 'npm' }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.timeoutMs).toBe(60_000);
        });

        it('caps timeout at max', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                timeoutMs: 999_999,
            }, workspaceRoot);
            expect(result.ok).toBe(true);
            expect(result.command!.timeoutMs).toBe(300_000);
        });
    });

    describe('formatValidatedCommand', () => {
        it('formats the command as a string', () => {
            const result = validateTestCommand({
                packageManager: 'npm',
                testFiles: ['tests/auth.test.ts'],
            }, workspaceRoot);
            if (result.ok && result.command) {
                expect(formatValidatedCommand(result.command)).toBe('npm test -- tests/auth.test.ts');
            }
        });
    });
});
