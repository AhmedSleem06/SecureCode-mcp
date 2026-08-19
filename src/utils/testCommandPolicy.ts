/**
 * Test command policy — strict validation for existing-test mode of run_tests.
 *
 * Allows only known package-manager test commands (npm/pnpm/yarn/bun test,
 * pytest) with optional file/pattern arguments. Rejects shell operators,
 * arbitrary executables, lifecycle commands other than test, absolute paths
 * outside the workspace, and path traversal.
 *
 * Security rules:
 *   - No shell operators (&&, ||, ;, |, >, <, $(), backticks)
 *   - Only the `test` lifecycle command (no build/install/publish/run/exec)
 *   - No --shell/--script-shell escape flags
 *   - All file paths workspace-confined via resolveWorkspacePath
 *   - Output is a validated executable + args array (never a shell string)
 */

import * as path from 'path';
import { resolveWorkspacePath } from './files';

export type TestPackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'pytest';

export interface ValidatedTestCommand {
    packageManager: TestPackageManager;
    executable: string;
    args: string[];
    cwd: string;
    selectedFiles: string[];
    timeoutMs: number;
}

export interface CommandPolicyResult {
    ok: boolean;
    command?: ValidatedTestCommand;
    error?: string;
}

const SUPPORTED_PMS: TestPackageManager[] = ['npm', 'pnpm', 'yarn', 'bun', 'pytest'];

const SHELL_OPERATORS = ['&&', '||', ';', '|', '>', '<', '$(', '`', '>&', '<&'];

const BLOCKED_FLAGS = new Set([
    '--shell', '--script-shell', '--foreground-scripts', '--no-shell',
    '-S', '--bash', '--sh', '--cmd', '--exec', '--host',
]);

const NPM_TEST_SUBCOMMANDS = new Set(['test', 't', 'tst']);

const NPM_FORBIDDEN_SUBCOMMANDS = new Set([
    'run', 'run-script', 'exec', 'x', 'install', 'i', 'add', 'isntall',
    'uninstall', 'r', 'rm', 'publish', 'unpublish', 'build', 'rebuild',
    'start', 'stop', 'restart', 'pack', 'ci', 'fund', 'link', 'unlink',
    'create', 'init', 'hook', 'org', 'team', 'token', 'owner', 'access',
    'dist-tag', 'version', 'deprecate', 'profile', 'config', 'cache',
    'clean-install', 'ci-install', 'force-clean-install',
]);

const MAX_PATTERN_LENGTH = 200;
const MAX_FILES = 50;
const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_TIMEOUT_MS = 300_000;

function isWorkspaceRelative(p: string): boolean {
    if (!p) return false;
    if (path.isAbsolute(p)) return false;
    if (p.includes('..')) return false;
    if (p.startsWith('~')) return false;
    return true;
}

function isSafeFilePath(p: string, workspaceRoot: string): boolean {
    if (!isWorkspaceRelative(p)) return false;
    try {
        resolveWorkspacePath(workspaceRoot, p);
        return true;
    } catch {
        return false;
    }
}

function containsShellOperators(s: string): boolean {
    return SHELL_OPERATORS.some(op => s.includes(op));
}

function normalizePackageManager(pm: string): TestPackageManager | null {
    const lower = (pm || '').toLowerCase();
    return SUPPORTED_PMS.includes(lower as TestPackageManager) ? (lower as TestPackageManager) : null;
}

function validateTimeoutMs(timeoutMs: any): number {
    if (timeoutMs === undefined || timeoutMs === null) return DEFAULT_TIMEOUT_MS;
    const n = Number(timeoutMs);
    if (!Number.isFinite(n) || n <= 0) return DEFAULT_TIMEOUT_MS;
    return Math.min(Math.floor(n), MAX_TIMEOUT_MS);
}

function buildNpmArgs(testFiles: string[], testPattern: string | undefined): string[] {
    const args = ['test'];
    if (testFiles.length > 0 || testPattern) {
        args.push('--');
        if (testPattern) args.push(testPattern);
        for (const f of testFiles) args.push(f);
    }
    return args;
}

function buildPnpmArgs(testFiles: string[], testPattern: string | undefined): string[] {
    const args = ['test'];
    if (testFiles.length > 0 || testPattern) {
        args.push('--');
        if (testPattern) args.push(testPattern);
        for (const f of testFiles) args.push(f);
    }
    return args;
}

function buildYarnArgs(testFiles: string[], testPattern: string | undefined): string[] {
    const args = ['test'];
    if (testPattern) args.push(testPattern);
    for (const f of testFiles) args.push(f);
    return args;
}

function buildBunArgs(testFiles: string[], testPattern: string | undefined): string[] {
    const args = ['test'];
    if (testPattern) args.push(testPattern);
    for (const f of testFiles) args.push(f);
    return args;
}

function buildPytestArgs(testFiles: string[], testPattern: string | undefined): string[] {
    const args: string[] = [];
    if (testPattern) args.push('-k', testPattern);
    for (const f of testFiles) args.push(f);
    return args;
}

function detectSubcommand(arg: string): string | null {
    if (NPM_TEST_SUBCOMMANDS.has(arg)) return 'test';
    if (NPM_FORBIDDEN_SUBCOMMANDS.has(arg)) return arg;
    return null;
}

export function validateTestCommand(
    input: {
        packageManager?: string;
        testFiles?: string[];
        testPattern?: string;
        timeoutMs?: number;
    },
    workspaceRoot: string,
): CommandPolicyResult {
    const pm = input.packageManager
        ? normalizePackageManager(input.packageManager)
        : null;
    if (input.packageManager && !pm) {
        return { ok: false, error: `Unsupported package manager: ${input.packageManager}. Supported: ${SUPPORTED_PMS.join(', ')}` };
    }

    const testFilesRaw = Array.isArray(input.testFiles) ? input.testFiles : [];
    if (testFilesRaw.length > MAX_FILES) {
        return { ok: false, error: `Too many test files (max ${MAX_FILES})` };
    }

    const testPattern = input.testPattern;
    if (testPattern !== undefined && testPattern !== null) {
        if (typeof testPattern !== 'string') {
            return { ok: false, error: 'testPattern must be a string' };
        }
        if (testPattern.length > MAX_PATTERN_LENGTH) {
            return { ok: false, error: `testPattern too long (max ${MAX_PATTERN_LENGTH} chars)` };
        }
        if (containsShellOperators(testPattern)) {
            return { ok: false, error: `testPattern contains forbidden shell operators` };
        }
    }

    const testFiles: string[] = [];
    for (const f of testFilesRaw) {
        if (typeof f !== 'string' || f.length === 0) {
            return { ok: false, error: 'testFiles must be non-empty strings' };
        }
        if (containsShellOperators(f)) {
            return { ok: false, error: `test file path contains forbidden shell operators: ${f}` };
        }
        if (!isSafeFilePath(f, workspaceRoot)) {
            return { ok: false, error: `test file path is outside workspace or unsafe: ${f}` };
        }
        testFiles.push(f.replace(/\\/g, '/'));
    }

    const timeoutMs = validateTimeoutMs(input.timeoutMs);
    const packageManager = pm || 'npm';
    let executable: string;
    let args: string[];

    switch (packageManager) {
        case 'npm':
            executable = 'npm';
            args = buildNpmArgs(testFiles, testPattern);
            break;
        case 'pnpm':
            executable = 'pnpm';
            args = buildPnpmArgs(testFiles, testPattern);
            break;
        case 'yarn':
            executable = 'yarn';
            args = buildYarnArgs(testFiles, testPattern);
            break;
        case 'bun':
            executable = 'bun';
            args = buildBunArgs(testFiles, testPattern);
            break;
        case 'pytest':
            executable = 'pytest';
            args = buildPytestArgs(testFiles, testPattern);
            break;
        default:
            return { ok: false, error: `Unhandled package manager: ${packageManager}` };
    }

    for (const a of args) {
        if (BLOCKED_FLAGS.has(a)) {
            return { ok: false, error: `Forbidden flag in test command: ${a}` };
        }
    }

    const sub = detectSubcommand(args[0] || '');
    if (sub && sub !== 'test') {
        return { ok: false, error: `Forbidden npm subcommand: ${sub}. Only "test" is allowed.` };
    }

    return {
        ok: true,
        command: {
            packageManager,
            executable,
            args,
            cwd: workspaceRoot,
            selectedFiles: testFiles,
            timeoutMs,
        },
    };
}

export function formatValidatedCommand(cmd: ValidatedTestCommand): string {
    return `${cmd.executable} ${cmd.args.join(' ')}`;
}
