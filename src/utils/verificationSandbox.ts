/**
 * Verification sandbox — the real security boundary for LLM-generated tests.
 *
 * Phase 2 of the agent scan pipeline takes an LLM-generated test script and
 * executes it on the user's machine. The previous implementation ran the
 * script via `execFileSync` with the full `process.env` spread and only a
 * decorative blocklist (`checkTestSafety`) in front. Prompt-injected code
 * in the scanned source could ride into the verify-generate prompt and
 * produce a test script that exfiltrated secrets, hit the network, or
 * spawned processes — `checkTestSafety` missed `fetch`, `http`, `https`,
 * `fs`, `dns`, `eval`, `new Function`, dynamic imports, and `process.env`
 * access.
 *
 * This module replaces that with a real isolation boundary. Pluggable
 * backends provide kernel-enforced isolation:
 *
 *   - DockerSandbox: `docker run --network=none --read-only --cpus=1
 *     --memory=256m --pids-limit=64 --user 1000:1000 -v <workspace>:/workspace:ro`
 *     — network disabled at the kernel level, filesystem read-only, temp
 *     dir as tmpfs, no host env, non-root user. Works for any Node/Python
 *     test script unchanged.
 *   - DenoSandbox: `deno run --allow-read=<workspace> --allow-write=<tmp>
 *     --allow-env=NODE_ENV --no-prompt --no-remote` — real permission
 *     model, no network, no arbitrary fs, no arbitrary env. Only works
 *     for test scripts that don't use `require()` (Deno is ESM-only by
 *     default); the verify-generate prompt must be told to emit
 *     Deno-compatible code when Deno is the backend.
 *
 * If neither backend is available, `detectSandbox()` returns null and the
 * caller MUST return INCONCLUSIVE. Never fall back to unrestricted
 * `execFileSync` — that is the bug this module exists to fix.
 *
 * `checkTestSafety()` remains as defense-in-depth (it can reject scripts
 * before we pay for a container start), but it is NOT the security
 * boundary. The sandbox is.
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawn, spawnSync, type ChildProcess } from 'child_process';

// ── Public interface ────────────────────────────────────────────────────────

export interface SandboxExecuteOptions {
    /** Execution mode: 'script' (default) runs a script via runner; 'command' runs a validated executable+args. */
    mode?: 'script' | 'command';
    /** Test script source code (required for mode='script'). */
    script?: string;
    /** Runner: 'node' | 'tsx' | 'bun' | 'python' | 'python3' | 'deno' | ... (required for mode='script'). */
    runner?: string;
    /** Validated executable (required for mode='command'). Passed as argv[0] — never via shell. */
    executable?: string;
    /** Validated args array (required for mode='command'). Each arg passed as a separate argv element. */
    args?: string[];
    /** Workspace root — mounted read-only into the sandbox. */
    workspaceRoot: string;
    /** Optional setup script run before the test (same sandbox). */
    setupScript?: string | null;
    /** Hard wall-clock timeout in ms. The sandbox kills the process at this boundary. */
    timeoutMs: number;
    /** AbortSignal — if aborted, the sandbox must kill the process and return. */
    signal?: AbortSignal;
}

export interface SandboxExecuteResult {
    verdict: 'pass' | 'fail' | 'error' | 'timeout' | 'blocked' | 'sandbox-unavailable';
    output: string;
    exitCode: number;
    /** Identifier of the backend that ran the test (for logging). */
    backend: string;
}

export interface SandboxBackend {
    readonly name: string;
    readonly available: boolean;
    execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult>;
}

// ── Verdict parsing (shared by backends) ─────────────────────────────────────

const PASS_PATTERN = /^PASS:\s*(.+)$/m;
const FAIL_PATTERN = /^FAIL:\s*(.+)$/m;

function parseVerdict(output: string, exitCode: number, timedOut: boolean): SandboxExecuteResult['verdict'] {
    if (timedOut) return 'timeout';
    if (PASS_PATTERN.test(output)) return 'pass';
    if (FAIL_PATTERN.test(output)) return 'fail';
    if (exitCode === 0) return 'error'; // ran but didn't print a marker
    return 'error';
}

/**
 * Command-mode verdict: no PASS:/FAIL: markers. Exit code 0 = pass, nonzero = fail.
 * This is the standard semantics for `npm test`, `pytest`, etc.
 */
export function parseVerdictCommandMode(exitCode: number, timedOut: boolean): SandboxExecuteResult['verdict'] {
    if (timedOut) return 'timeout';
    return exitCode === 0 ? 'pass' : 'fail';
}

/**
 * Pick the Docker image for a command-mode executable. Returns null if no
 * suitable image is configured — the caller returns sandbox-unavailable.
 */
export function pickImageForCommand(executable: string): { image: string | null; reason?: string } {
    if (executable === 'npm' || executable === 'npx') {
        return { image: process.env.SECURECODE_SANDBOX_IMAGE || 'node:20-alpine' };
    }
    if (executable === 'pnpm') {
        const img = process.env.SECURECODE_SANDBOX_PNPM_IMAGE;
        return img
            ? { image: img }
            : { image: null, reason: 'pnpm is not available in the default sandbox image. Set SECURECODE_SANDBOX_PNPM_IMAGE to a pnpm-enabled image to enable pnpm test execution.' };
    }
    if (executable === 'yarn') {
        const img = process.env.SECURECODE_SANDBOX_YARN_IMAGE;
        return img
            ? { image: img }
            : { image: null, reason: 'yarn is not available in the default sandbox image. Set SECURECODE_SANDBOX_YARN_IMAGE to a yarn-enabled image to enable yarn test execution.' };
    }
    if (executable === 'bun') {
        const img = process.env.SECURECODE_SANDBOX_BUN_IMAGE;
        return img
            ? { image: img }
            : { image: null, reason: 'bun is not available in the default sandbox image. Set SECURECODE_SANDBOX_BUN_IMAGE to a bun-enabled image to enable bun test execution.' };
    }
    if (executable === 'pytest') {
        return { image: process.env.SECURECODE_SANDBOX_PY_IMAGE || 'python:3.11-slim' };
    }
    return { image: null, reason: `No sandbox image configured for executable: ${executable}` };
}

// ── Probe caching ───────────────────────────────────────────────────────────

const probeCache = new Map<string, boolean>();

function probe(bin: string, args: string[] = ['--version']): boolean {
    const key = `${bin} ${args.join(' ')}`;
    if (probeCache.has(key)) return probeCache.get(key)!;
    let ok = false;
    try {
        const r = spawnSync(bin, args, {
            stdio: 'ignore',
            shell: process.platform === 'win32',
            timeout: 4000,
        });
        ok = r.status === 0;
    } catch {
        ok = false;
    }
    probeCache.set(key, ok);
    return ok;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function fileExtFor(runner: string): string {
    if (runner === 'python' || runner === 'python3') return '.py';
    if (runner === 'deno') return '.ts';
    if (runner === 'tsx' || runner === 'bun' || runner === 'node' || runner === 'pnpm-tsx' || runner === 'yarn-tsx') {
        return '.test.ts';
    }
    return '.test.js';
}

function uniqueSuffix(): string {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function ensureSandboxDir(workspaceRoot: string): string {
    const dir = path.join(workspaceRoot, '.securecode');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

function safeUnlink(p: string | null): void {
    if (!p) return;
    try { fs.unlinkSync(p); } catch { /* best effort */ }
}

// Kill a process tree, best-effort across platforms.
function killTree(proc: ChildProcess): void {
    try {
        if (process.platform === 'win32') {
            // Windows: use taskkill with /T to kill the tree.
            if (proc.pid) {
                spawnSync('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { stdio: 'ignore', shell: true });
            }
        } else {
            proc.kill('SIGKILL');
        }
    } catch { /* already dead */ }
}

// ── Docker backend ─────────────────────────────────────────────────────────

const DOCKER_IMAGE = process.env.SECURECODE_SANDBOX_IMAGE || 'node:20-alpine';
const DOCKER_PY_IMAGE = process.env.SECURECODE_SANDBOX_PY_IMAGE || 'python:3.11-slim';

class DockerSandbox implements SandboxBackend {
    readonly name = 'docker';

    get available(): boolean {
        return probe('docker', ['info']);
    }

    async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        // ── Command mode: run a validated executable + args in the sandbox ──
        if (opts.mode === 'command') {
            return this.executeCommand(opts);
        }
        // ── Script mode (default): write script to temp file and run via runner ──
        return this.executeScript(opts);
    }

    private async executeCommand(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        const executable = opts.executable;
        const cmdArgs = opts.args || [];
        if (!executable) {
            return { verdict: 'error', output: 'Command mode requires "executable"', exitCode: -1, backend: this.name };
        }

        const imageInfo = pickImageForCommand(executable);
        if (!imageInfo.image) {
            return {
                verdict: 'sandbox-unavailable',
                output: imageInfo.reason || `No sandbox image for ${executable}`,
                exitCode: -1,
                backend: this.name,
            };
        }

        const dockerArgs: string[] = [
            'run', '--rm', '-i',
            '--network=none',
            '--read-only',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,uid=1000,gid=1000',
            '--cpus=1',
            '--memory=512m',
            '--memory-swap=512m',
            '--pids-limit=128',
            '--user', '1000:1000',
            '--workdir', '/workspace',
            '--env', 'NODE_ENV=test',
            '--env', 'CI=1',
            '--env', 'HOME=/tmp',
            '--env', 'npm_config_cache=/tmp/npm-cache',
            '-v', `${opts.workspaceRoot}:/workspace:ro`,
            imageInfo.image,
            executable,
            ...cmdArgs,
        ];

        return await runSandboxedProcess('docker', dockerArgs, opts, this.name);
    }

    private async executeScript(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        const sandboxDir = ensureSandboxDir(opts.workspaceRoot);
        const ext = fileExtFor(opts.runner || 'node');
        const testFile = path.join(sandboxDir, `verify-test-${uniqueSuffix()}${ext}`);
        const setupFile = opts.setupScript
            ? path.join(sandboxDir, `verify-setup-${uniqueSuffix()}${ext}`)
            : null;

        try {
            fs.writeFileSync(testFile, opts.script || '', 'utf8');
            if (setupFile && opts.setupScript) {
                fs.writeFileSync(setupFile, opts.setupScript, 'utf8');
            }

            const isPython = opts.runner === 'python' || opts.runner === 'python3';
            const image = isPython ? DOCKER_PY_IMAGE : DOCKER_IMAGE;

            // Mount workspace read-only; the only writable area is /tmp (tmpfs).
            // Network disabled at the kernel level. CPU/mem/pids capped. Non-root.
            const dockerArgs: string[] = [
                'run', '--rm', '-i',
                '--network=none',
                '--read-only',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m,uid=1000,gid=1000',
                '--cpus=1',
                '--memory=256m',
                '--memory-swap=256m',
                '--pids-limit=64',
                '--user', '1000:1000',
                '--workdir', '/workspace',
                '--env', 'NODE_ENV=test',
                '--env', 'CI=1',
                '-v', `${opts.workspaceRoot}:/workspace:ro`,
                '-v', `${testFile}:/workspace/.securecode/test${ext}:ro`,
            ];
            if (setupFile) {
                dockerArgs.push('-v', `${setupFile}:/workspace/.securecode/setup${ext}:ro`);
            }
            dockerArgs.push(image);

            if (isPython) {
                if (setupFile) dockerArgs.push('python', '/workspace/.securecode/setup' + ext);
                dockerArgs.push('python', '/workspace/.securecode/test' + ext);
            } else {
                if (setupFile) dockerArgs.push('node', '/workspace/.securecode/setup' + ext);
                dockerArgs.push('node', '/workspace/.securecode/test' + ext);
            }

            return await runSandboxedProcess('docker', dockerArgs, opts, this.name);
        } finally {
            safeUnlink(testFile);
            safeUnlink(setupFile);
        }
    }
}

// ── Deno backend ────────────────────────────────────────────────────────────
//
// Deno's permission model is a real boundary: `--allow-none` (or no --allow-*
// flags) denies everything. We allow only:
//   --allow-read=<workspace>,<testFile>     (read workspace to import modules)
//   --allow-write=<tmpdir>                  (test may write a temp file)
//   --allow-env=NODE_ENV                    (only NODE_ENV; not process.env)
//   --no-remote                             (no network module fetches)
//   --no-prompt                             (fail instead of prompting)
//
// Caveat: Deno is ESM-only by default and cannot run tests that use require().
// The verify-generate prompt should detect Deno as the runner and emit
// ESM-compatible code. If the test uses require(), Deno will error out —
// which is a safe failure (no code executes).

class DenoSandbox implements SandboxBackend {
    readonly name = 'deno';

    get available(): boolean {
        return probe('deno', ['--version']);
    }

    async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        // Command mode: Deno can't run package-manager test commands (npm, pytest, etc.)
        // Return sandbox-unavailable so the caller surfaces the right message.
        if (opts.mode === 'command') {
            return {
                verdict: 'sandbox-unavailable',
                output: 'Deno sandbox cannot execute command-mode tests (npm/pnpm/yarn/bun/pytest). Docker is required for existing-test execution.',
                exitCode: -1,
                backend: this.name,
            };
        }

        if (opts.runner === 'python' || opts.runner === 'python3') {
            // Deno can't run Python.
            return {
                verdict: 'blocked',
                output: 'Deno sandbox cannot execute Python tests.',
                exitCode: -1,
                backend: this.name,
            };
        }

        const sandboxDir = ensureSandboxDir(opts.workspaceRoot);
        const ext = '.mts'; // Deno prefers .mts for ESM TS
        const testFile = path.join(sandboxDir, `verify-test-${uniqueSuffix()}${ext}`);
        const tmpDir = path.join(sandboxDir, `verify-tmp-${uniqueSuffix()}`);

        try {
            fs.writeFileSync(testFile, opts.script || '', 'utf8');
            fs.mkdirSync(tmpDir, { recursive: true });

            // Run setup first (if any) in the same sandbox.
            if (opts.setupScript) {
                const setupFile = path.join(sandboxDir, `verify-setup-${uniqueSuffix()}${ext}`);
                try {
                    fs.writeFileSync(setupFile, opts.setupScript, 'utf8');
                    const setupResult = await runSandboxedProcess(
                        'deno',
                        [
                            'run',
                            '--allow-read=' + opts.workspaceRoot,
                            '--allow-write=' + tmpDir,
                            '--allow-env=NODE_ENV',
                            '--no-remote',
                            '--no-prompt',
                            setupFile,
                        ],
                        { ...opts, timeoutMs: Math.min(opts.timeoutMs, 10_000) },
                        this.name + '/setup',
                    );
                    if (setupResult.verdict === 'error' || setupResult.verdict === 'timeout') {
                        return {
                            verdict: 'error',
                            output: `Setup script failed: ${setupResult.output}`,
                            exitCode: setupResult.exitCode,
                            backend: this.name,
                        };
                    }
                } finally {
                    safeUnlink(setupFile);
                }
            }

            const denoArgs = [
                'run',
                '--allow-read=' + opts.workspaceRoot + ',' + testFile,
                '--allow-write=' + tmpDir,
                '--allow-env=NODE_ENV',
                '--no-remote',
                '--no-prompt',
                testFile,
            ];

            return await runSandboxedProcess('deno', denoArgs, opts, this.name);
        } finally {
            safeUnlink(testFile);
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
        }
    }
}

// ── Subprocess runner shared by Docker/Deno backends ────────────────────────

function runSandboxedProcess(
    bin: string,
    args: string[],
    opts: SandboxExecuteOptions,
    backendLabel: string,
): Promise<SandboxExecuteResult> {
    const isCommandMode = opts.mode === 'command';
    return new Promise((resolve) => {
        let stdout = '';
        let stderr = '';
        let timedOut = false;
        let settled = false;

        const proc = spawn(bin, args, {
            cwd: opts.workspaceRoot,
            stdio: ['pipe', 'pipe', 'pipe'],
            shell: process.platform === 'win32',
            env: { NODE_ENV: 'test', CI: '1', PATH: process.env.PATH || '' },
            windowsHide: true,
        });

        proc.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
        proc.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });

        const timer = setTimeout(() => {
            timedOut = true;
            killTree(proc);
        }, opts.timeoutMs);

        const onAbort = () => {
            if (settled) return;
            timedOut = true;
            killTree(proc);
        };
        opts.signal?.addEventListener('abort', onAbort, { once: true });

        proc.on('error', (err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            opts.signal?.removeEventListener('abort', onAbort);
            resolve({
                verdict: 'error',
                output: `Failed to spawn ${bin}: ${err.message}`,
                exitCode: -1,
                backend: backendLabel,
            });
        });

        proc.on('close', (code) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            opts.signal?.removeEventListener('abort', onAbort);

            const output = (stdout + '\n' + stderr).trim();
            const exitCode = code ?? -1;
            const verdict = isCommandMode
                ? parseVerdictCommandMode(exitCode, timedOut)
                : parseVerdict(output, exitCode, timedOut);

            if (timedOut && verdict === 'error') {
                resolve({
                    verdict: 'timeout',
                    output: `Test timed out after ${opts.timeoutMs}ms. Partial output:\n${output.slice(0, 4000)}`,
                    exitCode: -1,
                    backend: backendLabel,
                });
                return;
            }

            resolve({
                verdict,
                output: output.slice(0, 16000),
                exitCode,
                backend: backendLabel,
            });
        });
    });
}

// ── Backend selection ───────────────────────────────────────────────────────

let cachedBackend: SandboxBackend | null | undefined;

/**
 * Detect the best available sandbox backend. Docker is preferred (runs any
 * Node/Python test unchanged); Deno is a fallback for TS/JS tests only.
 * Returns null if neither is available — the caller MUST return INCONCLUSIVE.
 */
export function detectSandbox(): SandboxBackend | null {
    if (cachedBackend !== undefined) return cachedBackend;

    const docker = new DockerSandbox();
    if (docker.available) {
        cachedBackend = docker;
        return docker;
    }

    const deno = new DenoSandbox();
    if (deno.available) {
        cachedBackend = deno;
        return deno;
    }

    cachedBackend = null;
    return null;
}

/** Reset the cached backend selection. Used by tests. */
export function _resetSandboxCacheForTests(): void {
    cachedBackend = undefined;
}

/** Force a specific backend (for tests). Pass null to simulate "no sandbox". */
export function _setSandboxForTests(backend: SandboxBackend | null): void {
    cachedBackend = backend;
}

// ── Unsafe host execution — ONLY for unit tests of the runner logic ─────────
//
// This backend runs scripts via direct `execFileSync` with the host's full
// privileges. It is NOT a security boundary. It exists solely so the runner's
// PASS/FAIL parsing and cleanup logic can be unit-tested without a real
// sandbox. Production code MUST NOT use it — `detectSandbox()` never returns
// it. The constructor requires `SECURECODE_TEST_MODE=1` so it cannot be
// accidentally instantiated in production.

export class __UnsafeHostSandboxForTests implements SandboxBackend {
    readonly name = 'unsafe-host-tests-only';

    constructor() {
        if (process.env.SECURECODE_TEST_MODE !== '1') {
            throw new Error(
                '__UnsafeHostSandboxForTests cannot be used in production. Set SECURECODE_TEST_MODE=1 only in tests.',
            );
        }
    }

    get available(): boolean { return true; }

    async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        if (opts.mode === 'command') {
            const executable = opts.executable || 'echo';
            const cmdArgs = opts.args || [];
            return await runSandboxedProcess(executable, cmdArgs, opts, this.name);
        }

        const sandboxDir = ensureSandboxDir(opts.workspaceRoot);
        const ext = fileExtFor(opts.runner || 'node');
        const testFile = path.join(sandboxDir, `verify-test-${uniqueSuffix()}${ext}`);

        try {
            fs.writeFileSync(testFile, opts.script || '', 'utf8');

            let runnerBin = opts.runner || 'node';
            let runnerArgs: string[] = [testFile];
            if (opts.runner === 'tsx') {
                runnerBin = 'npx';
                runnerArgs = ['tsx', testFile];
            } else if (opts.runner === 'pnpm-tsx') {
                runnerBin = 'pnpm';
                runnerArgs = ['exec', 'tsx', testFile];
            } else if (opts.runner === 'yarn-tsx') {
                runnerBin = 'yarn';
                runnerArgs = ['tsx', testFile];
            } else if (opts.runner === 'deno') {
                runnerBin = 'deno';
                runnerArgs = ['run', '--allow-all', testFile];
            }

            return await runSandboxedProcess(runnerBin, runnerArgs, opts, this.name);
        } finally {
            safeUnlink(testFile);
        }
    }
}
