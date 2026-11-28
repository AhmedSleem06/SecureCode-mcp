/**
 * Verification sandbox â€” the real security boundary for LLM-generated tests.
 *
 * Phase 2 of the agent scan pipeline takes an LLM-generated test script and
 * executes it on the user's machine. The previous implementation ran the
 * script via `execFileSync` with the full `process.env` spread and only a
 * decorative blocklist (`checkTestSafety`) in front. Prompt-injected code
 * in the scanned source could ride into the verify-generate prompt and
 * produce a test script that exfiltrated secrets, hit the network, or
 * spawned processes â€” `checkTestSafety` missed `fetch`, `http`, `https`,
 * `fs`, `dns`, `eval`, `new Function`, dynamic imports, and `process.env`
 * access.
 *
 * This module replaces that with a real isolation boundary. Pluggable
 * backends provide kernel-enforced isolation:
 *
 *   - DockerSandbox: `docker run --network=none --cpus=1
 *     --memory=256m --pids-limit=64 --user 1000:1000 -v <workspace>:/workspace:ro`
 *     â€” network disabled at the kernel level, workspace read-only, temp
 *     dir as tmpfs, no host env, non-root user. Works for any Node/Python
 *     test script unchanged.
 *   - DenoSandbox: `deno run --allow-read=<workspace> --allow-write=<tmp>
 *     --allow-env=NODE_ENV --no-prompt --no-remote --unstable-detect-cjs
 *     --unstable-sloppy-imports` â€” real permission model, no network, no
 *     subprocesses, no arbitrary fs, no arbitrary env. Runs ESM (.mts) or
 *     CommonJS (.cjs, when the script uses require() and no import/export)
 *     test scripts; the verify-generate prompt is told the backend so it
 *     emits Deno-compatible code.
 *
 * If neither backend is available, `detectSandbox()` returns null and the
 * caller MUST return INCONCLUSIVE. Never fall back to unrestricted
 * `execFileSync` â€” that is the bug this module exists to fix.
 *
 * `checkTestSafety()` remains as defense-in-depth (it can reject scripts
 * before we pay for a container start), but it is NOT the security
 * boundary. The sandbox is.
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import { LocalSandbox } from './localSandbox';

// â”€â”€ Ancestor node_modules discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export interface AncestorNodeModules {
    dirs: string[];
    workspaceRoot: string;
}

function isGitRoot(dir: string): boolean {
    return fs.existsSync(path.join(dir, '.git'));
}

export function discoverAncestorNodeModules(workspaceRoot: string): AncestorNodeModules {
    const result: string[] = [];
    const wsNormalized = path.resolve(workspaceRoot);
    let current = wsNormalized;
    const MAX_LEVELS = 6;
    let hitGitRoot = false;

    for (let i = 0; i < MAX_LEVELS; i++) {
        const nm = path.join(current, 'node_modules');
        if (fs.existsSync(nm)) {
            try {
                const stat = fs.statSync(nm);
                if (stat.isDirectory()) result.push(nm);
            } catch { /* skip unreadable */ }
        }

        if (hitGitRoot) break;
        if (isGitRoot(current)) hitGitRoot = true;

        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
    }

    if (process.env.NODE_PATH) {
        const sep = process.platform === 'win32' ? ';' : ':';
        for (const p of process.env.NODE_PATH.split(sep)) {
            const resolved = path.resolve(p);
            if (fs.existsSync(resolved) && !result.includes(resolved)) {
                result.push(resolved);
            }
        }
    }

    return { dirs: result, workspaceRoot: wsNormalized };
}

export function buildDockerMountsForDeps(workspace: string, ancestorDirs: string[]): { mounts: string[]; workdir: string; toContainerPath: (hostPath: string) => string } {
    const wsNorm = path.resolve(workspace);
    const externalNMs = ancestorDirs.filter(nm =>
        path.resolve(nm) !== path.join(wsNorm, 'node_modules')
    );

    if (externalNMs.length === 0) {
        return {
            mounts: ['-v', `${wsNorm}:/workspace:ro`],
            workdir: '/workspace',
            toContainerPath: (hostPath: string) =>
                '/workspace/' + path.relative(wsNorm, hostPath).replace(/\\/g, '/'),
        };
    }

    let topDir = wsNorm;
    for (const nm of externalNMs) {
        const nmParent = path.dirname(path.resolve(nm));
        if (nmParent.length < topDir.length) topDir = nmParent;
    }

    const relWs = path.relative(topDir, wsNorm).replace(/\\/g, '/');
    const containerWs = `/w/${relWs}`;
    const mountArgs: string[] = ['-v', `${wsNorm}:${containerWs}:ro`];

    for (const nm of externalNMs) {
        const nmNorm = path.resolve(nm);
        const relNM = path.relative(topDir, nmNorm).replace(/\\/g, '/');
        const containerNM = `/w/${relNM}`;
        mountArgs.push('-v', `${nmNorm}:${containerNM}:ro`);
    }

    return {
        mounts: mountArgs,
        workdir: containerWs,
        toContainerPath: (hostPath: string) => {
            const rel = path.relative(wsNorm, hostPath).replace(/\\/g, '/');
            return `${containerWs}/${rel}`;
        },
    };
}

// â”€â”€ Host-side TypeScript bundler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export interface BundleResult {
    ok: boolean;
    code?: string;
    outPath?: string;
    error?: string;
}

function needsBanner(src: string, name: string): boolean {
    const declRe = new RegExp(`(?:const|let|var|function)\\s+${name}\\b`);
    if (declRe.test(src)) return false;
    const useRe = new RegExp(`\\b${name}\\b`);
    return useRe.test(src);
}

function outputNeedsRequire(output: string): boolean {
    if (/\b__require\b/.test(output)) return true;
    if (/\brequire\(/.test(output)) return true;
    return false;
}

export function bundleScript(
    scriptPath: string,
    workspaceRoot: string,
    outDir?: string,
): BundleResult {
    try {
        const esbuild: typeof import('esbuild') = require('esbuild');
        const src = fs.readFileSync(scriptPath, 'utf8');

        const srcNeedsBanner = needsBanner(src, 'require');

        let dirnameNeeded = false;
        let filenameNeeded = false;
        if (needsBanner(src, '__dirname')) {
            dirnameNeeded = true;
        } else if (needsBanner(src, '__filename')) {
            filenameNeeded = true;
        }

        const writeDir = outDir || path.dirname(scriptPath);
        const baseName = path.basename(scriptPath, path.extname(scriptPath));
        const outFile = path.join(writeDir, `${baseName}.bundle-${Date.now()}.mjs`);

        esbuild.buildSync({
            entryPoints: [scriptPath],
            bundle: true,
            platform: 'node',
            format: 'esm',
            target: 'node20',
            packages: 'external',
            sourcemap: 'inline',
            outfile: outFile,
            absWorkingDir: workspaceRoot,
            logLevel: 'silent',
        });

        if (!fs.existsSync(outFile)) {
            return { ok: false, error: 'esbuild produced no output file' };
        }

        let outputCode = fs.readFileSync(outFile, 'utf8');

        const requireBanner = 'import { createRequire as __scCR } from "node:module"; const require = __scCR(import.meta.url);';
        const addRequireBanner = !srcNeedsBanner && outputNeedsRequire(outputCode)
            ? !needsBanner(outputCode, 'require') ? false : true
            : srcNeedsBanner;

        const bannerLines: string[] = [];
        if (addRequireBanner || (outputNeedsRequire(outputCode) && !(/(?:const|let|var|function)\s+require\b/.test(outputCode)))) {
            bannerLines.push(requireBanner);
        }
        if (dirnameNeeded || needsBanner(outputCode, '__dirname')) {
            bannerLines.push('import { fileURLToPath as __scFU } from "node:url"; import { dirname as __scDN } from "node:path"; const __filename = __scFU(import.meta.url); const __dirname = __scDN(__filename);');
        } else if (filenameNeeded || needsBanner(outputCode, '__filename')) {
            bannerLines.push('import { fileURLToPath as __scFU } from "node:url"; const __filename = __scFU(import.meta.url);');
        }

        if (bannerLines.length > 0) {
            outputCode = bannerLines.join('\n') + '\n' + outputCode;
            fs.writeFileSync(outFile, outputCode, 'utf8');
        }

        return { ok: true, outPath: outFile, code: outputCode };
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return { ok: false, error: `esbuild bundle failed: ${msg.slice(0, 500)}` };
    }
}

// â”€â”€ Public interface â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export interface SandboxExecuteOptions {
    mode?: 'script' | 'command';
    script?: string;
    runner?: string;
    executable?: string;
    args?: string[];
    workspaceRoot: string;
    setupScript?: string | null;
    timeoutMs: number;
    signal?: AbortSignal;
    targetFilePath?: string;
}

export interface SandboxExecuteResult {
    verdict: 'pass' | 'fail' | 'error' | 'timeout' | 'blocked' | 'sandbox-unavailable' | 'cancelled';
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

// â”€â”€ Verdict parsing (shared by backends) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
 * suitable image is configured â€” the caller returns sandbox-unavailable.
 */
export function pickImageForCommand(executable: string): { image: string | null; reason?: string } {
    if (executable === 'npm' || executable === 'npx') {
        return { image: process.env.SECURECODE_SANDBOX_IMAGE || 'node:22-alpine' };
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
        return { image: process.env.SECURECODE_SANDBOX_BUN_IMAGE || 'oven/bun:1' };
    }
    if (executable === 'pytest') {
        return { image: process.env.SECURECODE_SANDBOX_PY_IMAGE || 'python:3.11-slim' };
    }
    if (executable === 'go') {
        return { image: process.env.SECURECODE_SANDBOX_GO_IMAGE || 'golang:1.23-alpine' };
    }
    if (executable === 'ruby' || executable === 'bundle') {
        return { image: process.env.SECURECODE_SANDBOX_RUBY_IMAGE || 'ruby:3.3-slim' };
    }
    if (executable === 'php') {
        return { image: process.env.SECURECODE_SANDBOX_PHP_IMAGE || 'php:8.3-cli' };
    }
    if (executable === 'mvn') {
        return { image: process.env.SECURECODE_SANDBOX_JAVA_MAVEN_IMAGE || 'maven:3.9-eclipse-temurin-21' };
    }
    if (executable === 'gradle') {
        return { image: process.env.SECURECODE_SANDBOX_JAVA_GRADLE_IMAGE || 'gradle:8-jdk21' };
    }
    if (executable === 'dotnet') {
        return { image: process.env.SECURECODE_SANDBOX_DOTNET_IMAGE || 'mcr.microsoft.com/dotnet/sdk:8.0' };
    }
    return { image: null, reason: `No sandbox image configured for executable: ${executable}` };
}

// â”€â”€ Probe caching â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const probeCache = new Map<string, boolean>();
let dockerPositiveCache = false;
let dockerNegativeExpiry = 0;
const DOCKER_NEGATIVE_TTL_MS = 60_000;
const DOCKER_PROBE_TIMEOUT_MS = 15_000;

function resolveWindowsBin(bin: string): { cmd: string; preArgs: string[] } | null {
    if (process.platform !== 'win32') return null;
    try {
        const r = spawnSync('where.exe', [bin], { stdio: ['ignore', 'pipe', 'ignore'], timeout: 4000 });
        if (r.status !== 0 || !r.stdout) return null;
        const lines = r.stdout.toString('utf8').split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        const exe = lines.find(l => /\.exe$/i.test(l));
        if (exe) return { cmd: exe, preArgs: [] };
        const shim = lines.find(l => /\.(cmd|bat)$/i.test(l));
        if (shim) return { cmd: 'cmd.exe', preArgs: ['/c', shim] };
        return null;
    } catch {
        return null;
    }
}

function probeDockerOnce(): boolean {
    let cmd = 'docker';
    let args = ['info', '--format', '{{.ServerVersion}}'];
    const resolved = resolveWindowsBin('docker');
    if (resolved) {
        cmd = resolved.cmd;
        args = [...resolved.preArgs, 'info', '--format', '{{.ServerVersion}}'];
    }
    try {
        const r = spawnSync(cmd, args, {
            stdio: ['ignore', 'pipe', 'ignore'],
            shell: false,
            timeout: DOCKER_PROBE_TIMEOUT_MS,
        });
        return r.status === 0 && !!r.stdout && r.stdout.toString('utf8').trim().length > 0;
    } catch {
        return false;
    }
}

export function probeDocker(): boolean {
    if (dockerPositiveCache) return true;
    if (Date.now() < dockerNegativeExpiry) return false;

    let ok = probeDockerOnce();
    if (!ok) ok = probeDockerOnce(); // retry once

    if (ok) {
        dockerPositiveCache = true;
    } else {
        dockerNegativeExpiry = Date.now() + DOCKER_NEGATIVE_TTL_MS;
    }
    return ok;
}

export function _resetDockerCacheForTests(): void {
    dockerPositiveCache = false;
    dockerNegativeExpiry = 0;
}

function probe(bin: string, args: string[] = ['--version']): boolean {
    if (bin === 'docker') return probeDocker();
    const key = `${bin} ${args.join(' ')}`;
    if (probeCache.has(key)) return probeCache.get(key)!;
    let ok = false;
    try {
        let cmd = bin;
        let cmdArgs = args;
        const resolved = resolveWindowsBin(bin);
        if (resolved) {
            cmd = resolved.cmd;
            cmdArgs = [...resolved.preArgs, ...args];
        }
        const r = spawnSync(cmd, cmdArgs, {
            stdio: 'ignore',
            shell: false,
            timeout: 4000,
        });
        ok = r.status === 0;
    } catch {
        ok = false;
    }
    probeCache.set(key, ok);
    return ok;
}

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/**
 * Pick the file extension for a generated script-mode runner.
 *
 *   - node â†’ '.mjs': plain `node` runs ESM .mjs natively and cannot execute
 *     TypeScript â€” a .ts file is a guaranteed failure for every node-runner
 *     script.
 *   - tsx / pnpm-tsx / yarn-tsx / bun / deno â†’ '.ts': TS-capable runners
 *     (bun and deno execute TS natively; the tsx variants strip types).
 *   - python / python3 â†’ '.py'.
 *   - anything else â†’ '.js'.
 *
 * No '.test.' infix: these are standalone verification scripts, not
 * test-suite files, and the infix risks accidental discovery by workspace
 * test runners.
 */
export function fileExtFor(runner: string): string {
    if (runner === 'python' || runner === 'python3') return '.py';
    if (runner === 'node') return '.mjs';
    if (runner === 'tsx' || runner === 'pnpm-tsx' || runner === 'yarn-tsx' || runner === 'bun' || runner === 'deno') {
        return '.ts';
    }
    if (runner === 'go') return '.go';
    if (runner === 'ruby') return '.rb';
    if (runner === 'php') return '.php';
    if (runner === 'java-maven' || runner === 'java-gradle') return '.java';
    if (runner === 'dotnet') return '.cs';
    return '.js';
}

function isPythonRunner(runner: string): boolean {
    return runner === 'python' || runner === 'python3';
}

/**
 * Pick the Docker image for a script-mode runner. Returns null if no suitable
 * image is configured â€” the caller returns sandbox-unavailable so the user
 * gets a clear "install X / set ENV to enable" message rather than a crash.
 */
const COMPILED_LANG_RUNNERS = new Set(['go', 'ruby', 'php', 'java-maven', 'java-gradle', 'dotnet']);
const COMPILED_LANG_TIMEOUT_MS = 180_000;

export function isCompiledLangRunner(runner: string): boolean {
    return COMPILED_LANG_RUNNERS.has(runner);
}

export function pickImageForRunner(runner: string): { image: string | null; reason?: string } {
    if (isPythonRunner(runner)) {
        return { image: process.env.SECURECODE_SANDBOX_PY_IMAGE || 'python:3.11-slim' };
    }
    switch (runner) {
        case 'node':
        case 'tsx':
        case 'pnpm-tsx':
        case 'yarn-tsx':
            return { image: process.env.SECURECODE_SANDBOX_IMAGE || 'node:22-alpine' };
        case 'deno': {
            const img = process.env.SECURECODE_SANDBOX_DENO_IMAGE;
            return img
                ? { image: img }
                : { image: null, reason: 'deno runner requires a Deno image. Set SECURECODE_SANDBOX_DENO_IMAGE (e.g. denoland/deno) to enable deno script execution.' };
        }
        case 'bun':
            return { image: process.env.SECURECODE_SANDBOX_BUN_IMAGE || 'oven/bun:1' };
        case 'go':
            return { image: process.env.SECURECODE_SANDBOX_GO_IMAGE || 'golang:1.23-alpine' };
        case 'ruby':
            return { image: process.env.SECURECODE_SANDBOX_RUBY_IMAGE || 'ruby:3.3-slim' };
        case 'php':
            return { image: process.env.SECURECODE_SANDBOX_PHP_IMAGE || 'php:8.3-cli' };
        case 'java-maven':
            return { image: process.env.SECURECODE_SANDBOX_JAVA_MAVEN_IMAGE || 'maven:3.9-eclipse-temurin-21' };
        case 'java-gradle':
            return { image: process.env.SECURECODE_SANDBOX_JAVA_GRADLE_IMAGE || 'gradle:8-jdk21' };
        case 'dotnet':
            return { image: process.env.SECURECODE_SANDBOX_DOTNET_IMAGE || 'mcr.microsoft.com/dotnet/sdk:8.0' };
        default:
            return { image: null, reason: `No sandbox image configured for runner: ${runner}` };
    }
}

/**
 * Build the in-container command string for a runner + script path.
 * The path is generated by us (unique suffix), so shell quoting is not
 * required for safety; we still quote defensively in case the workspace
 * path contains spaces.
 */
export function runnerInvocation(runner: string, scriptPath: string, workdir?: string): string {
    const p = `"${scriptPath}"`;
    const wd = workdir || '/workspace';
    switch (runner) {
        case 'node':
            return `node ${p}`;
        case 'tsx':
            return `node --enable-source-maps ${p}`;
        case 'pnpm-tsx':
            return `pnpm exec tsx ${p}`;
        case 'yarn-tsx':
            return `yarn tsx ${p}`;
        case 'bun':
            return `bun run ${p}`;
        case 'deno':
            return `deno run --allow-read=${wd} --allow-env=NODE_ENV --no-prompt ${p}`;
        case 'python':
        case 'python3':
            return `python ${p}`;
        case 'go': {
            const goDir = scriptPath ? path.posix.dirname(scriptPath).replace(/^\.?\/?/, '') : '.';
            return `go test -run TestSecureCodeProof -v -count=1 ./${goDir || '.'}`;
        }
        case 'ruby':
            return `bundle exec ruby ${p}`;
        case 'php':
            return `php ${p}`;
        case 'java-maven':
            return `mvn -o -q test -Dtest=ScProofTest -Dmaven.repo.local=/tmp/m2 -Dmaven.repo.local.tail=/tmp/m2-ro`;
        case 'java-gradle':
            return `gradle test --offline --no-daemon --tests ScProofTest`;
        case 'dotnet':
            return `dotnet test ScProof --no-restore`;
        default:
            return `node ${p}`;
    }
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

function copyExpressRunner(destDir: string): void {
    const candidates = [
        path.resolve(__dirname, '../assurance/harness/expressRunner.cjs'),
        path.resolve(__dirname, '../../src/assurance/harness/expressRunner.cjs'),
    ];
    for (const src of candidates) {
        if (fs.existsSync(src)) {
            fs.copyFileSync(src, path.join(destDir, 'expressRunner.cjs'));
            return;
        }
    }
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

export function parseJavaPackagePath(script: string): string {
    const m = script.match(/^\s*package\s+([\w.]+)\s*;/m);
    if (!m) return '';
    return m[1].replace(/\./g, '/');
}

export function buildCompiledLangPlacement(runner: string, script: string, targetFilePath?: string): { testRelPath: string; runCmd: string } {
    if (runner === 'go') {
        const targetDir = targetFilePath ? path.dirname(targetFilePath) : '.';
        const normalizedDir = targetDir.replace(/\\/g, '/').replace(/^\.?\/?/, '');
        const testRelPath = normalizedDir
            ? `${normalizedDir}/sc_proof_test.go`
            : 'sc_proof_test.go';
        const runDir = normalizedDir || '.';
        return {
            testRelPath,
            runCmd: `go test -run TestSecureCodeProof -v -count=1 ./${runDir}`,
        };
    }
    if (runner === 'ruby') {
        return {
            testRelPath: 'sc_proof.rb',
            runCmd: 'bundle exec ruby sc_proof.rb',
        };
    }
    if (runner === 'php') {
        return {
            testRelPath: 'sc_proof.php',
            runCmd: 'php sc_proof.php',
        };
    }
    if (runner === 'java-maven' || runner === 'java-gradle') {
        const pkgPath = parseJavaPackagePath(script);
        const testRelDir = pkgPath
            ? `src/test/java/${pkgPath}`
            : 'src/test/java';
        const runCmd = runner === 'java-maven'
            ? 'mvn -o -q test -Dtest=ScProofTest -Dmaven.repo.local=/tmp/m2 -Dmaven.repo.local.tail=/tmp/m2-ro'
            : 'gradle test --offline --no-daemon --tests ScProofTest';
        return {
            testRelPath: `${testRelDir}/ScProofTest.java`,
            runCmd,
        };
    }
    if (runner === 'dotnet') {
        return {
            testRelPath: 'ScProof/ScProofTest.cs',
            runCmd: 'dotnet test ScProof --no-restore',
        };
    }
    return { testRelPath: `sc_proof_test${fileExtFor(runner)}`, runCmd: '' };
}

const OFFLINE_DEPS_PATTERNS: Array<{ pattern: RegExp; lang: string; hint?: string }> = [
    { pattern: /cannot find module providing package|module lookup disabled by GOPROXY=off/i, lang: 'go' },
    { pattern: /Could not resolve dependencies|offline mode|Cannot access .* in offline mode/i, lang: 'java-maven' },
    { pattern: /No cached version .* available for offline mode|Could not resolve all dependencies/i, lang: 'java-gradle' },
    { pattern: /Unable to find package|NU1101|Unable to load the service index|Failed to retrieve information about .* from remote source/i, lang: 'dotnet' },
    { pattern: /Could not find gem|bundle install/i, lang: 'ruby', hint: 'Ruby gems must be vendored: bundle config set --local path vendor/bundle && bundle install' },
    { pattern: /vendor\/autoload\.php.*No such file|Failed opening required.*vendor\/autoload/i, lang: 'php', hint: 'run composer install' },
];

export function isOfflineDepsFailure(output: string): { match: boolean; detail: string; hint?: string } {
    for (const { pattern, hint } of OFFLINE_DEPS_PATTERNS) {
        const m = output.match(pattern);
        if (m) return { match: true, detail: m[0], hint };
    }
    return { match: false, detail: '' };
}

class DockerSandbox implements SandboxBackend {
    readonly name = 'docker';

    get available(): boolean {
        return probe('docker', ['info']);
    }

    async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        // â”€â”€ Command mode: run a validated executable + args in the sandbox â”€â”€
        if (opts.mode === 'command') {
            return this.executeCommand(opts);
        }
        // â”€â”€ Script mode (default): write script to temp file and run via runner â”€â”€
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

        const ancestors = discoverAncestorNodeModules(opts.workspaceRoot);
        const depInfo = buildDockerMountsForDeps(opts.workspaceRoot, ancestors.dirs);

        const dockerArgs: string[] = [
            'run', '--rm', '-i',
            '--network=none',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,uid=1000,gid=1000',
            '--cpus=1',
            '--memory=512m',
            '--memory-swap=512m',
            '--pids-limit=128',
            '--user', '1000:1000',
            '--workdir', depInfo.workdir,
            '--env', 'NODE_ENV=test',
            '--env', 'CI=1',
            '--env', 'HOME=/tmp',
            '--env', 'npm_config_cache=/tmp/npm-cache',
            ...depInfo.mounts,
        ];
        dockerArgs.push(
            imageInfo.image,
            executable,
            ...cmdArgs,
        );

        return await runSandboxedProcess('docker', dockerArgs, opts, this.name);
    }

    private async executeScript(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        const runner = opts.runner || 'node';
        if (COMPILED_LANG_RUNNERS.has(runner)) {
            return this.executeCompiledLangScript(opts);
        }

        const sandboxDir = ensureSandboxDir(opts.workspaceRoot);
        copyExpressRunner(sandboxDir);
        const needsBundle = runner === 'tsx';
        const ext = fileExtFor(runner);
        const srcSuffix = uniqueSuffix();
        const srcTestFile = path.join(sandboxDir, `verify-test-${srcSuffix}${ext}`);
        const setupExt = isPythonRunner(runner) ? '.py' : ext;
        const srcSetupFile = opts.setupScript
            ? path.join(sandboxDir, `verify-setup-${srcSuffix}${setupExt}`)
            : null;

        const cleanupFiles: string[] = [];

        try {
            fs.writeFileSync(srcTestFile, opts.script || '', 'utf8');
            cleanupFiles.push(srcTestFile);
            if (srcSetupFile && opts.setupScript) {
                fs.writeFileSync(srcSetupFile, opts.setupScript, 'utf8');
                cleanupFiles.push(srcSetupFile);
            }

            let testFile = srcTestFile;
            let setupFile = srcSetupFile;

            if (needsBundle) {
                const tb = bundleScript(srcTestFile, opts.workspaceRoot, sandboxDir);
                if (!tb.ok) {
                    return { verdict: 'error', output: `TypeScript bundle failed: ${tb.error}`, exitCode: -1, backend: this.name };
                }
                testFile = tb.outPath!;
                cleanupFiles.push(testFile);

                if (srcSetupFile) {
                    const sb = bundleScript(srcSetupFile, opts.workspaceRoot, sandboxDir);
                    if (!sb.ok) {
                        return { verdict: 'error', output: `TypeScript setup bundle failed: ${sb.error}`, exitCode: -1, backend: this.name };
                    }
                    setupFile = sb.outPath!;
                    cleanupFiles.push(setupFile);
                }
            }

            const imageInfo = pickImageForRunner(runner);
            if (!imageInfo.image) {
                return {
                    verdict: 'sandbox-unavailable',
                    output: imageInfo.reason || `No sandbox image for runner: ${runner}`,
                    exitCode: -1,
                    backend: this.name,
                };
            }

            const ancestors = discoverAncestorNodeModules(opts.workspaceRoot);
            const depInfo = buildDockerMountsForDeps(opts.workspaceRoot, ancestors.dirs);

            const containerTestPath = depInfo.toContainerPath(testFile);
            const containerSetupPath = setupFile ? depInfo.toContainerPath(setupFile) : '';

            const dockerArgs: string[] = [
                'run', '--rm', '-i',
                '--network=none',
                '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m,uid=1000,gid=1000',
                '--cpus=1',
                '--memory=256m',
                '--memory-swap=256m',
                '--pids-limit=64',
                '--user', '1000:1000',
                '--workdir', depInfo.workdir,
                '--env', 'NODE_ENV=test',
                '--env', 'CI=1',
                '--env', 'HOME=/tmp',
                '--env', 'npm_config_cache=/tmp/npm-cache',
                ...depInfo.mounts,
            ];

            dockerArgs.push(imageInfo.image);

            const effectiveRunner = needsBundle ? 'tsx' : runner;
            const testCmd = runnerInvocation(effectiveRunner, containerTestPath, depInfo.workdir);
            const fullCmd = setupFile
                ? `${runnerInvocation(effectiveRunner, containerSetupPath, depInfo.workdir)} && ${testCmd}`
                : testCmd;

            dockerArgs.push('sh', '-c', fullCmd);

            return await runSandboxedProcess('docker', dockerArgs, opts, this.name);
        } finally {
            for (const f of cleanupFiles) safeUnlink(f);
        }
    }

    private async executeCompiledLangScript(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        const runner = opts.runner || 'go';
        const imageInfo = pickImageForRunner(runner);
        if (!imageInfo.image) {
            return {
                verdict: 'sandbox-unavailable',
                output: imageInfo.reason || `No sandbox image for runner: ${runner}`,
                exitCode: -1,
                backend: this.name,
            };
        }

        const wsNorm = path.resolve(opts.workspaceRoot);
        const osModule = require('os') as typeof import('os');
        const homeDir = osModule.homedir();

        const depMounts: string[] = [];
        const extraEnv: string[] = [];
        if (runner === 'go') {
            const gomodcache = process.env.GOMODCACHE;
            const gopath = process.env.GOPATH || path.join(homeDir, 'go');
            const modCache = gomodcache || path.join(gopath, 'pkg', 'mod');
            if (fs.existsSync(modCache)) {
                depMounts.push('-v', `${modCache}:/tmp/gomod:ro`);
                extraEnv.push('--env', 'GOMODCACHE=/tmp/gomod');
            }
            extraEnv.push('--env', 'GOPROXY=off');
            extraEnv.push('--env', 'GOCACHE=/tmp/gocache');
            if (fs.existsSync(path.join(wsNorm, 'vendor'))) {
                extraEnv.push('--env', 'GOFLAGS=-mod=vendor');
            }
        } else if (runner === 'java-maven') {
            const m2Repo = path.join(homeDir, '.m2', 'repository');
            if (fs.existsSync(m2Repo)) {
                depMounts.push('-v', `${m2Repo}:/tmp/m2-ro:ro`);
            }
        } else if (runner === 'java-gradle') {
            const gradleCaches = path.join(homeDir, '.gradle', 'caches');
            if (fs.existsSync(gradleCaches)) {
                depMounts.push('-v', `${gradleCaches}:/tmp/gradle-ro:ro`);
                extraEnv.push('--env', 'GRADLE_RO_DEP_CACHE=/tmp/gradle-ro');
            }
            extraEnv.push('--env', 'GRADLE_USER_HOME=/tmp/gradle-home');
        } else if (runner === 'dotnet') {
            const nugetPkgs = path.join(homeDir, '.nuget', 'packages');
            if (fs.existsSync(nugetPkgs)) {
                depMounts.push('-v', `${nugetPkgs}:/tmp/.nuget/packages:ro`);
            }
            extraEnv.push('--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1');
            extraEnv.push('--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1');
        }

        const timeoutMs = opts.timeoutMs || COMPILED_LANG_TIMEOUT_MS;
        const placement = buildCompiledLangPlacement(runner, opts.script || '', opts.targetFilePath);

        const proofOutFile = '/tmp/sc_proof_out.txt';
        extraEnv.push('--env', `SECURECODE_PROOF_OUT=${proofOutFile}`);
        const catProofOut = `; if [ -f ${proofOutFile} ]; then echo '---SECURECODE_PROOF_FILE---'; cat ${proofOutFile}; fi`;

        let runCmdAdjusted = placement.runCmd;
        if (runner === 'java-gradle') {
            const initScript = `allprojects { tasks.withType(Test).configureEach { testLogging { showStandardStreams = true; events 'passed','failed' } } }`;
            const writeInit = `printf '%s' '${initScript}' > /tmp/sc-init.gradle`;
            runCmdAdjusted = `${writeInit} && ${placement.runCmd.replace('gradle test', 'gradle test --init-script /tmp/sc-init.gradle')}`;
        }
        if (runner === 'dotnet') {
            runCmdAdjusted = placement.runCmd.replace('dotnet test ScProof --no-restore', 'dotnet test ScProof --no-restore --logger "console;verbosity=detailed"');
        }

        let placeAndRun: string;
        if (runner === 'dotnet') {
            const appCsprojSearch = `APP_CSPROJ=$(find /tmp/ws -maxdepth 3 -name '*.csproj' ! -path '*/ScProof/*' | head -1)`;
            const genCsproj = `mkdir -p /tmp/ws/ScProof && cat > /tmp/ws/ScProof/ScProof.csproj << 'CSPROJEOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="xunit" Version="*" />
    <PackageReference Include="xunit.runner.visualstudio" Version="*" />
    <PackageReference Include="Microsoft.NET.Test.Sdk" Version="*" />
  </ItemGroup>
  <ItemGroup Condition="'$(APP_CSPROJ)' != ''">
    <ProjectReference Include="$(APP_CSPROJ)" />
  </ItemGroup>
</Project>
CSPROJEOF`;
            const restoreCmd = 'dotnet restore ScProof --source /tmp/.nuget/packages --ignore-failed-sources';
            placeAndRun = `cp -a /workspace /tmp/ws && cd /tmp/ws && ${appCsprojSearch} && ${genCsproj} && cat /tmp/sc_test_b64 | base64 -d > /tmp/ws/${placement.testRelPath} && ${restoreCmd} && ${runCmdAdjusted}${catProofOut}`;
        } else if (runner === 'java-gradle') {
            const testDir = path.posix.dirname(placement.testRelPath);
            const mkdirCmd = testDir && testDir !== '.' ? `mkdir -p /tmp/ws/${testDir} && ` : '';
            placeAndRun = `cp -a /workspace /tmp/ws && cd /tmp/ws && ${mkdirCmd}cat /tmp/sc_test_b64 | base64 -d > /tmp/ws/${placement.testRelPath} && ${runCmdAdjusted}${catProofOut}`;
        } else {
            const testDir = path.posix.dirname(placement.testRelPath);
            const mkdirCmd = testDir && testDir !== '.' ? `mkdir -p /tmp/ws/${testDir} && ` : '';
            placeAndRun = `cp -a /workspace /tmp/ws && cd /tmp/ws && ${mkdirCmd}cat /tmp/sc_test_b64 | base64 -d > /tmp/ws/${placement.testRelPath} && ${runCmdAdjusted}${catProofOut}`;
        }

        const b64Script = Buffer.from(opts.script || '').toString('base64');

        const dockerArgs: string[] = [
            'run', '--rm', '-i',
            '--network=none',
            '--cpus=1',
            '--memory=512m',
            '--memory-swap=512m',
            '--pids-limit=128',
            '--workdir', '/workspace',
            '--env', 'CI=1',
            '--env', 'HOME=/tmp',
            ...extraEnv,
            '-v', `${wsNorm}:/workspace:ro`,
            ...depMounts,
            imageInfo.image,
            'sh', '-c',
            `printf '%s' '${b64Script}' > /tmp/sc_test_b64 && ${placeAndRun}`,
        ];

        const adjustedOpts = { ...opts, timeoutMs };
        return await runSandboxedProcess('docker', dockerArgs, adjustedOpts, this.name);
    }
}

// â”€â”€ Deno backend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// Deno's permission model is a real boundary: `--allow-none` (or no --allow-*
// flags) denies everything. We allow only:
//   --allow-read=<workspace>,<testFile>     (read workspace to import modules)
//   --allow-write=<tmpdir>                  (test may write a temp file)
//   --allow-env=NODE_ENV                    (only NODE_ENV; not process.env)
//   --no-remote                             (no network module fetches)
//   --no-prompt                             (fail instead of prompting)
//
// Caveat: Deno resolves modules ESM-style. We pass --unstable-detect-cjs so
// CommonJS project files (module.exports / require) can be loaded, and
// --unstable-sloppy-imports so extensionless relative imports resolve. A
// test script that uses require() and no ESM import/export is written as
// .cjs so Deno runs it as CommonJS; everything else is written as .mts.

const DENO_COMPAT_FLAGS = ['--unstable-detect-cjs', '--unstable-sloppy-imports'];

const ESM_SYNTAX = /^\s*(?:import(?:\s+[\w$*{'"]|\s*[{*'"])|export\s)|\bimport\.meta\b/m;
const CJS_REQUIRE = /\brequire\s*\(/;

export function denoScriptExt(script: string): '.cjs' | '.mts' {
    return CJS_REQUIRE.test(script) && !ESM_SYNTAX.test(script) ? '.cjs' : '.mts';
}

export function denoRunArgs(scriptFile: string, readPaths: string[], writeDir: string): string[] {
    return [
        'run',
        '--allow-read=' + readPaths.join(','),
        '--allow-write=' + writeDir,
        '--allow-env=NODE_ENV',
        '--no-remote',
        '--no-prompt',
        ...DENO_COMPAT_FLAGS,
        scriptFile,
    ];
}

export class DenoSandbox implements SandboxBackend {
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
        copyExpressRunner(sandboxDir);
        const testFile = path.join(sandboxDir, `verify-test-${uniqueSuffix()}${denoScriptExt(opts.script || '')}`);
        const tmpDir = path.join(sandboxDir, `verify-tmp-${uniqueSuffix()}`);

        try {
            fs.writeFileSync(testFile, opts.script || '', 'utf8');
            fs.mkdirSync(tmpDir, { recursive: true });

            // Run setup first (if any) in the same sandbox.
            if (opts.setupScript) {
                const setupFile = path.join(sandboxDir, `verify-setup-${uniqueSuffix()}${denoScriptExt(opts.setupScript)}`);
                try {
                    fs.writeFileSync(setupFile, opts.setupScript, 'utf8');
                    const setupResult = await runSandboxedProcess(
                        'deno',
                        denoRunArgs(setupFile, [opts.workspaceRoot], tmpDir),
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

            const denoArgs = denoRunArgs(testFile, [opts.workspaceRoot, testFile], tmpDir);

            return await runSandboxedProcess('deno', denoArgs, opts, this.name);
        } finally {
            safeUnlink(testFile);
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ }
        }
    }
}

// â”€â”€ Subprocess runner shared by Docker/Deno backends â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        let cancelled = false;
        let settled = false;

        let spawnBin = bin;
        let spawnArgs = args;
        const resolved = resolveWindowsBin(bin);
        if (resolved) {
            spawnBin = resolved.cmd;
            spawnArgs = [...resolved.preArgs, ...args];
        }

        const proc = spawn(spawnBin, spawnArgs, {
            cwd: opts.workspaceRoot,
            stdio: ['pipe', 'pipe', 'pipe'],
            shell: false,
            env: {
                NODE_ENV: 'test',
                CI: '1',
                PATH: process.env.PATH || '',
                PATHEXT: process.env.PATHEXT || '',
                SystemRoot: process.env.SystemRoot || '',
            },
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
            cancelled = true;
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

            // Cancellation takes priority over timeout â€” if the user aborted,
            // we must not report a timeout (which can trigger a retry).
            if (cancelled) {
                resolve({
                    verdict: 'cancelled',
                    output: `Test cancelled by user. Partial output:\n${output.slice(0, 4000)}`,
                    exitCode: -1,
                    backend: backendLabel,
                });
                return;
            }

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

// â”€â”€ Backend selection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

let cachedBackend: SandboxBackend | null | undefined;
let cachedOverride: string | undefined;

function loadLocalSandboxLazy(): SandboxBackend | null {
    try {
        return new LocalSandbox();
    } catch {
        return null;
    }
}

export function detectSandbox(): SandboxBackend | null {
    const override = process.env.SECURECODE_SANDBOX;
    if (cachedBackend !== undefined && cachedOverride === override) return cachedBackend;
    cachedOverride = override;

    if (override === 'none') { cachedBackend = null; return null; }

    if (override === 'docker') {
        const d = new DockerSandbox();
        cachedBackend = d.available ? d : null;
        return cachedBackend;
    }
    if (override === 'deno') {
        const d = new DenoSandbox();
        cachedBackend = d.available ? d : null;
        return cachedBackend;
    }
    if (override === 'local') {
        cachedBackend = loadLocalSandboxLazy();
        return cachedBackend;
    }

    // Auto: docker â†’ local â†’ (deno only if explicitly selected)
    const docker = new DockerSandbox();
    if (docker.available) {
        cachedBackend = docker;
        return docker;
    }

    const local = loadLocalSandboxLazy();
    if (local && local.available) {
        cachedBackend = local;
        return local;
    }

    cachedBackend = null;
    return null;
}

/** Reset the cached backend selection. Used by tests. */
export function _resetSandboxCacheForTests(): void {
    cachedBackend = undefined;
    cachedOverride = undefined;
}

/** Force a specific backend (for tests). Pass null to simulate "no sandbox". */
export function _setSandboxForTests(backend: SandboxBackend | null): void {
    cachedBackend = backend;
}

// â”€â”€ Unsafe host execution â€” ONLY for unit tests of the runner logic â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// This backend runs scripts via direct `execFileSync` with the host's full
// privileges. It is NOT a security boundary. It exists solely so the runner's
// PASS/FAIL parsing and cleanup logic can be unit-tested without a real
// sandbox. Production code MUST NOT use it â€” `detectSandbox()` never returns
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
        copyExpressRunner(sandboxDir);
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
