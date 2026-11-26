import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import type { SandboxBackend, SandboxExecuteOptions, SandboxExecuteResult } from './verificationSandbox';
import { fileExtFor, parseVerdictCommandMode, bundleScript, discoverAncestorNodeModules } from './verificationSandbox';

const PASS_PATTERN = /^PASS:\s*(.+)$/m;
const FAIL_PATTERN = /^FAIL:\s*(.+)$/m;

function parseVerdict(output: string, exitCode: number, timedOut: boolean): SandboxExecuteResult['verdict'] {
    if (timedOut) return 'timeout';
    if (PASS_PATTERN.test(output)) return 'pass';
    if (FAIL_PATTERN.test(output)) return 'fail';
    return 'error';
}

const COPY_SKIP_DIRS = new Set(['.git', 'node_modules', '.securecode', '.env', '__pycache__', '.venv', 'venv']);
const COPY_SKIP_EXTS = new Set(['.exe', '.dll', '.so', '.dylib', '.o', '.a', '.lib', '.obj', '.bin', '.iso', '.img', '.zip', '.tar', '.gz', '.7z', '.rar', '.jar', '.war']);
const MAX_COPY_SIZE = 200 * 1024 * 1024;
const MAX_COPY_FILES = 20_000;
const MAX_SINGLE_FILE = 10 * 1024 * 1024;
const ENV_FILE_RE = /^\.env(\..+)?$/;

interface CopyStats { bytes: number; files: number }

function copyWorkspace(src: string, dest: string, stats: CopyStats): void {
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        if (stats.files >= MAX_COPY_FILES || stats.bytes >= MAX_COPY_SIZE) return;
        const name = entry.name;
        if (COPY_SKIP_DIRS.has(name)) continue;
        if (ENV_FILE_RE.test(name)) continue;
        const srcPath = path.join(src, name);
        const destPath = path.join(dest, name);
        if (entry.isDirectory()) {
            fs.mkdirSync(destPath, { recursive: true });
            copyWorkspace(srcPath, destPath, stats);
        } else if (entry.isFile()) {
            const ext = path.extname(name).toLowerCase();
            if (COPY_SKIP_EXTS.has(ext)) continue;
            let size: number;
            try { size = fs.statSync(srcPath).size; } catch { continue; }
            if (size > MAX_SINGLE_FILE) continue;
            if (stats.bytes + size > MAX_COPY_SIZE) continue;
            try {
                fs.copyFileSync(srcPath, destPath);
                stats.bytes += size;
                stats.files++;
            } catch { /* skip unreadable files */ }
        }
    }
}

interface MirroredLayout {
    tmpRoot: string;
    workspaceCopy: string;
    junctions: string[];
    junctionTargets: string[];
}

function buildMirroredLayout(workspaceRoot: string): MirroredLayout {
    const wsNorm = path.resolve(workspaceRoot);
    const ancestors = discoverAncestorNodeModules(wsNorm);
    const externalNMs = ancestors.dirs.filter(nm =>
        path.resolve(nm) !== path.join(wsNorm, 'node_modules')
    );

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-local-'));

    if (externalNMs.length === 0) {
        const wsCopy = tmpRoot;
        copyWorkspace(wsNorm, wsCopy, { bytes: 0, files: 0 });
        const junctions: string[] = [];
        const junctionTargets: string[] = [];
        const wsOwnNM = path.join(wsNorm, 'node_modules');
        if (fs.existsSync(wsOwnNM)) {
            const dest = path.join(wsCopy, 'node_modules');
            try {
                if (process.platform === 'win32') {
                    fs.symlinkSync(wsOwnNM, dest, 'junction');
                } else {
                    fs.symlinkSync(wsOwnNM, dest, 'dir');
                }
                junctions.push(dest);
                junctionTargets.push(wsOwnNM);
            } catch { /* */ }
        }
        return { tmpRoot, workspaceCopy: wsCopy, junctions, junctionTargets };
    }

    let topDir = wsNorm;
    for (const nm of externalNMs) {
        const nmParent = path.dirname(path.resolve(nm));
        if (nmParent.length < topDir.length) topDir = nmParent;
    }

    const relWs = path.relative(topDir, wsNorm);
    const wsCopy = path.join(tmpRoot, relWs);
    fs.mkdirSync(wsCopy, { recursive: true });
    copyWorkspace(wsNorm, wsCopy, { bytes: 0, files: 0 });

    const junctions: string[] = [];
    const junctionTargets: string[] = [];

    const wsOwnNM = path.join(wsNorm, 'node_modules');
    if (fs.existsSync(wsOwnNM)) {
        const dest = path.join(wsCopy, 'node_modules');
        try {
            if (process.platform === 'win32') {
                fs.symlinkSync(wsOwnNM, dest, 'junction');
            } else {
                fs.symlinkSync(wsOwnNM, dest, 'dir');
            }
            junctions.push(dest);
            junctionTargets.push(wsOwnNM);
        } catch { /* */ }
    }

    for (const nm of externalNMs) {
        const nmNorm = path.resolve(nm);
        const relNM = path.relative(topDir, nmNorm);
        const dest = path.join(tmpRoot, relNM);
        if (fs.existsSync(dest)) continue;
        try {
            fs.mkdirSync(path.dirname(dest), { recursive: true });
            if (process.platform === 'win32') {
                fs.symlinkSync(nmNorm, dest, 'junction');
            } else {
                fs.symlinkSync(nmNorm, dest, 'dir');
            }
            junctions.push(dest);
            junctionTargets.push(nmNorm);
        } catch { /* skip */ }
    }

    return { tmpRoot, workspaceCopy: wsCopy, junctions, junctionTargets };
}

function cleanupMirroredLayout(layout: MirroredLayout): void {
    for (const junc of layout.junctions) {
        try {
            if (process.platform === 'win32') {
                fs.rmSync(junc, { recursive: false });
            } else {
                fs.unlinkSync(junc);
            }
        } catch { /* already gone */ }
    }
    try { fs.rmSync(layout.tmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
}

function detectPermissionModelSupport(): 'full' | 'experimental' | 'none' {
    const [major] = process.versions.node.split('.').map(Number);
    if (major >= 22) return 'full';
    if (major >= 20) return 'experimental';
    return 'none';
}

let _permissionSupport: 'full' | 'experimental' | 'none' | undefined;

function getPermissionSupport(): 'full' | 'experimental' | 'none' {
    if (_permissionSupport !== undefined) return _permissionSupport;
    const support = detectPermissionModelSupport();
    if (support === 'none') {
        _permissionSupport = support;
        return support;
    }
    const flag = support === 'full' ? '--permission' : '--experimental-permission';
    const nodeDir = path.dirname(process.execPath);
    const tmpTest = path.join(os.tmpdir(), `sc-perm-test-${Date.now()}`);
    try {
        fs.mkdirSync(tmpTest, { recursive: true });
        const sep = process.platform === 'win32' ? ';' : ',';
        const star = process.platform === 'win32' ? '\\*' : '/*';
        const r = spawnSync(process.execPath, [
            flag,
            `--allow-fs-read=${tmpTest + star}${sep}${nodeDir + star}`,
            `--allow-fs-write=${tmpTest + star}`,
            '-e', 'require("fs").existsSync(require("path").join(process.cwd(),".x")); process.exit(0)',
        ], {
            cwd: tmpTest,
            stdio: 'ignore',
            timeout: 5000,
        });
        _permissionSupport = r.status === 0 ? support : 'none';
    } catch {
        _permissionSupport = 'none';
    } finally {
        try { fs.rmSync(tmpTest, { recursive: true, force: true }); } catch { /* */ }
    }
    return _permissionSupport;
}

export function _resetPermissionCacheForTests(): void {
    _permissionSupport = undefined;
    _permProbeWithJunctionResult = undefined;
}

let _permProbeWithJunctionResult: boolean | undefined;

function permissionModelWorksWithJunction(layout: MirroredLayout): boolean {
    if (_permProbeWithJunctionResult !== undefined) return _permProbeWithJunctionResult;
    const support = getPermissionSupport();
    if (support === 'none') { _permProbeWithJunctionResult = false; return false; }
    if (layout.junctions.length === 0) { _permProbeWithJunctionResult = true; return true; }

    const flag = support === 'full' ? '--permission' : '--experimental-permission';
    const sep = process.platform === 'win32' ? ';' : ',';
    const star = process.platform === 'win32' ? '\\*' : '/*';
    const nodeDir = path.dirname(process.execPath);
    const readPaths = [layout.tmpRoot + star, nodeDir + star];
    for (const t of layout.junctionTargets) readPaths.push(t + star);

    const testPkg = layout.junctionTargets.length > 0
        ? findAnyPackageInNM(layout.junctionTargets[0])
        : null;
    if (!testPkg) { _permProbeWithJunctionResult = true; return true; }

    const r = spawnSync(process.execPath, [
        flag,
        `--allow-fs-read=${readPaths.join(sep)}`,
        `--allow-fs-write=${layout.tmpRoot + star}`,
        '-e', `try{require("${testPkg}");process.exit(0)}catch{process.exit(1)}`,
    ], {
        cwd: layout.workspaceCopy,
        stdio: 'ignore',
        timeout: 8000,
        env: { NODE_ENV: 'test', PATH: process.env.PATH || '', PATHEXT: process.env.PATHEXT || '', SystemRoot: process.env.SystemRoot || '' },
    });
    _permProbeWithJunctionResult = r.status === 0;
    return _permProbeWithJunctionResult;
}

function findAnyPackageInNM(nmDir: string): string | null {
    try {
        const entries = fs.readdirSync(nmDir);
        for (const e of entries) {
            if (e.startsWith('.') || e.startsWith('@')) continue;
            if (fs.existsSync(path.join(nmDir, e, 'package.json'))) return e;
        }
    } catch { /* */ }
    return null;
}

const NETWORK_BLOCK_PRELUDE = `
(function(){
  var _scListeningPorts = new Set();
  try {
    var net = require('net');
    var origListen = net.Server.prototype.listen;
    net.Server.prototype.listen = function() {
      var srv = this;
      var ret = origListen.apply(this, arguments);
      try {
        var check = function() {
          var addr = srv.address();
          if (addr && typeof addr === 'object' && addr.port) _scListeningPorts.add(addr.port);
        };
        if (srv.listening) check();
        srv.on('listening', check);
      } catch(e) {}
      return ret;
    };
    var origAddress = net.Server.prototype.address;
    net.Server.prototype.address = function() {
      var addr = origAddress.call(this);
      if (addr && typeof addr === 'object' && addr.port) _scListeningPorts.add(addr.port);
      return addr;
    };
    var origConnect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function() {
      var args = arguments;
      var port, host;
      var first = args[0];
      if (Array.isArray(first)) first = first[0];
      if (typeof first === 'number') { port = first; host = typeof args[1] === 'string' ? args[1] : '127.0.0.1'; }
      else if (typeof first === 'object' && first !== null) { port = first.port; host = first.host || first.hostname || '127.0.0.1'; }
      else if (typeof first === 'string' && !isNaN(Number(first))) { port = Number(first); host = '127.0.0.1'; }
      var isLoopback = !host || host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '0.0.0.0';
      if (port && isLoopback && _scListeningPorts.has(port)) {
        return origConnect.apply(this, arguments);
      }
      var self = this;
      var err = new Error('SECURECODE_SANDBOX: network access is blocked');
      err.code = 'ENETDENIED';
      process.nextTick(function() { self.destroy(err); });
      return this;
    };
    net.createConnection = function() {
      var sock = new net.Socket();
      return net.Socket.prototype.connect.apply(sock, arguments);
    };
    net.connect = net.createConnection;
  } catch(e) {}
  try {
    var tls = require('tls');
    var origTlsConnect = tls.connect;
    tls.connect = function() {
      var err = new Error('SECURECODE_SANDBOX: TLS network access is blocked');
      err.code = 'ENETDENIED';
      var sock = new (require('net').Socket)();
      process.nextTick(function() { sock.destroy(err); });
      return sock;
    };
  } catch(e) {}
  try {
    var dgram = require('dgram');
    dgram.Socket.prototype.send = function() {
      var cb = arguments[arguments.length - 1];
      var err = new Error('SECURECODE_SANDBOX: UDP network access is blocked');
      err.code = 'ENETDENIED';
      if (typeof cb === 'function') cb(err);
    };
  } catch(e) {}
  try {
    var dns = require('dns');
    var origDnsLookup = dns.lookup;
    var dnsErr = function(cb) {
      var err = new Error('SECURECODE_SANDBOX: DNS lookup is blocked');
      err.code = 'ENETDENIED';
      if (typeof cb === 'function') process.nextTick(function() { cb(err); });
    };
    dns.lookup = function(hostname, options, cb) {
      if (typeof options === 'function') { cb = options; options = {}; }
      if (hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1' || hostname === '0.0.0.0') {
        return origDnsLookup.call(dns, hostname, options, cb);
      }
      dnsErr(cb);
    };
    dns.resolve = function(_h, _t, cb) { if (typeof _t === 'function') cb = _t; dnsErr(cb); };
    dns.resolve4 = function(_h, _o, cb) { if (typeof _o === 'function') cb = _o; dnsErr(cb); };
    dns.resolve6 = function(_h, _o, cb) { if (typeof _o === 'function') cb = _o; dnsErr(cb); };
    if (dns.promises) {
      var dnsReject = function() { return Promise.reject(new Error('SECURECODE_SANDBOX: DNS is blocked')); };
      dns.promises.lookup = dnsReject;
      dns.promises.resolve = dnsReject;
      dns.promises.resolve4 = dnsReject;
      dns.promises.resolve6 = dnsReject;
    }
  } catch(e) {}
  try {
    var cp = require('child_process');
    var cpErr = function() { throw new Error('SECURECODE_SANDBOX: child_process is blocked'); };
    cp.exec = cpErr; cp.execSync = cpErr; cp.execFile = cpErr; cp.execFileSync = cpErr;
    cp.spawn = cpErr; cp.spawnSync = cpErr; cp.fork = cpErr;
  } catch(e) {}
  if (typeof globalThis.fetch === 'function') {
    globalThis.fetch = function() {
      return Promise.reject(new Error('SECURECODE_SANDBOX: network access is blocked (fetch)'));
    };
  }
})();
`;

function buildPreludeFile(dir: string): string {
    const p = path.join(dir, '_securecode_prelude.cjs');
    fs.writeFileSync(p, NETWORK_BLOCK_PRELUDE, 'utf8');
    return p;
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

function killTree(proc: ChildProcess): void {
    try {
        if (process.platform === 'win32') {
            if (proc.pid) {
                spawnSync('taskkill', ['/pid', String(proc.pid), '/T', '/F'], { stdio: 'ignore', shell: true });
            }
        } else {
            proc.kill('SIGKILL');
        }
    } catch { /* already dead */ }
}

function uniqueSuffix(): string {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export class LocalSandbox implements SandboxBackend {
    readonly name = 'local';

    get available(): boolean {
        return true;
    }

    async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        if (opts.mode === 'command') {
            return this.executeCommand(opts);
        }
        return this.executeScript(opts);
    }

    private async executeCommand(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        const executable = opts.executable;
        if (!executable) {
            return { verdict: 'error', output: 'Command mode requires "executable"', exitCode: -1, backend: this.name };
        }

        const layout = buildMirroredLayout(opts.workspaceRoot);
        try {
            const prelude = buildPreludeFile(layout.workspaceCopy);
            const permArgs = this.buildPermissionArgs(layout);
            const env = this.buildEnv(layout, permArgs.length > 0);

            const args = [...(opts.args || [])];
            const nodeBased = executable === 'npm' || executable === 'npx';

            const result = await this.runProcess(
                executable,
                nodeBased ? ['--require', prelude, ...args] : args,
                layout.workspaceCopy, env, permArgs, opts, false, permArgs.length > 0,
            );
            return result;
        } finally {
            cleanupMirroredLayout(layout);
        }
    }

    private async executeScript(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
        const runner = opts.runner || 'node';
        const needsBundle = runner === 'tsx';
        const layout = buildMirroredLayout(opts.workspaceRoot);
        const srcCleanup: string[] = [];
        try {
            const ext = fileExtFor(runner);
            const scDir = path.join(layout.workspaceCopy, '.securecode');
            fs.mkdirSync(scDir, { recursive: true });
            copyExpressRunner(scDir);
            const suffix = uniqueSuffix();

            let testFile: string;
            let setupFile: string | null = null;

            if (needsBundle) {
                const srcScDir = path.join(opts.workspaceRoot, '.securecode');
                if (!fs.existsSync(srcScDir)) fs.mkdirSync(srcScDir, { recursive: true });

                const srcTest = path.join(srcScDir, `verify-test-${suffix}${ext}`);
                fs.writeFileSync(srcTest, opts.script || '', 'utf8');
                srcCleanup.push(srcTest);

                const tb = bundleScript(srcTest, opts.workspaceRoot, srcScDir);
                if (!tb.ok) {
                    return { verdict: 'error', output: `TypeScript bundle failed: ${tb.error}`, exitCode: -1, backend: 'local/reduced' };
                }
                srcCleanup.push(tb.outPath!);
                const bundleName = path.basename(tb.outPath!);
                testFile = path.join(scDir, bundleName);
                fs.copyFileSync(tb.outPath!, testFile);

                if (opts.setupScript) {
                    const srcSetup = path.join(srcScDir, `verify-setup-${suffix}${ext}`);
                    fs.writeFileSync(srcSetup, opts.setupScript, 'utf8');
                    srcCleanup.push(srcSetup);

                    const sb = bundleScript(srcSetup, opts.workspaceRoot, srcScDir);
                    if (!sb.ok) {
                        return { verdict: 'error', output: `TypeScript setup bundle failed: ${sb.error}`, exitCode: -1, backend: 'local/reduced' };
                    }
                    srcCleanup.push(sb.outPath!);
                    const setupBundleName = path.basename(sb.outPath!);
                    setupFile = path.join(scDir, setupBundleName);
                    fs.copyFileSync(sb.outPath!, setupFile);
                }
            } else {
                testFile = path.join(scDir, `verify-test-${suffix}${ext}`);
                fs.writeFileSync(testFile, opts.script || '', 'utf8');
                if (opts.setupScript) {
                    const setupExt = (runner === 'python' || runner === 'python3') ? '.py' : ext;
                    setupFile = path.join(scDir, `verify-setup-${suffix}${setupExt}`);
                    fs.writeFileSync(setupFile, opts.setupScript, 'utf8');
                }
            }

            const prelude = buildPreludeFile(layout.workspaceCopy);
            const permArgs = this.buildPermissionArgs(layout);
            const env = this.buildEnv(layout, permArgs.length > 0);
            const permApplied = permArgs.length > 0;

            if (setupFile) {
                const setupResult = await this.runProcess(
                    this.resolveRunner(runner), this.buildRunnerArgs(runner, setupFile, prelude, permArgs),
                    layout.workspaceCopy, env, [], { ...opts, timeoutMs: Math.min(opts.timeoutMs, 10_000) }, true, permApplied,
                );
                if (setupResult.verdict === 'error' || setupResult.verdict === 'timeout') {
                    return {
                        verdict: 'error',
                        output: `Setup script failed: ${setupResult.output}`,
                        exitCode: setupResult.exitCode,
                        backend: permApplied ? 'local' : 'local/reduced',
                    };
                }
            }

            const result = await this.runProcess(
                this.resolveRunner(runner), this.buildRunnerArgs(runner, testFile, prelude, permArgs),
                layout.workspaceCopy, env, [], opts, true, permApplied,
            );
            return result;
        } finally {
            for (const f of srcCleanup) { try { fs.unlinkSync(f); } catch { /* */ } }
            cleanupMirroredLayout(layout);
        }
    }

    private buildEnv(layout: MirroredLayout, _permApplied: boolean): Record<string, string> {
        const env: Record<string, string> = {
            NODE_ENV: 'test',
            PATH: process.env.PATH || '',
            PATHEXT: process.env.PATHEXT || '',
        };
        if (process.platform === 'win32') {
            env.SystemRoot = process.env.SystemRoot || 'C:\\Windows';
            const tmpSub = path.join(layout.workspaceCopy, '_tmp');
            env.TEMP = tmpSub;
            env.TMP = tmpSub;
            try { fs.mkdirSync(tmpSub, { recursive: true }); } catch { /* */ }
        }
        return env;
    }

    private buildPermissionArgs(layout: MirroredLayout): string[] {
        const support = getPermissionSupport();
        if (support === 'none') return [];

        if (!permissionModelWorksWithJunction(layout)) return [];

        const flag = support === 'full' ? '--permission' : '--experimental-permission';
        const star = process.platform === 'win32' ? '\\*' : '/*';
        const readPaths = [layout.tmpRoot + star];
        for (const t of layout.junctionTargets) {
            readPaths.push(t + star);
        }
        const nodeDir = path.dirname(process.execPath);
        readPaths.push(nodeDir + star);
        const sep = process.platform === 'win32' ? ';' : ',';
        return [
            flag,
            `--allow-fs-read=${readPaths.join(sep)}`,
            `--allow-fs-write=${layout.tmpRoot + star}`,
        ];
    }

    private resolveRunner(runner: string): string {
        if (runner === 'python' || runner === 'python3') return 'python';
        return process.execPath;
    }

    private buildRunnerArgs(runner: string, scriptPath: string, prelude: string, permArgs: string[]): string[] {
        if (runner === 'python' || runner === 'python3') return [scriptPath];
        const args: string[] = [...permArgs];
        if (runner === 'tsx') {
            args.push('--enable-source-maps');
        }
        args.push('--require', prelude, scriptPath);
        return args;
    }

    private runProcess(
        bin: string,
        args: string[],
        cwd: string,
        env: Record<string, string>,
        _permArgs: string[],
        opts: Pick<SandboxExecuteOptions, 'timeoutMs' | 'signal' | 'mode'>,
        parseMarkers: boolean,
        permApplied: boolean,
    ): Promise<SandboxExecuteResult> {
        const isCommandMode = opts.mode === 'command';
        const backendLabel = permApplied ? 'local' : 'local/reduced';
        return new Promise((resolve) => {
            let stdout = '';
            let stderr = '';
            let timedOut = false;
            let cancelled = false;
            let settled = false;

            const proc = spawn(bin, args, {
                cwd,
                stdio: ['pipe', 'pipe', 'pipe'],
                shell: false,
                env,
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
                if (cancelled) {
                    resolve({
                        verdict: 'cancelled',
                        output: `Test cancelled. Partial output:\n${output.slice(0, 4000)}`,
                        exitCode: -1,
                        backend: backendLabel,
                    });
                    return;
                }
                const verdict = isCommandMode
                    ? parseVerdictCommandMode(exitCode, timedOut)
                    : parseMarkers
                        ? parseVerdict(output, exitCode, timedOut)
                        : parseVerdictCommandMode(exitCode, timedOut);
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
}
