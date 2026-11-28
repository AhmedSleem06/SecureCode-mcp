import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawnSync } from 'child_process';

export type ProjectRuntime = 'bun' | 'node' | 'deno' | 'python' | 'go' | 'ruby' | 'php' | 'java' | 'dotnet';
export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'pip' | 'poetry' | 'uv' | 'go' | 'bundler' | 'composer' | 'maven' | 'gradle' | 'nuget' | null;
export type Framework =
    | 'electron' | 'next' | 'remix' | 'nuxt'
    | 'react-native'
    | 'express' | 'fastify' | 'nestjs' | 'koa' | 'hapi'
    | 'flask' | 'fastapi' | 'django'
    | 'react' | 'vue' | 'svelte'
    | 'cloudflare-workers'
    | 'net/http' | 'gin' | 'echo'
    | 'rails'
    | 'laravel'
    | 'spring-boot'
    | 'aspnet-core'
    | null;
export type TestabilityTier = 1 | 2 | 3 | 4;

export interface RuntimeInfo {
    runtime: ProjectRuntime;
    runner: string;
    suggestedRunner: string;
    packageManager: PackageManager;
    framework: Framework;
    frameworkVersion: string | null;
    testabilityTier: TestabilityTier;
    canRunLocally: boolean;
    skipReason?: string;
    hasBunLock: boolean;
    depsInstalled: boolean;
}

const JS_FRAMEWORK_RULES: Array<{ dep: string; framework: Framework; tier: TestabilityTier }> = [
    { dep: 'react-native', framework: 'react-native', tier: 4 },
    { dep: '@cloudflare/workers-types', framework: 'cloudflare-workers', tier: 4 },
    { dep: 'wrangler', framework: 'cloudflare-workers', tier: 4 },
    { dep: 'electron', framework: 'electron', tier: 2 },
    { dep: 'next', framework: 'next', tier: 2 },
    { dep: '@remix-run/node', framework: 'remix', tier: 2 },
    { dep: 'remix', framework: 'remix', tier: 2 },
    { dep: 'nuxt', framework: 'nuxt', tier: 2 },
    { dep: '@nestjs/core', framework: 'nestjs', tier: 1 },
    { dep: 'fastify', framework: 'fastify', tier: 1 },
    { dep: 'express', framework: 'express', tier: 1 },
    { dep: 'koa', framework: 'koa', tier: 1 },
    { dep: '@hapi/hapi', framework: 'hapi', tier: 1 },
    { dep: 'svelte', framework: 'svelte', tier: 3 },
    { dep: 'vue', framework: 'vue', tier: 3 },
    { dep: 'react', framework: 'react', tier: 3 },
];

const PY_FRAMEWORK_RULES: Array<{ dep: string; framework: Framework; tier: TestabilityTier }> = [
    { dep: 'fastapi', framework: 'fastapi', tier: 1 },
    { dep: 'flask', framework: 'flask', tier: 1 },
    { dep: 'django', framework: 'django', tier: 1 },
];

const TIER_SKIP_REASONS: Record<number, string> = {
    4: 'Framework requires a runtime that cannot be invoked locally (Metro/worker runtime). Set canTest: false.',
};

const probeCache = new Map<string, boolean>();

function probe(bin: string): boolean {
    if (probeCache.has(bin)) return probeCache.get(bin)!;
    let ok = false;
    try {
        const r = spawnSync(bin, ['--version'], {
            stdio: 'ignore',
            shell: process.platform === 'win32',
            timeout: 4000,
        });
        ok = r.status === 0;
    } catch {
        ok = false;
    }
    probeCache.set(bin, ok);
    return ok;
}

function readJson(file: string): any | null {
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
        return null;
    }
}

function exists(...files: string[]): boolean {
    return files.some(f => fs.existsSync(f));
}

function findNearest(
    startDir: string,
    root: string,
    candidates: string[],
): { dir: string; file: string } | null {
    let dir = startDir;
    const rootAbs = path.resolve(root);
    while (true) {
        for (const c of candidates) {
            const p = path.join(dir, c);
            if (fs.existsSync(p)) return { dir, file: p };
        }
        const parent = path.dirname(dir);
        if (parent === dir || !dir.startsWith(rootAbs)) break;
        dir = parent;
    }
    return null;
}

function detectJsFramework(pkg: any): { framework: Framework; version: string | null; tier: TestabilityTier } {
    if (!pkg) return { framework: null, version: null, tier: 1 };
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    for (const rule of JS_FRAMEWORK_RULES) {
        if (deps[rule.dep]) {
            return { framework: rule.framework, version: deps[rule.dep] || null, tier: rule.tier };
        }
    }
    return { framework: null, version: null, tier: 1 };
}

function detectPyFramework(startDir: string, root: string): { framework: Framework; version: string | null; tier: TestabilityTier } {
    const reqs = findNearest(startDir, root, ['requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile']);
    if (!reqs) return { framework: null, version: null, tier: 1 };
    let text = '';
    try {
        text = fs.readFileSync(reqs.file, 'utf8');
    } catch {
        return { framework: null, version: null, tier: 1 };
    }
    const lower = text.toLowerCase();
    for (const rule of PY_FRAMEWORK_RULES) {
        const re = new RegExp(`^\\s*${rule.dep}(\\s*[=><~!]|\\s*$)`, 'im');
        if (re.test(lower)) {
            const verMatch = lower.match(new RegExp(`${rule.dep}\\s*[=><~!]*\\s*([0-9][0-9a-zA-Z.\\-]*)`, 'im'));
            return { framework: rule.framework, version: verMatch ? verMatch[1] : null, tier: rule.tier };
        }
    }
    return { framework: null, version: null, tier: 1 };
}

function resolveJsRunner(runtime: ProjectRuntime, pkgManager: PackageManager): string {
    if (runtime === 'bun') return probe('bun') ? 'bun' : 'tsx';
    if (runtime === 'deno') return probe('deno') ? 'deno' : 'tsx';
    if (pkgManager === 'pnpm' && probe('pnpm')) return 'pnpm-tsx';
    if (pkgManager === 'yarn' && probe('yarn')) return 'yarn-tsx';
    return 'tsx';
}

function resolvePythonRunner(): { runner: string; installed: boolean } {
    if (probe('python3')) return { runner: 'python3', installed: true };
    if (probe('python')) return { runner: 'python', installed: true };
    return { runner: 'python3', installed: false };
}

function detectPackageManager(pkg: any, nearest: { dir: string; file: string } | null): PackageManager {
    if (pkg?.packageManager) {
        const pm = String(pkg.packageManager).toLowerCase();
        if (pm.startsWith('bun')) return 'bun';
        if (pm.startsWith('pnpm')) return 'pnpm';
        if (pm.startsWith('yarn')) return 'yarn';
        if (pm.startsWith('npm')) return 'npm';
    }
    if (nearest) {
        const dir = nearest.dir;
        if (exists(path.join(dir, 'bun.lockb'), path.join(dir, 'bun.lock'))) return 'bun';
        if (exists(path.join(dir, 'pnpm-lock.yaml'))) return 'pnpm';
        if (exists(path.join(dir, 'yarn.lock'))) return 'yarn';
        if (exists(path.join(dir, 'package-lock.json'))) return 'npm';
    }
    return 'npm';
}

function readText(file: string): string | null {
    try {
        return fs.readFileSync(file, 'utf8');
    } catch {
        return null;
    }
}

function detectGoFramework(startDir: string, root: string): { framework: Framework; version: string | null; tier: TestabilityTier } {
    const gomod = findNearest(startDir, root, ['go.mod']);
    if (!gomod) return { framework: 'net/http', version: null, tier: 1 };
    const text = readText(gomod.file);
    if (!text) return { framework: 'net/http', version: null, tier: 1 };
    const ginRe = /^\s*(?:require\s+)?github\.com\/gin-gonic\/gin\s+(v[\d.]+)?/m;
    const ginMatch = text.match(ginRe);
    if (ginMatch) return { framework: 'gin', version: ginMatch[1] || null, tier: 1 };
    const echoRe = /^\s*(?:require\s+)?github\.com\/labstack\/echo\s+(v[\d.]+)?/m;
    const echoMatch = text.match(echoRe);
    if (echoMatch) return { framework: 'echo', version: echoMatch[1] || null, tier: 1 };
    return { framework: 'net/http', version: null, tier: 1 };
}

function detectRubyFramework(startDir: string, root: string): { framework: Framework; version: string | null; tier: TestabilityTier } {
    const gemlock = findNearest(startDir, root, ['Gemfile.lock', 'Gemfile']);
    if (!gemlock) return { framework: null, version: null, tier: 2 };
    const text = readText(gemlock.file);
    if (!text) return { framework: null, version: null, tier: 2 };
    const railsRe = /rails\s+\(([0-9][0-9a-zA-Z.\-]*)\)/;
    const railsMatch = text.match(railsRe);
    if (railsMatch) return { framework: 'rails', version: railsMatch[1], tier: 1 };
    if (/\brails\b/i.test(text)) return { framework: 'rails', version: null, tier: 1 };
    return { framework: null, version: null, tier: 2 };
}

function detectPhpFramework(startDir: string, root: string): { framework: Framework; version: string | null; tier: TestabilityTier } {
    const composerLock = findNearest(startDir, root, ['composer.lock', 'composer.json']);
    if (!composerLock) return { framework: null, version: null, tier: 2 };
    const text = readText(composerLock.file);
    if (!text) return { framework: null, version: null, tier: 2 };
    const laravelRe = /laravel\/framework/i;
    if (laravelRe.test(text)) {
        const verRe = /"laravel\/framework"\s*:\s*"([^"]+)"/;
        const verMatch = text.match(verRe);
        return { framework: 'laravel', version: verMatch ? verMatch[1] : null, tier: 1 };
    }
    return { framework: null, version: null, tier: 2 };
}

function detectJavaFramework(startDir: string, root: string): { framework: Framework; version: string | null; tier: TestabilityTier; buildTool: 'maven' | 'gradle' | null } {
    const pom = findNearest(startDir, root, ['pom.xml']);
    if (pom) {
        const text = readText(pom.file);
        if (text && /spring-boot/i.test(text)) {
            const verRe = /<spring-boot\.version>([^<]+)<\/spring-boot\.version>/;
            const verMatch = text.match(verRe);
            return { framework: 'spring-boot', version: verMatch ? verMatch[1] : null, tier: 1, buildTool: 'maven' };
        }
        return { framework: null, version: null, tier: 2, buildTool: 'maven' };
    }
    const gradle = findNearest(startDir, root, ['build.gradle', 'build.gradle.kts']);
    if (gradle) {
        const text = readText(gradle.file);
        if (text && /spring-boot/i.test(text)) {
            const verRe = /spring-boot.*?['"]([0-9][0-9a-zA-Z.\-]*)['"]/;
            const verMatch = text.match(verRe);
            return { framework: 'spring-boot', version: verMatch ? verMatch[1] : null, tier: 1, buildTool: 'gradle' };
        }
        return { framework: null, version: null, tier: 2, buildTool: 'gradle' };
    }
    return { framework: null, version: null, tier: 2, buildTool: null };
}

function detectDotnetFramework(startDir: string, root: string): { framework: Framework; version: string | null; tier: TestabilityTier } {
    const csproj = findNearest(startDir, root, ['*.csproj']);
    if (!csproj) {
        try {
            const entries = fs.readdirSync(startDir);
            for (const e of entries) {
                if (e.endsWith('.csproj')) {
                    const text = readText(path.join(startDir, e));
                    if (text && (/Microsoft\.AspNetCore/i.test(text) || /Sdk="Microsoft\.NET\.Sdk\.Web"/i.test(text))) {
                        const verRe = /TargetFramework>net([0-9.]+)</;
                        const verMatch = text.match(verRe);
                        return { framework: 'aspnet-core', version: verMatch ? verMatch[1] : null, tier: 1 };
                    }
                    return { framework: null, version: null, tier: 2 };
                }
            }
        } catch { /* */ }
        let dir = startDir;
        const rootAbs = path.resolve(root);
        while (true) {
            try {
                const entries = fs.readdirSync(dir);
                for (const e of entries) {
                    if (e.endsWith('.csproj')) {
                        const text = readText(path.join(dir, e));
                        if (text && (/Microsoft\.AspNetCore/i.test(text) || /Sdk="Microsoft\.NET\.Sdk\.Web"/i.test(text))) {
                            const verRe = /TargetFramework>net([0-9.]+)</;
                            const verMatch = text.match(verRe);
                            return { framework: 'aspnet-core', version: verMatch ? verMatch[1] : null, tier: 1 };
                        }
                        return { framework: null, version: null, tier: 2 };
                    }
                }
            } catch { /* */ }
            const parent = path.dirname(dir);
            if (parent === dir || !dir.startsWith(rootAbs)) break;
            dir = parent;
        }
    }
    return { framework: null, version: null, tier: 2 };
}

function goModuleCacheExists(): boolean {
    const gomodcache = process.env.GOMODCACHE;
    if (gomodcache && fs.existsSync(gomodcache)) return true;
    const gopath = process.env.GOPATH || path.join(os.homedir(), 'go');
    return fs.existsSync(path.join(gopath, 'pkg', 'mod'));
}

function goDepsInstalled(startDir: string): boolean {
    if (exists(path.join(startDir, 'vendor'))) return true;
    return goModuleCacheExists();
}

function rubyDepsInstalled(startDir: string, root: string): boolean {
    if (exists(path.join(startDir, 'vendor', 'bundle'))) return true;
    if (exists(path.join(root, 'vendor', 'bundle'))) return true;
    return false;
}

function phpDepsInstalled(startDir: string, root: string): boolean {
    return exists(path.join(startDir, 'vendor')) || exists(path.join(root, 'vendor'));
}

function javaDepsInstalled(): boolean {
    const m2 = path.join(os.homedir(), '.m2');
    if (fs.existsSync(m2)) return true;
    const gradleCache = path.join(os.homedir(), '.gradle', 'caches');
    if (fs.existsSync(gradleCache)) return true;
    return false;
}

function dotnetDepsInstalled(startDir: string, root: string): boolean {
    return exists(path.join(startDir, 'obj', 'project.assets.json')) ||
        exists(path.join(root, 'obj', 'project.assets.json'));
}

export function detectRuntime(workspaceRoot: string, filePath?: string): RuntimeInfo {
    const rootAbs = path.resolve(workspaceRoot);
    const isPythonFile = filePath ? /\.p(yi?|yx)$/i.test(filePath) : false;
    const isGoFile = filePath ? /\.go$/i.test(filePath) : false;
    const isRubyFile = filePath ? /\.rb$/i.test(filePath) : false;
    const isPhpFile = filePath ? /\.php$/i.test(filePath) : false;
    const isJavaFile = filePath ? /\.(java|kt)$/i.test(filePath) : false;
    const isDotnetFile = filePath ? /\.cs$/i.test(filePath) : false;

    const startDir = filePath
        ? path.resolve(rootAbs, path.dirname(filePath))
        : rootAbs;

    if (isGoFile || (!filePath && exists(path.join(rootAbs, 'go.mod')))) {
        const { framework, version, tier } = detectGoFramework(startDir, rootAbs);
        return {
            runtime: 'go',
            runner: 'go',
            suggestedRunner: 'go',
            packageManager: 'go',
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: true,
            hasBunLock: false,
            depsInstalled: goDepsInstalled(startDir),
        };
    }

    if (isRubyFile || (!filePath && exists(path.join(rootAbs, 'Gemfile')))) {
        const { framework, version, tier } = detectRubyFramework(startDir, rootAbs);
        return {
            runtime: 'ruby',
            runner: 'ruby',
            suggestedRunner: 'ruby',
            packageManager: 'bundler',
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: true,
            hasBunLock: false,
            depsInstalled: rubyDepsInstalled(startDir, rootAbs),
        };
    }

    if (isPhpFile || (!filePath && exists(path.join(rootAbs, 'composer.json')))) {
        const { framework, version, tier } = detectPhpFramework(startDir, rootAbs);
        return {
            runtime: 'php',
            runner: 'php',
            suggestedRunner: 'php',
            packageManager: 'composer',
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: true,
            hasBunLock: false,
            depsInstalled: phpDepsInstalled(startDir, rootAbs),
        };
    }

    if (isJavaFile || (!filePath && (exists(path.join(rootAbs, 'pom.xml')) || exists(path.join(rootAbs, 'build.gradle')) || exists(path.join(rootAbs, 'build.gradle.kts'))))) {
        const { framework, version, tier, buildTool } = detectJavaFramework(startDir, rootAbs);
        const runner = buildTool === 'gradle' ? 'java-gradle' : 'java-maven';
        return {
            runtime: 'java',
            runner,
            suggestedRunner: runner,
            packageManager: buildTool === 'gradle' ? 'gradle' : 'maven',
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: true,
            hasBunLock: false,
            depsInstalled: javaDepsInstalled(),
        };
    }

    if (isDotnetFile || (!filePath && (() => { try { return fs.readdirSync(rootAbs).some(e => e.endsWith('.csproj')); } catch { return false; } })())) {
        const { framework, version, tier } = detectDotnetFramework(startDir, rootAbs);
        return {
            runtime: 'dotnet',
            runner: 'dotnet',
            suggestedRunner: 'dotnet',
            packageManager: 'nuget',
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: true,
            hasBunLock: false,
            depsInstalled: dotnetDepsInstalled(startDir, rootAbs),
        };
    }

    if (isPythonFile) {
        const pyStartDir = filePath
            ? path.resolve(rootAbs, path.dirname(filePath))
            : rootAbs;
        const py = resolvePythonRunner();
        const { framework, version, tier } = detectPyFramework(pyStartDir, rootAbs);
        const pkgMan = (() => {
            if (exists(path.join(pyStartDir, 'poetry.lock'))) return 'poetry';
            if (exists(path.join(pyStartDir, 'uv.lock'))) return 'uv';
            if (exists(path.join(pyStartDir, 'Pipfile'))) return 'pip';
            if (exists(path.join(pyStartDir, 'requirements.txt'), path.join(pyStartDir, 'pyproject.toml'))) return 'pip';
            return null;
        })();
        const canRun = py.installed && tier !== 4;
        return {
            runtime: 'python',
            runner: py.runner,
            suggestedRunner: py.runner,
            packageManager: pkgMan,
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: canRun,
            skipReason: !py.installed
                ? 'Python interpreter not found in PATH. Install python3 to run local exploit tests.'
                : tier === 4 ? TIER_SKIP_REASONS[4] : undefined,
            hasBunLock: false,
            depsInstalled: exists(path.join(pyStartDir, '__pycache__')) || exists(path.join(pyStartDir, '.venv'), path.join(pyStartDir, 'venv')),
        };
    }

    const nearestPkg = findNearest(startDir, rootAbs, ['package.json']);
    const pkg = nearestPkg ? readJson(nearestPkg.file) : null;

    const hasBunLock = exists(
        path.join(rootAbs, 'bun.lockb'),
        path.join(rootAbs, 'bun.lock'),
        path.join(rootAbs, 'bunfig.toml'),
    );

    let runtime: ProjectRuntime = 'node';
    const nearestLock = findNearest(startDir, rootAbs, [
        'bun.lockb', 'bun.lock', 'bunfig.toml',
        'deno.json', 'deno.jsonc',
        'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
    ]);

    if (pkg?.packageManager && String(pkg.packageManager).toLowerCase().startsWith('bun')) {
        runtime = 'bun';
    } else if (pkg?.engines?.bun) {
        runtime = 'bun';
    } else if (hasBunLock) {
        runtime = 'bun';
    } else if (pkg?.packageManager && String(pkg.packageManager).toLowerCase().startsWith('deno')) {
        runtime = 'deno';
    } else if (exists(path.join(rootAbs, 'deno.json'), path.join(rootAbs, 'deno.jsonc'))) {
        runtime = 'deno';
    } else if (nearestLock?.file.endsWith('deno.json') || nearestLock?.file.endsWith('deno.jsonc')) {
        runtime = 'deno';
    } else {
        runtime = 'node';
    }

    const packageManager = detectPackageManager(pkg, nearestLock);
    const { framework, version, tier } = detectJsFramework(pkg);
    const runner = resolveJsRunner(runtime, packageManager);

    const canRun = tier !== 4;
    const depsInstalled = (() => {
        const searchDirs = [startDir, rootAbs];
        for (const d of searchDirs) {
            if (exists(path.join(d, 'node_modules'))) return true;
        }
        if (nearestPkg) {
            if (exists(path.join(nearestPkg.dir, 'node_modules'))) return true;
        }
        return false;
    })();
    return {
        runtime,
        runner,
        suggestedRunner: runner,
        packageManager,
        framework,
        frameworkVersion: version,
        testabilityTier: tier,
        canRunLocally: canRun,
        skipReason: tier === 4 ? TIER_SKIP_REASONS[4] : undefined,
        hasBunLock,
        depsInstalled,
    };
}

const EXTENSION_SAFE_RUNNERS = new Set(['node', 'deno', 'tsx', 'pnpm-tsx', 'yarn-tsx', 'bun']);

export function computeRelativeImportPath(testFileDir: string, targetFilePath: string, runner?: string): string {
    const rel = path.relative(testFileDir, targetFilePath);
    const normalized = rel.replace(/\\/g, '/');

    if (/\.p(yi?|yx)$/i.test(targetFilePath)) {
        const fromRoot = path.relative(path.dirname(testFileDir), targetFilePath).replace(/\\/g, '/');
        return fromRoot.startsWith('.') ? fromRoot : `./${fromRoot}`;
    }

    const keepExt = runner === undefined || EXTENSION_SAFE_RUNNERS.has(runner);
    const spec = keepExt ? normalized : normalized.replace(/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/, '');
    return spec.startsWith('.') ? spec : `./${spec}`;
}
