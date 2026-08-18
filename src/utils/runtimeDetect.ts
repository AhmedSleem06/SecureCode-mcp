import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';

export type ProjectRuntime = 'bun' | 'node' | 'deno' | 'python';
export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun' | 'pip' | 'poetry' | 'uv' | null;
export type Framework =
    | 'electron' | 'next' | 'remix' | 'nuxt'
    | 'react-native'
    | 'express' | 'fastify' | 'nestjs' | 'koa' | 'hapi'
    | 'flask' | 'fastapi' | 'django'
    | 'react' | 'vue' | 'svelte'
    | 'cloudflare-workers'
    | null;
export type TestabilityTier = 1 | 2 | 3 | 4;

export interface RuntimeInfo {
    runtime: ProjectRuntime;
    runner: string;
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

export function detectRuntime(workspaceRoot: string, filePath?: string): RuntimeInfo {
    const rootAbs = path.resolve(workspaceRoot);
    const isPythonFile = filePath ? /\.p(yi?|yx)$/i.test(filePath) : false;

    if (isPythonFile) {
        const startDir = filePath
            ? path.resolve(rootAbs, path.dirname(filePath))
            : rootAbs;
        const py = resolvePythonRunner();
        const { framework, version, tier } = detectPyFramework(startDir, rootAbs);
        const pkgMan = (() => {
            if (exists(path.join(startDir, 'poetry.lock'))) return 'poetry';
            if (exists(path.join(startDir, 'uv.lock'))) return 'uv';
            if (exists(path.join(startDir, 'Pipfile'))) return 'pip';
            if (exists(path.join(startDir, 'requirements.txt'), path.join(startDir, 'pyproject.toml'))) return 'pip';
            return null;
        })();
        const canRun = py.installed && tier !== 4;
        return {
            runtime: 'python',
            runner: py.runner,
            packageManager: pkgMan,
            framework,
            frameworkVersion: version,
            testabilityTier: tier,
            canRunLocally: canRun,
            skipReason: !py.installed
                ? 'Python interpreter not found in PATH. Install python3 to run local exploit tests.'
                : tier === 4 ? TIER_SKIP_REASONS[4] : undefined,
            hasBunLock: false,
            depsInstalled: exists(path.join(startDir, '__pycache__')) || exists(path.join(startDir, '.venv'), path.join(startDir, 'venv')),
        };
    }

    const startDir = filePath
        ? path.resolve(rootAbs, path.dirname(filePath))
        : rootAbs;
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

export function computeRelativeImportPath(testFileDir: string, targetFilePath: string): string {
    const rel = path.relative(testFileDir, targetFilePath);
    const normalized = rel.replace(/\\/g, '/');

    if (/\.p(yi?|yx)$/i.test(targetFilePath)) {
        const fromRoot = path.relative(path.dirname(testFileDir), targetFilePath).replace(/\\/g, '/');
        return fromRoot.startsWith('.') ? fromRoot : `./${fromRoot}`;
    }

    const withoutExt = normalized.replace(/\.(ts|tsx|js|jsx|mjs|cjs)$/, '');
    return withoutExt.startsWith('.') ? withoutExt : `./${withoutExt}`;
}
