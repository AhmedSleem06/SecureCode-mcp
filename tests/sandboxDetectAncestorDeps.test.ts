import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawnSync } from 'child_process';
import { LocalSandbox, _resetPermissionCacheForTests } from '../src/utils/localSandbox';
import {
    discoverAncestorNodeModules,
    buildDockerMountsForDeps,
    bundleScript,
    _resetSandboxCacheForTests,
} from '../src/utils/verificationSandbox';

const REPO_ROOT = path.resolve(__dirname, '../..');
const FIXTURE_ROOT = path.join(REPO_ROOT, 'test_lab', 'assurance-fixtures');
const FIXTURE_WORKSPACE = path.join(FIXTURE_ROOT, '03-role-escalation-update', 'flawed');
const PARENT_NODE_MODULES = path.join(FIXTURE_ROOT, 'node_modules');

const POLLUTION_DIRS = [
    path.join(os.tmpdir(), 'node_modules'),
    path.resolve(os.tmpdir(), '..', 'node_modules'),
    path.resolve(os.tmpdir(), '..', '..', 'node_modules'),
];

function assertNoPollution(): void {
    for (const d of POLLUTION_DIRS) {
        expect(fs.existsSync(d), `pollution found at ${d}`).toBe(false);
    }
}

function assertFixtureIntact(): void {
    expect(fs.existsSync(path.join(PARENT_NODE_MODULES, 'express', 'package.json'))).toBe(true);
    expect(fs.existsSync(path.join(PARENT_NODE_MODULES, 'jsonwebtoken', 'package.json'))).toBe(true);
}

function dockerAvailable(): boolean {
    try {
        return spawnSync('docker', ['info'], { stdio: 'ignore', timeout: 5000 }).status === 0;
    } catch { return false; }
}

const HAS_DOCKER = dockerAvailable();
const describeDocker = HAS_DOCKER ? describe : describe.skip;

describe('discoverAncestorNodeModules', () => {
    it('finds the parent node_modules from the fixture workspace', () => {
        const result = discoverAncestorNodeModules(FIXTURE_WORKSPACE);
        const normalizedDirs = result.dirs.map(d => path.resolve(d));
        expect(normalizedDirs).toContain(path.resolve(PARENT_NODE_MODULES));
    });

    it('stops at git root (does not find mcp/node_modules)', () => {
        const result = discoverAncestorNodeModules(FIXTURE_WORKSPACE);
        for (const d of result.dirs) {
            const dirName = path.basename(path.dirname(d));
            expect(dirName).not.toBe('mcp');
        }
    });

    it('workspace with its own node_modules includes it', () => {
        const result = discoverAncestorNodeModules(FIXTURE_WORKSPACE);
        const wsNm = path.join(FIXTURE_WORKSPACE, 'node_modules');
        if (fs.existsSync(wsNm)) {
            expect(result.dirs.map(d => path.resolve(d))).toContain(path.resolve(wsNm));
        }
    });
});

describe('buildDockerMountsForDeps', () => {
    it('generates mirrored mount layout for ancestor node_modules', () => {
        const ancestors = discoverAncestorNodeModules(FIXTURE_WORKSPACE);
        const depInfo = buildDockerMountsForDeps(FIXTURE_WORKSPACE, ancestors.dirs);
        expect(depInfo.mounts.length).toBeGreaterThan(2);
        expect(depInfo.workdir).toContain('/w/');
        const testPath = depInfo.toContainerPath(path.join(FIXTURE_WORKSPACE, '.securecode', 'test.mjs'));
        expect(testPath).toContain('.securecode/test.mjs');
        expect(testPath.startsWith(depInfo.workdir)).toBe(true);
    });

    it('uses /workspace for no-ancestor case', () => {
        const depInfo = buildDockerMountsForDeps(FIXTURE_WORKSPACE, [
            path.join(FIXTURE_WORKSPACE, 'node_modules'),
        ]);
        expect(depInfo.workdir).toBe('/workspace');
    });
});

describe('bundleScript — require shim on CJS target (Task 2)', () => {
    it('adds require banner when bundled output references require from CJS target', () => {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-test-'));
        const testScript = path.join(tmpDir, 'test.ts');
        const usersPath = path.resolve(FIXTURE_WORKSPACE, 'src', 'users.ts').replace(/\\/g, '/');
        fs.writeFileSync(testScript, `
import { app } from "${usersPath}";
console.log("PASS: loaded", typeof app);
`);
        try {
            const result = bundleScript(testScript, FIXTURE_WORKSPACE, tmpDir);
            if (!result.ok) expect.fail(`Bundle failed: ${result.error}`);
            expect(result.code).toBeDefined();
            expect(result.code).toContain('createRequire');
        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    it('does not duplicate require banner when test script already declares require', () => {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-test-'));
        const testScript = path.join(tmpDir, 'test.ts');
        fs.writeFileSync(testScript, `
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const jwt = require("jsonwebtoken");
console.log("PASS: jwt loaded", typeof jwt.sign);
`);
        try {
            const result = bundleScript(testScript, FIXTURE_WORKSPACE, tmpDir);
            expect(result.ok).toBe(true);
            const code = result.code || '';
            const bannerDecls = (code.match(/const require\s*=\s*__scCR/g) || []).length;
            const userDecls = (code.match(/const require\s*=\s*createRequire/g) || []).length;
            expect(bannerDecls + userDecls).toBeLessThanOrEqual(2);
        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    it('pure-ESM test importing pure-ESM module does not get require banner', () => {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bundle-test-'));
        const helperFile = path.join(tmpDir, 'helper.mjs');
        fs.writeFileSync(helperFile, 'export function greet(n) { return "Hi " + n; }');
        const testScript = path.join(tmpDir, 'test.ts');
        fs.writeFileSync(testScript, `
import { greet } from "./helper.mjs";
console.log("PASS:", greet("world"));
`);
        try {
            const result = bundleScript(testScript, tmpDir, tmpDir);
            expect(result.ok).toBe(true);
            expect(result.code).not.toContain('__scCR');
        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });
});

describe('LocalSandbox — ancestor deps (Task 1)', () => {
    const backend = new LocalSandbox();

    beforeAll(() => { _resetPermissionCacheForTests(); });

    it('resolves jsonwebtoken from parent node_modules via mirrored layout', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: `
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
try {
    const jwt = require("jsonwebtoken");
    if (typeof jwt.sign === 'function') {
        console.log("PASS: jsonwebtoken resolved from ancestor node_modules");
    } else {
        console.log("FAIL: jwt.sign not a function");
    }
} catch(e) {
    console.log("FAIL: " + e.message);
}
`,
            runner: 'node',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 15_000,
        });
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('jsonwebtoken resolved');
        assertNoPollution();
        assertFixtureIntact();
    });

    it('resolves express from parent node_modules', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: `
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
try {
    const express = require("express");
    if (typeof express === 'function') {
        console.log("PASS: express resolved from ancestor node_modules");
    } else {
        console.log("FAIL: express not a function");
    }
} catch(e) {
    console.log("FAIL: " + e.message);
}
`,
            runner: 'node',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 15_000,
        });
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('express resolved');
        assertNoPollution();
        assertFixtureIntact();
    });

    it('reports isolation as local/reduced when permission model is skipped', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: 'console.log("PASS: isolation check");',
            runner: 'node',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 15_000,
        });
        expect(result.backend).toMatch(/^local/);
    });
});

describe('LocalSandbox — bundled CJS target require (Task 2)', () => {
    const backend = new LocalSandbox();

    it('bundled test importing CJS target that calls require("express") works', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: `
import { app } from "../src/users.ts";
if (typeof app === 'object' || typeof app === 'function') {
    console.log("PASS: CJS target loaded via bundled ESM, express resolved");
} else {
    console.log("FAIL: unexpected type " + typeof app);
}
`,
            runner: 'tsx',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 30_000,
        });
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('CJS target loaded');
        assertNoPollution();
        assertFixtureIntact();
    }, 60_000);
});

describe('LocalSandbox — ESM bare import from ancestor (Task 1b)', () => {
    const backend = new LocalSandbox();

    it('ESM import jwt from "jsonwebtoken" resolves through mirrored junction', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: `
import jwt from "jsonwebtoken";
if (typeof jwt.sign === 'function') {
    console.log("PASS: ESM bare import of jsonwebtoken works");
} else {
    console.log("FAIL: jwt.sign not a function");
}
`,
            runner: 'node',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 15_000,
        });
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('ESM bare import');
        assertNoPollution();
        assertFixtureIntact();
    });
});

describeDocker('Docker — ancestor deps mirrored mount (Task 1)', () => {
    let backend: any;

    beforeAll(async () => {
        _resetSandboxCacheForTests();
        process.env.SECURECODE_SANDBOX = 'docker';
        const { detectSandbox } = await import('../src/utils/verificationSandbox');
        _resetSandboxCacheForTests();
        backend = detectSandbox();
    });

    it('CJS require("jsonwebtoken") resolves in Docker via mirrored mount', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: `
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
try {
    const jwt = require("jsonwebtoken");
    if (typeof jwt.sign === 'function') {
        console.log("PASS: CJS jsonwebtoken resolved in Docker");
    } else {
        console.log("FAIL: jwt.sign not a function");
    }
} catch(e) {
    console.log("FAIL: " + e.message);
}
`,
            runner: 'node',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 90_000,
        });
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('CJS jsonwebtoken resolved');
        assertFixtureIntact();
    }, 120_000);

    it('ESM import jwt from "jsonwebtoken" resolves in Docker via mirrored mount', async () => {
        const result = await backend.execute({
            mode: 'script',
            script: `
import jwt from "jsonwebtoken";
if (typeof jwt.sign === 'function') {
    console.log("PASS: ESM jsonwebtoken resolved in Docker");
} else {
    console.log("FAIL: jwt.sign not a function");
}
`,
            runner: 'node',
            workspaceRoot: FIXTURE_WORKSPACE,
            timeoutMs: 90_000,
        });
        expect(result.verdict).toBe('pass');
        expect(result.output).toContain('ESM jsonwebtoken resolved');
        assertFixtureIntact();
    }, 120_000);
});
