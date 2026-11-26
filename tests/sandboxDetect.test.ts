import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
    probeDocker,
    _resetDockerCacheForTests,
    _resetSandboxCacheForTests,
    detectSandbox,
    bundleScript,
} from '../src/utils/verificationSandbox';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('probeDocker (Windows)', () => {
    beforeEach(() => {
        _resetDockerCacheForTests();
    });

    it('returns a boolean', () => {
        const result = probeDocker();
        expect(typeof result).toBe('boolean');
    });

    it('caches a positive result for the process lifetime', () => {
        const first = probeDocker();
        if (!first) return;
        const second = probeDocker();
        expect(second).toBe(true);
    });

    it('caches a negative result with TTL', () => {
        _resetDockerCacheForTests();
        const result = probeDocker();
        expect(typeof result).toBe('boolean');
    });
});

describe('detectSandbox — SECURECODE_SANDBOX override', () => {
    const origEnv = process.env.SECURECODE_SANDBOX;

    beforeEach(() => {
        _resetSandboxCacheForTests();
        _resetDockerCacheForTests();
        delete process.env.SECURECODE_SANDBOX;
    });

    afterEach(() => {
        if (origEnv !== undefined) process.env.SECURECODE_SANDBOX = origEnv;
        else delete process.env.SECURECODE_SANDBOX;
        _resetSandboxCacheForTests();
    });

    it('returns null when override is "none"', () => {
        process.env.SECURECODE_SANDBOX = 'none';
        const backend = detectSandbox();
        expect(backend).toBeNull();
    });

    it('returns local backend when override is "local"', () => {
        process.env.SECURECODE_SANDBOX = 'local';
        const backend = detectSandbox();
        expect(backend).not.toBeNull();
        expect(backend!.name).toBe('local');
    });

    it('respects override change between calls', () => {
        process.env.SECURECODE_SANDBOX = 'none';
        expect(detectSandbox()).toBeNull();
        process.env.SECURECODE_SANDBOX = 'local';
        _resetSandboxCacheForTests();
        expect(detectSandbox()?.name).toBe('local');
    });
});

describe('bundleScript', () => {
    it('bundles a simple TS file into ESM .mjs with inline sourcemap', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundle-'));
        try {
            fs.writeFileSync(path.join(ws, 'test.ts'), 'const x: number = 42;\nconsole.log("PASS: " + x);');
            const result = bundleScript(path.join(ws, 'test.ts'), ws);
            expect(result.ok).toBe(true);
            expect(result.outPath).toMatch(/\.mjs$/);
            expect(result.code).toContain('PASS:');
            expect(result.code).toContain('sourceMappingURL=data:application/json;base64,');
            fs.unlinkSync(result.outPath!);
        } finally { fs.rmSync(ws, { recursive: true, force: true }); }
    });

    it('bundles a TS file that imports another TS file (inlined)', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundle-'));
        try {
            fs.mkdirSync(path.join(ws, 'src'));
            fs.writeFileSync(path.join(ws, 'src', 'lib.ts'), 'export function greet(n: string): string { return "Hello " + n; }');
            fs.mkdirSync(path.join(ws, '.securecode'));
            fs.writeFileSync(path.join(ws, '.securecode', 'test.ts'), 'import { greet } from "../src/lib";\nconsole.log("PASS: " + greet("world"));');
            const result = bundleScript(path.join(ws, '.securecode', 'test.ts'), ws);
            expect(result.ok).toBe(true);
            expect(result.code).toContain('Hello');
            expect(result.code).toContain('PASS:');
            fs.unlinkSync(result.outPath!);
        } finally { fs.rmSync(ws, { recursive: true, force: true }); }
    });

    it('keeps node_modules external', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundle-'));
        try {
            fs.writeFileSync(path.join(ws, 'test.ts'), 'import * as path from "path";\nconsole.log("PASS: " + path.sep);');
            const result = bundleScript(path.join(ws, 'test.ts'), ws);
            expect(result.ok).toBe(true);
            expect(result.code).not.toContain('node:path');
            fs.unlinkSync(result.outPath!);
        } finally { fs.rmSync(ws, { recursive: true, force: true }); }
    });

    it('adds require shim banner when script uses require()', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundle-'));
        try {
            fs.writeFileSync(path.join(ws, 'test.ts'), 'const x = require("path");\nconsole.log("PASS: " + x.sep);');
            const result = bundleScript(path.join(ws, 'test.ts'), ws);
            expect(result.ok).toBe(true);
            expect(result.code).toContain('createRequire');
            fs.unlinkSync(result.outPath!);
        } finally { fs.rmSync(ws, { recursive: true, force: true }); }
    });

    it('supports top-level await', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundle-'));
        try {
            fs.writeFileSync(path.join(ws, 'test.ts'), 'const x: number = await Promise.resolve(42);\nconsole.log("PASS: " + x);');
            const result = bundleScript(path.join(ws, 'test.ts'), ws);
            expect(result.ok).toBe(true);
            expect(result.code).toContain('await');
            fs.unlinkSync(result.outPath!);
        } finally { fs.rmSync(ws, { recursive: true, force: true }); }
    });

    it('returns error for syntax errors', () => {
        const ws = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-bundle-'));
        try {
            fs.writeFileSync(path.join(ws, 'bad.ts'), 'const x: number = {{{');
            const result = bundleScript(path.join(ws, 'bad.ts'), ws);
            expect(result.ok).toBe(false);
            expect(result.error).toBeTruthy();
        } finally { fs.rmSync(ws, { recursive: true, force: true }); }
    });
});
