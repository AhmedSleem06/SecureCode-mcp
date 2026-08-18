import { describe, it, expect } from 'vitest';
import { checkTestSafety } from '../src/utils/testSafety';

describe('checkTestSafety', () => {
    it('allows relative imports', () => {
        const script = `import { foo } from "./foo"; import { bar } from "../lib/bar";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('allows node: built-in imports', () => {
        const script = `import { readFileSync } from "node:fs";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('allows effect import', () => {
        const script = `import { Effect } from "effect";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });

    it('allows bun imports', () => {
        const script = `import { describe, it } from "bun:test";`;
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

    it('allows workspace-scoped packages', () => {
        const script = `import { something } from "@synara/shared";`;
        const result = checkTestSafety(script, '/workspace');
        expect(result.allowed).toBe(true);
    });
});
