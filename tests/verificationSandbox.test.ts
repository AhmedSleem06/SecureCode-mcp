import { describe, it, expect, afterEach } from 'vitest';
import { parseVerdictCommandMode, pickImageForCommand, pickImageForRunner, runnerInvocation } from '../src/utils/verificationSandbox';

describe('parseVerdictCommandMode', () => {
    it('returns pass for exit code 0', () => {
        expect(parseVerdictCommandMode(0, false)).toBe('pass');
    });

    it('returns fail for nonzero exit code', () => {
        expect(parseVerdictCommandMode(1, false)).toBe('fail');
        expect(parseVerdictCommandMode(127, false)).toBe('fail');
        expect(parseVerdictCommandMode(-1, false)).toBe('fail');
    });

    it('returns timeout when timed out regardless of exit code', () => {
        expect(parseVerdictCommandMode(0, true)).toBe('timeout');
        expect(parseVerdictCommandMode(1, true)).toBe('timeout');
        expect(parseVerdictCommandMode(-1, true)).toBe('timeout');
    });
});

describe('pickImageForCommand', () => {
    const origEnv = { ...process.env };

    afterEach(() => {
        // Restore env
        for (const k of Object.keys(process.env)) {
            if (!(k in origEnv)) delete process.env[k];
        }
        for (const [k, v] of Object.entries(origEnv)) {
            process.env[k] = v;
        }
    });

    it('returns node:20-alpine for npm', () => {
        delete process.env.SECURECODE_SANDBOX_IMAGE;
        const result = pickImageForCommand('npm');
        expect(result.image).toBe('node:20-alpine');
    });

    it('returns custom image when SECURECODE_SANDBOX_IMAGE is set', () => {
        process.env.SECURECODE_SANDBOX_IMAGE = 'my-custom-node:latest';
        const result = pickImageForCommand('npm');
        expect(result.image).toBe('my-custom-node:latest');
    });

    it('returns python:3.11-slim for pytest', () => {
        delete process.env.SECURECODE_SANDBOX_PY_IMAGE;
        const result = pickImageForCommand('pytest');
        expect(result.image).toBe('python:3.11-slim');
    });

    it('returns null for pnpm without env var', () => {
        delete process.env.SECURECODE_SANDBOX_PNPM_IMAGE;
        const result = pickImageForCommand('pnpm');
        expect(result.image).toBeNull();
        expect(result.reason).toContain('pnpm');
    });

    it('returns image for pnpm with env var', () => {
        process.env.SECURECODE_SANDBOX_PNPM_IMAGE = 'pnpm:latest';
        const result = pickImageForCommand('pnpm');
        expect(result.image).toBe('pnpm:latest');
    });

    it('returns null for yarn without env var', () => {
        delete process.env.SECURECODE_SANDBOX_YARN_IMAGE;
        const result = pickImageForCommand('yarn');
        expect(result.image).toBeNull();
        expect(result.reason).toContain('yarn');
    });

    it('returns null for bun without env var', () => {
        delete process.env.SECURECODE_SANDBOX_BUN_IMAGE;
        const result = pickImageForCommand('bun');
        expect(result.image).toBeNull();
        expect(result.reason).toContain('bun');
    });

    it('returns null for unknown executable', () => {
        const result = pickImageForCommand('cargo');
        expect(result.image).toBeNull();
        expect(result.reason).toContain('No sandbox image');
    });

    it('returns image for npx', () => {
        delete process.env.SECURECODE_SANDBOX_IMAGE;
        const result = pickImageForCommand('npx');
        expect(result.image).toBe('node:20-alpine');
    });
});

// ── pickImageForRunner (Fix 2: Docker script-mode runner dispatch) ──────────

describe('pickImageForRunner', () => {
    const origEnv = { ...process.env };

    afterEach(() => {
        for (const k of Object.keys(process.env)) {
            if (!(k in origEnv)) delete process.env[k];
        }
        for (const [k, v] of Object.entries(origEnv)) {
            process.env[k] = v;
        }
    });

    it('returns node:20-alpine for node runner', () => {
        delete process.env.SECURECODE_SANDBOX_IMAGE;
        expect(pickImageForRunner('node').image).toBe('node:20-alpine');
    });

    it('returns node:20-alpine for tsx runner', () => {
        delete process.env.SECURECODE_SANDBOX_IMAGE;
        expect(pickImageForRunner('tsx').image).toBe('node:20-alpine');
    });

    it('returns python:3.11-slim for python runner', () => {
        delete process.env.SECURECODE_SANDBOX_PY_IMAGE;
        expect(pickImageForRunner('python').image).toBe('python:3.11-slim');
    });

    it('returns python:3.11-slim for python3 runner', () => {
        delete process.env.SECURECODE_SANDBOX_PY_IMAGE;
        expect(pickImageForRunner('python3').image).toBe('python:3.11-slim');
    });

    it('returns null for deno without env var', () => {
        delete process.env.SECURECODE_SANDBOX_DENO_IMAGE;
        const r = pickImageForRunner('deno');
        expect(r.image).toBeNull();
        expect(r.reason).toContain('deno');
    });

    it('returns image for deno with env var', () => {
        process.env.SECURECODE_SANDBOX_DENO_IMAGE = 'denoland/deno:latest';
        expect(pickImageForRunner('deno').image).toBe('denoland/deno:latest');
    });

    it('returns null for bun without env var', () => {
        delete process.env.SECURECODE_SANDBOX_BUN_IMAGE;
        const r = pickImageForRunner('bun');
        expect(r.image).toBeNull();
        expect(r.reason).toContain('bun');
    });

    it('returns image for bun with env var', () => {
        process.env.SECURECODE_SANDBOX_BUN_IMAGE = 'oven/bun:latest';
        expect(pickImageForRunner('bun').image).toBe('oven/bun:latest');
    });

    it('returns null for unknown runner', () => {
        const r = pickImageForRunner('ruby');
        expect(r.image).toBeNull();
        expect(r.reason).toContain('No sandbox image');
    });
});

// ── runnerInvocation (Fix 2 + Fix 3: correct runner + setup chaining) ──────

describe('runnerInvocation', () => {
    it('invokes node directly', () => {
        expect(runnerInvocation('node', '/workspace/.securecode/test.test.ts'))
            .toBe('node "/workspace/.securecode/test.test.ts"');
    });

    it('invokes tsx via npx --no-install', () => {
        expect(runnerInvocation('tsx', '/workspace/.securecode/test.test.ts'))
            .toBe('npx --no-install tsx "/workspace/.securecode/test.test.ts"');
    });

    it('invokes bun via bun run', () => {
        expect(runnerInvocation('bun', '/workspace/.securecode/test.test.ts'))
            .toBe('bun run "/workspace/.securecode/test.test.ts"');
    });

    it('invokes python directly', () => {
        expect(runnerInvocation('python', '/workspace/.securecode/test.py'))
            .toBe('python "/workspace/.securecode/test.py"');
    });

    it('invokes python3 directly', () => {
        expect(runnerInvocation('python3', '/workspace/.securecode/test.py'))
            .toBe('python "/workspace/.securecode/test.py"');
    });

    it('invokes deno with allow-read and no-prompt', () => {
        const cmd = runnerInvocation('deno', '/workspace/.securecode/test.ts');
        expect(cmd).toContain('deno run');
        expect(cmd).toContain('--allow-read=/workspace');
        expect(cmd).toContain('--no-prompt');
    });

    it('invokes pnpm-tsx via pnpm exec', () => {
        expect(runnerInvocation('pnpm-tsx', '/workspace/.securecode/test.test.ts'))
            .toBe('pnpm exec tsx "/workspace/.securecode/test.test.ts"');
    });

    it('invokes yarn-tsx via yarn tsx', () => {
        expect(runnerInvocation('yarn-tsx', '/workspace/.securecode/test.test.ts'))
            .toBe('yarn tsx "/workspace/.securecode/test.test.ts"');
    });

    it('falls back to node for unknown runner', () => {
        expect(runnerInvocation('ruby', '/workspace/.securecode/test.rb'))
            .toBe('node "/workspace/.securecode/test.rb"');
    });
});
