import { describe, it, expect, afterEach } from 'vitest';
import { parseVerdictCommandMode, pickImageForCommand } from '../src/utils/verificationSandbox';

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
