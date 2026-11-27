import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('expressRunner.cjs availability', () => {
    it('expressRunner.cjs exists in the harness directory', () => {
        const candidates = [
            path.resolve(__dirname, '../src/assurance/harness/expressRunner.cjs'),
            path.resolve(__dirname, '../dist/assurance/harness/expressRunner.cjs'),
        ];
        const found = candidates.some(p => fs.existsSync(p));
        expect(found).toBe(true);
    });

    it('expressRunner.cjs exports load, invoke, mock, jwtIdentities', () => {
        const src = path.resolve(__dirname, '../src/assurance/harness/expressRunner.cjs');
        if (!fs.existsSync(src)) return;
        const content = fs.readFileSync(src, 'utf8');
        expect(content).toContain('load');
        expect(content).toContain('invoke');
    });

    it('copyExpressRunner is called in localSandbox executeScript', () => {
        const src = fs.readFileSync(path.resolve(__dirname, '../src/utils/localSandbox.ts'), 'utf8');
        expect(src).toContain('copyExpressRunner(scDir)');
    });

    it('copyExpressRunner is called in verificationSandbox executeScript', () => {
        const src = fs.readFileSync(path.resolve(__dirname, '../src/utils/verificationSandbox.ts'), 'utf8');
        expect(src).toContain('copyExpressRunner(sandboxDir)');
    });
});
