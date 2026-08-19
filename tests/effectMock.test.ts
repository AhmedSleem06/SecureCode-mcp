import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { createEffectMock } from '../src/utils/effectMock';

describe('createEffectMock', () => {
    let workspaceRoot: string;

    afterEach(() => {
        if (workspaceRoot) {
            try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
        }
    });

    it('creates node_modules/effect/ directory with package.json and index.js', () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-effect-mock-'));
        createEffectMock(workspaceRoot);

        const effectDir = path.join(workspaceRoot, 'node_modules', 'effect');
        expect(fs.existsSync(effectDir)).toBe(true);
        expect(fs.existsSync(path.join(effectDir, 'package.json'))).toBe(true);
        expect(fs.existsSync(path.join(effectDir, 'index.js'))).toBe(true);
    });

    it('writes a valid package.json with mock version', () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-effect-mock-'));
        createEffectMock(workspaceRoot);

        const pkgPath = path.join(workspaceRoot, 'node_modules', 'effect', 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        expect(pkg.name).toBe('effect');
        expect(pkg.version).toBe('0.0.0-mock');
        expect(pkg.main).toBe('index.js');
    });

    it('writes index.js that exports Effect, Layer, Context, and other modules', () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-effect-mock-'));
        createEffectMock(workspaceRoot);

        const indexPath = path.join(workspaceRoot, 'node_modules', 'effect', 'index.js');
        const content = fs.readFileSync(indexPath, 'utf8');
        expect(content).toContain('Effect');
        expect(content).toContain('Layer');
        expect(content).toContain('Context');
        expect(content).toContain('Schema');
        expect(content).toContain('export');
    });

    it('is idempotent — can be called twice without error', () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-effect-mock-'));
        createEffectMock(workspaceRoot);
        expect(() => createEffectMock(workspaceRoot)).not.toThrow();
    });

    it('the mock index.js contains runnable Effect primitives', () => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-effect-mock-'));
        createEffectMock(workspaceRoot);

        const indexPath = path.join(workspaceRoot, 'node_modules', 'effect', 'index.js');
        const content = fs.readFileSync(indexPath, 'utf8');
        // The mock should define Effect.runSync, Effect.sync, Effect.succeed
        expect(content).toContain('runSync');
        expect(content).toContain('sync');
        expect(content).toContain('succeed');
    });
});
