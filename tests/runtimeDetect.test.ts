import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { detectRuntime, computeRelativeImportPath } from '../src/utils/runtimeDetect';

function mkdtempRoot(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'runtimedetect-'));
}

function write(root: string, rel: string, content: string): void {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content, 'utf8');
}

describe('detectRuntime — JS/TS', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('defaults to node + tsx when nothing is present', () => {
        const info = detectRuntime(root);
        expect(info.runtime).toBe('node');
        expect(info.runner).toBe('tsx');
        expect(info.framework).toBeNull();
        expect(info.testabilityTier).toBe(1);
        expect(info.canRunLocally).toBe(true);
    });

    it('detects bun from bun.lock', () => {
        write(root, 'bun.lock', '');
        const info = detectRuntime(root);
        expect(info.hasBunLock).toBe(true);
        expect(info.runtime).toBe('bun');
    });

    it('detects deno from deno.json', () => {
        write(root, 'deno.json', '{}');
        const info = detectRuntime(root);
        expect(info.runtime).toBe('deno');
    });

    it('detects pnpm from pnpm-lock.yaml', () => {
        write(root, 'pnpm-lock.yaml', '');
        write(root, 'package.json', JSON.stringify({ name: 'x' }));
        const info = detectRuntime(root);
        expect(info.packageManager).toBe('pnpm');
    });

    it('detects yarn from yarn.lock', () => {
        write(root, 'yarn.lock', '');
        write(root, 'package.json', JSON.stringify({ name: 'x' }));
        const info = detectRuntime(root);
        expect(info.packageManager).toBe('yarn');
    });

    it('detects npm from package-lock.json', () => {
        write(root, 'package-lock.json', '');
        write(root, 'package.json', JSON.stringify({ name: 'x' }));
        const info = detectRuntime(root);
        expect(info.packageManager).toBe('npm');
    });

    it('reads packageManager field over lockfiles', () => {
        write(root, 'package-lock.json', '');
        write(root, 'package.json', JSON.stringify({ packageManager: 'pnpm@9.0.0' }));
        const info = detectRuntime(root);
        expect(info.packageManager).toBe('pnpm');
    });

    it('detects next framework + tier 2', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { next: '14.2.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('next');
        expect(info.frameworkVersion).toBe('14.2.0');
        expect(info.testabilityTier).toBe(2);
        expect(info.canRunLocally).toBe(true);
    });

    it('detects electron framework + tier 2', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { electron: '30.0.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('electron');
        expect(info.testabilityTier).toBe(2);
    });

    it('detects react-native + tier 4 (cannot run locally)', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { 'react-native': '0.74.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('react-native');
        expect(info.testabilityTier).toBe(4);
        expect(info.canRunLocally).toBe(false);
        expect(info.skipReason).toBeDefined();
    });

    it('detects cloudflare workers + tier 4', () => {
        write(root, 'package.json', JSON.stringify({ devDependencies: { wrangler: '3.0.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('cloudflare-workers');
        expect(info.canRunLocally).toBe(false);
    });

    it('detects express + tier 1', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { express: '4.18.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('express');
        expect(info.testabilityTier).toBe(1);
    });

    it('prioritizes next over react (meta-framework wins)', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { next: '14.0.0', react: '18.0.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('next');
        expect(info.testabilityTier).toBe(2);
    });

    it('react without meta-framework → tier 3 (needs DOM)', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { react: '18.0.0' } }));
        const info = detectRuntime(root);
        expect(info.framework).toBe('react');
        expect(info.testabilityTier).toBe(3);
        expect(info.canRunLocally).toBe(true);
    });
});

describe('detectRuntime — monorepo', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('finds nearest lockfile from target file dir', () => {
        write(root, 'package.json', JSON.stringify({ name: 'root', packageManager: 'npm' }));
        write(root, 'apps/web/package.json', JSON.stringify({ name: 'web' }));
        write(root, 'apps/web/pnpm-lock.yaml', '');
        const info = detectRuntime(root, 'apps/web/src/handler.ts');
        expect(info.packageManager).toBe('pnpm');
    });

    it('walks up to root when nested dir has no lockfile', () => {
        write(root, 'yarn.lock', '');
        write(root, 'package.json', JSON.stringify({ name: 'root' }));
        write(root, 'apps/web/src/handler.ts', 'export const x = 1;');
        const info = detectRuntime(root, 'apps/web/src/handler.ts');
        expect(info.packageManager).toBe('yarn');
    });
});

describe('detectRuntime — Python', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('detects python runtime from .py filePath', () => {
        write(root, 'app.py', 'print("hi")');
        const info = detectRuntime(root, 'app.py');
        expect(info.runtime).toBe('python');
        expect(['python3', 'python']).toContain(info.runner);
    });

    it('detects flask framework from requirements.txt', () => {
        write(root, 'requirements.txt', 'flask==3.0.0\n');
        const info = detectRuntime(root, 'app.py');
        expect(info.framework).toBe('flask');
        expect(info.frameworkVersion).toBe('3.0.0');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects fastapi framework', () => {
        write(root, 'requirements.txt', 'fastapi==0.110.0\n');
        const info = detectRuntime(root, 'app/main.py');
        expect(info.framework).toBe('fastapi');
    });

    it('detects django framework', () => {
        write(root, 'requirements.txt', 'django>=5.0\n');
        const info = detectRuntime(root, 'manage.py');
        expect(info.framework).toBe('django');
    });

    it('python with no framework → tier 1, runnable', () => {
        write(root, 'app.py', 'print("hi")');
        const info = detectRuntime(root, 'app.py');
        expect(info.framework).toBeNull();
        expect(info.testabilityTier).toBe(1);
    });
});

describe('computeRelativeImportPath', () => {
    it('returns ../-prefixed path for JS/TS', () => {
        const p = computeRelativeImportPath('/ws/.securecode', '/ws/src/lib/auth.ts');
        expect(p).toBe('../src/lib/auth');
    });

    it('strips extension for JS/TS', () => {
        const p = computeRelativeImportPath('/ws/.securecode', '/ws/src/foo.js');
        expect(p).toBe('../src/foo');
    });

    it('returns workspace-relative path for Python', () => {
        const p = computeRelativeImportPath('/ws/.securecode', '/ws/src/app/handler.py');
        expect(p).toBe('./src/app/handler.py');
    });
});
