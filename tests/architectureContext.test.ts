import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
    writeCachedArchitectureContext,
    getCachedArchitectureContext,
    clearArchitectureCache,
    formatArchitectureContextForPrompt,
    ARCHITECTURE_CONTEXT_VERSION,
    type ArchitectureContext,
} from '../src/project-map/architectureContext';

function makeContext(overrides?: Partial<ArchitectureContext>): ArchitectureContext {
    return {
        version: ARCHITECTURE_CONTEXT_VERSION,
        depth: 'standard',
        derivedAt: Date.now(),
        projectMapBuiltAt: 1000,
        projectMapVersion: 2,
        project: {
            type: 'TypeScript Express API',
            frameworks: ['express'],
            runtimes: ['node'],
            packageManager: 'npm',
            languages: ['typescript'],
        },
        importantFiles: [
            { file: 'src/index.ts', role: 'entrypoint', importance: 95, reasons: ['App bootstrap'] },
            { file: 'src/lib/auth.ts', role: 'authentication', importance: 90, reasons: ['JWT verification'], keySymbols: ['requireAuth'] },
        ],
        trustBoundaries: [
            { entry: 'POST /api/login', inputType: 'HTTP body', guard: null },
        ],
        dataFlows: [
            { label: 'login → JWT', path: ['src/routes/auth.ts', 'src/lib/auth.ts'], guarded: false },
        ],
        securityControls: [
            { kind: 'auth', location: 'src/lib/auth.ts', coverage: 'full' },
            { kind: 'rate_limit', location: '(none)', coverage: 'unknown', notes: 'No rate limiting' },
        ],
        architectureRisks: [
            { title: 'No rate limiting on login', description: 'Brute-force risk', files: ['src/routes/auth.ts'], severity: 'high' },
        ],
        recommendedScanOrder: ['src/routes/auth.ts', 'src/lib/auth.ts', 'src/index.ts'],
        summary: 'Express API with JWT auth.',
        completeness: 'full',
        ...overrides,
    };
}

describe('architectureContext cache', () => {
    let workspaceRoot: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'arch-ctx-'));
        fs.mkdirSync(path.join(workspaceRoot, '.securecode'), { recursive: true });
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    it('writes and reads a context with matching project map metadata', () => {
        const ctx = makeContext();
        writeCachedArchitectureContext(workspaceRoot, ctx);

        const cached = getCachedArchitectureContext(workspaceRoot, 'standard', 1000, 2);
        expect(cached).not.toBeNull();
        expect(cached!.project.type).toBe('TypeScript Express API');
        expect(cached!.importantFiles).toHaveLength(2);
    });

    it('returns null when the project map builtAt differs (stale)', () => {
        const ctx = makeContext();
        writeCachedArchitectureContext(workspaceRoot, ctx);

        // Map was rebuilt → different builtAt
        const cached = getCachedArchitectureContext(workspaceRoot, 'standard', 2000, 2);
        expect(cached).toBeNull();
    });

    it('returns null when the depth differs (different context per depth)', () => {
        const ctx = makeContext();
        writeCachedArchitectureContext(workspaceRoot, ctx);

        const cached = getCachedArchitectureContext(workspaceRoot, 'quick', 1000, 2);
        expect(cached).toBeNull();
    });

    it('clears the cache', () => {
        const ctx = makeContext();
        writeCachedArchitectureContext(workspaceRoot, ctx);
        clearArchitectureCache(workspaceRoot);

        const cached = getCachedArchitectureContext(workspaceRoot, 'standard', 1000, 2);
        expect(cached).toBeNull();
    });

    it('stores separate entries per depth', () => {
        const quickCtx = makeContext({ depth: 'quick', summary: 'Quick survey' });
        const standardCtx = makeContext({ depth: 'standard', summary: 'Standard survey' });

        writeCachedArchitectureContext(workspaceRoot, quickCtx);
        writeCachedArchitectureContext(workspaceRoot, standardCtx);

        const quick = getCachedArchitectureContext(workspaceRoot, 'quick', 1000, 2);
        const standard = getCachedArchitectureContext(workspaceRoot, 'standard', 1000, 2);

        expect(quick?.summary).toBe('Quick survey');
        expect(standard?.summary).toBe('Standard survey');
    });

    it('formatArchitectureContextForPrompt produces a non-empty string with key sections', () => {
        const ctx = makeContext();
        const formatted = formatArchitectureContextForPrompt(ctx);
        expect(formatted).toContain('Project architecture');
        expect(formatted).toContain('TypeScript Express API');
        expect(formatted).toContain('src/index.ts');
        expect(formatted).toContain('src/lib/auth.ts');
        expect(formatted).toContain('Trust boundaries');
        expect(formatted).toContain('Security controls');
        expect(formatted).toContain('Architecture-level risks');
        expect(formatted).toContain('Recommended scan order');
    });

    it('formatArchitectureContextForPrompt returns empty string for empty context', () => {
        const formatted = formatArchitectureContextForPrompt({ ...makeContext(), importantFiles: [] });
        expect(formatted).toBe('');
    });
});
