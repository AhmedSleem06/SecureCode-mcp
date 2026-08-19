import { describe, it, expect } from 'vitest';
import { computeBlastRadius, formatBlastRadius } from '../src/project-map/blastRadius';
import type { ProjectMap } from '../src/project-map/types';

function makeMap(files: Record<string, { imports?: Record<string, string>; endpoints?: any[] }>): ProjectMap {
    const map: ProjectMap = {
        files: {},
        endpoints: [],
        websockets: [],
        dynamicPatterns: [],
        version: 2,
        builtAt: Date.now(),
    };
    for (const [file, info] of Object.entries(files)) {
        map.files[file] = {
            file,
            language: 'typescript',
            endpoints: info.endpoints || [],
            websockets: [],
            dynamicPatterns: [],
            imports: info.imports || {},
            mtime: 0,
            hash: '',
        };
    }
    return map;
}

describe('computeBlastRadius', () => {
    it('returns empty for no changed files', () => {
        const map = makeMap({});
        const result = computeBlastRadius({ changedFiles: [], map });
        expect(result.files).toEqual([]);
        expect(result.changedFiles).toEqual([]);
        expect(result.affectedFiles).toEqual([]);
    });

    it('returns just the changed file when no reverse deps exist', () => {
        const map = makeMap({
            'src/utils.ts': {},
            'src/other.ts': {},
        });
        const result = computeBlastRadius({ changedFiles: ['src/utils.ts'], map });
        expect(result.files).toEqual(['src/utils.ts']);
        expect(result.affectedFiles).toEqual([]);
    });

    it('finds direct importers of a changed file', () => {
        const map = makeMap({
            'src/auth.ts': { imports: { './utils': 'src/utils.ts' } },
            'src/utils.ts': {},
            'src/handler.ts': { imports: { './auth': 'src/auth.ts' } },
        });
        const result = computeBlastRadius({ changedFiles: ['src/utils.ts'], map });
        expect(result.files).toContain('src/utils.ts');
        expect(result.files).toContain('src/auth.ts');
        expect(result.affectedFiles).toContain('src/auth.ts');
    });

    it('finds transitive importers (depth 2)', () => {
        const map = makeMap({
            'src/utils.ts': {},
            'src/auth.ts': { imports: { './utils': 'src/utils.ts' } },
            'src/handler.ts': { imports: { './auth': 'src/auth.ts' } },
            'src/routes.ts': { imports: { './handler': 'src/handler.ts' } },
        });
        const result = computeBlastRadius({ changedFiles: ['src/utils.ts'], map, maxDepth: 3 });
        expect(result.files).toContain('src/utils.ts');
        expect(result.files).toContain('src/auth.ts');
        expect(result.files).toContain('src/handler.ts');
        expect(result.files).toContain('src/routes.ts');
        expect(result.depthReached).toBeGreaterThanOrEqual(2);
    });

    it('respects maxDepth cap', () => {
        const map = makeMap({
            'a.ts': {},
            'b.ts': { imports: { './a': 'a.ts' } },
            'c.ts': { imports: { './b': 'b.ts' } },
            'd.ts': { imports: { './c': 'c.ts' } },
        });
        const result = computeBlastRadius({ changedFiles: ['a.ts'], map, maxDepth: 1 });
        expect(result.files).toContain('a.ts');
        expect(result.files).toContain('b.ts');
        expect(result.files).not.toContain('c.ts');
        expect(result.files).not.toContain('d.ts');
    });

    it('respects maxFiles cap', () => {
        const map: ProjectMap = {
            files: {},
            endpoints: [],
            websockets: [],
            dynamicPatterns: [],
            version: 2,
            builtAt: Date.now(),
        };
        for (let i = 0; i < 200; i++) {
            map.files[`dep${i}.ts`] = {
                file: `dep${i}.ts`,
                language: 'typescript',
                endpoints: [],
                websockets: [],
                dynamicPatterns: [],
                imports: { './base': 'base.ts' },
                mtime: 0,
                hash: '',
            };
        }
        map.files['base.ts'] = {
            file: 'base.ts',
            language: 'typescript',
            endpoints: [],
            websockets: [],
            dynamicPatterns: [],
            imports: {},
            mtime: 0,
            hash: '',
        };
        const result = computeBlastRadius({ changedFiles: ['base.ts'], map, maxFiles: 50 });
        expect(result.files.length).toBeLessThanOrEqual(50);
        expect(result.truncated).toBe(true);
    });

    it('handles multiple changed files', () => {
        const map = makeMap({
            'a.ts': {},
            'b.ts': {},
            'c.ts': { imports: { './a': 'a.ts' } },
            'd.ts': { imports: { './b': 'b.ts' } },
        });
        const result = computeBlastRadius({ changedFiles: ['a.ts', 'b.ts'], map });
        expect(result.files).toContain('a.ts');
        expect(result.files).toContain('b.ts');
        expect(result.files).toContain('c.ts');
        expect(result.files).toContain('d.ts');
    });

    it('finds callers via call graph edges', () => {
        const map = makeMap({
            'src/lib.ts': {},
            'src/handler.ts': {
                endpoints: [{
                    method: 'GET',
                    path: '/api',
                    sourceFile: 'src/handler.ts',
                    line: 1,
                    handlerName: 'getHandler',
                    middleware: [],
                    callGraph: [{ callee: 'doStuff', calleeFile: 'src/lib.ts', line: 5 }],
                }],
            },
        });
        const result = computeBlastRadius({ changedFiles: ['src/lib.ts'], map });
        expect(result.files).toContain('src/lib.ts');
        expect(result.files).toContain('src/handler.ts');
        expect(result.affectedFiles).toContain('src/handler.ts');
    });

    it('finds handlers via middleware edges', () => {
        const map = makeMap({
            'src/middleware.ts': {},
            'src/handler.ts': {
                endpoints: [{
                    method: 'GET',
                    path: '/api',
                    sourceFile: 'src/handler.ts',
                    line: 1,
                    handlerName: 'getHandler',
                    middleware: [{ name: 'auth', sourceFile: 'src/middleware.ts', line: 1 }],
                    callGraph: [],
                }],
            },
        });
        const result = computeBlastRadius({ changedFiles: ['src/middleware.ts'], map });
        expect(result.files).toContain('src/middleware.ts');
        expect(result.files).toContain('src/handler.ts');
    });

    it('normalizes Windows-style paths', () => {
        const map = makeMap({
            'src/auth.ts': { imports: { './utils': 'src/utils.ts' } },
            'src/utils.ts': {},
        });
        const result = computeBlastRadius({ changedFiles: ['src\\utils.ts'], map });
        expect(result.files).toContain('src/utils.ts');
    });

    it('does not traverse forward edges (changing a dependency does not affect its importers)', () => {
        const map = makeMap({
            'src/auth.ts': { imports: { './utils': 'src/utils.ts' } },
            'src/utils.ts': { imports: { './other': 'src/other.ts' } },
            'src/other.ts': {},
        });
        const result = computeBlastRadius({ changedFiles: ['src/auth.ts'], map });
        expect(result.files).toContain('src/auth.ts');
        expect(result.files).not.toContain('src/utils.ts');
        expect(result.files).not.toContain('src/other.ts');
    });
});

describe('formatBlastRadius', () => {
    it('formats empty result', () => {
        const result = computeBlastRadius({ changedFiles: [], map: makeMap({}) });
        const formatted = formatBlastRadius(result);
        expect(formatted).toContain('No blast radius');
    });

    it('formats non-empty result with changed and affected sections', () => {
        const map = makeMap({
            'src/utils.ts': {},
            'src/auth.ts': { imports: { './utils': 'src/utils.ts' } },
        });
        const result = computeBlastRadius({ changedFiles: ['src/utils.ts'], map });
        const formatted = formatBlastRadius(result);
        expect(formatted).toContain('Changed files:');
        expect(formatted).toContain('[changed] src/utils.ts');
        expect(formatted).toContain('Affected files');
        expect(formatted).toContain('[affected] src/auth.ts');
    });
});
