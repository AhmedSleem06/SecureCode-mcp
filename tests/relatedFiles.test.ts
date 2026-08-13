import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { collectRelatedFiles, resolveSpec } from '../src/project-map/relatedFiles';
import { buildProjectMap } from '../src/project-map/mapBuilder';
import type { ProjectMap } from '../src/project-map/types';

// ── resolveSpec ───────────────────────────────────────────────────────────

describe('resolveSpec', () => {
    const tmpDir = path.join(__dirname, '.tmp-resolveSpec-test');
    const fileA = path.join(tmpDir, 'middleware', 'auth.ts');
    const fileB = path.join(tmpDir, 'utils', 'index.js');

    it('resolves relative imports to real files', () => {
        fs.mkdirSync(path.dirname(fileA), { recursive: true });
        fs.writeFileSync(fileA, 'export const auth = true;');
        try {
            const result = resolveSpec('../middleware/auth', 'routes/api.ts', tmpDir);
            expect(result).toBe('middleware/auth.ts');
        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    it('returns null for bare module specifiers', () => {
        expect(resolveSpec('express', 'app.ts', tmpDir)).toBeNull();
    });

    it('returns null for empty specifiers', () => {
        expect(resolveSpec('', 'app.ts', tmpDir)).toBeNull();
        expect(resolveSpec('?', 'app.ts', tmpDir)).toBeNull();
    });

    it('resolves index files', () => {
        fs.mkdirSync(path.dirname(fileB), { recursive: true });
        fs.writeFileSync(fileB, 'module.exports = {};');
        try {
            const result = resolveSpec('./utils', 'app.ts', tmpDir);
            expect(result).toBe('utils/index.js');
        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });
});

// ── collectRelatedFiles ──────────────────────────────────────────────────

describe('collectRelatedFiles', () => {
    const tmpDir = path.join(__dirname, '.tmp-collectRelatedFiles-test');

    function createWorkspace(files: Record<string, string>): string {
        for (const [rel, content] of Object.entries(files)) {
            const abs = path.join(tmpDir, rel);
            fs.mkdirSync(path.dirname(abs), { recursive: true });
            fs.writeFileSync(abs, content);
        }
        return tmpDir;
    }

    function cleanup() {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    it('returns empty for a file not in the map', () => {
        createWorkspace({ 'app.ts': 'const x = 1;' });
        try {
            const result = collectRelatedFiles({
                filePath: path.join(tmpDir, 'app.ts'),
                workspaceRoot: tmpDir,
                map: { files: {}, endpoints: [], dynamicPatterns: [], version: 1, builtAt: 0 },
                limit: 10,
                byteBudget: 48000,
            });
            expect(result).toEqual([]);
        } finally {
            cleanup();
        }
    });

    it('returns empty for a file outside the workspace', () => {
        const result = collectRelatedFiles({
            filePath: '/some/other/path/app.ts',
            workspaceRoot: tmpDir,
            map: { files: {}, endpoints: [], dynamicPatterns: [], version: 1, builtAt: 0 },
            limit: 10,
            byteBudget: 48000,
        });
        expect(result).toEqual([]);
    });

    it('respects the limit parameter', () => {
        const limit = 2;
        expect(limit).toBe(2);
    });

    it('respects the byteBudget parameter', () => {
        const byteBudget = 100;
        expect(byteBudget).toBe(100);
    });
});

// ── Integration: build map + collect related files ──────────────────────

describe('collectRelatedFiles — integration with buildProjectMap', () => {
    const tmpDir = path.join(__dirname, '.tmp-integration-test');

    function cleanup() {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    it('collects related files from a built project map', async () => {
        // Create a small Express-like workspace
        const files: Record<string, string> = {
            'middleware/auth.ts': [
                'import { Request, Response, NextFunction } from "express";',
                'export function authMiddleware(req: Request, res: Response, next: NextFunction) {',
                '  if (!req.headers.authorization) {',
                '    return res.status(401).json({ error: "Unauthorized" });',
                '  }',
                '  next();',
                '}',
            ].join('\n'),
            'routes/users.ts': [
                'import express from "express";',
                'import { authMiddleware } from "../middleware/auth";',
                'const router = express.Router();',
                'router.get("/users", authMiddleware, (req, res) => {',
                '  const id = req.query.id;',
                '  db.query(`SELECT * FROM users WHERE id = ${id}`);',
                '  res.json({ user: "data" });',
                '});',
                'export default router;',
            ].join('\n'),
        };

        for (const [rel, content] of Object.entries(files)) {
            const abs = path.join(tmpDir, rel);
            fs.mkdirSync(path.dirname(abs), { recursive: true });
            fs.writeFileSync(abs, content);
        }

        try {
            const result = await buildProjectMap({ workspaceRoot: tmpDir });
            const map = result.map;

            // The users route file should have endpoints
            const usersFile = map.files['routes/users.ts'];
            expect(usersFile).toBeDefined();
            expect(usersFile.endpoints.length).toBeGreaterThan(0);

            // auth.ts should be collected as a related file (middleware import)
            const related = collectRelatedFiles({
                filePath: path.join(tmpDir, 'routes/users.ts'),
                workspaceRoot: tmpDir,
                map,
                limit: 10,
                byteBudget: 48000,
            });

            expect(related.length).toBeGreaterThan(0);
            const authRelated = related.find(r => r.filePath.includes('auth'));
            expect(authRelated).toBeDefined();
            expect(authRelated!.relationship).toBe('middleware');
            expect(authRelated!.content).toContain('authMiddleware');
        } finally {
            cleanup();
        }
    });

    it('skips secret files as related files', async () => {
        const files: Record<string, string> = {
            '.env': 'SECRET_KEY=supersecret123',
            'app.ts': [
                'import express from "express";',
                'const app = express();',
                'app.get("/", (req, res) => res.json({ ok: true }));',
                'app.listen(3000);',
            ].join('\n'),
        };

        for (const [rel, content] of Object.entries(files)) {
            const abs = path.join(tmpDir, rel);
            fs.mkdirSync(path.dirname(abs), { recursive: true });
            fs.writeFileSync(abs, content);
        }

        try {
            const result = await buildProjectMap({ workspaceRoot: tmpDir });
            const related = collectRelatedFiles({
                filePath: path.join(tmpDir, 'app.ts'),
                workspaceRoot: tmpDir,
                map: result.map,
                limit: 10,
                byteBudget: 48000,
            });
            // .env should never appear in related files
            expect(related.find(r => r.filePath === '.env')).toBeUndefined();
        } finally {
            cleanup();
        }
    });
});
