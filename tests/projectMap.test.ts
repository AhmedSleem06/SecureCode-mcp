import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { buildProjectMap } from '../src/project-map/mapBuilder';
import { writeCache, readCache, cacheStatus, cachePath } from '../src/project-map/cache';
import { parseSource } from '../src/project-map/parserLoader';
import { extractLayer1 } from '../src/project-map/layer1';
import { detectDynamicPatterns } from '../src/project-map/layer2';

const EXPRESS_FIXTURE = `const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const auth = (req, res, next) => {
  if (!req.headers.authorization) return res.status(401).json({ error: 'No token' });
  next();
};

router.get('/users/:id', auth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  res.json(user);
});

router.post('/users', async (req, res) => {
  const { email, name } = req.body;
  const user = await prisma.user.create({ data: { email, name } });
  res.status(201).json(user);
});

router.delete('/users/:id', auth, async (req, res) => {
  await prisma.user.delete({ where: { id: req.params.id } });
  res.status(204).send();
});

module.exports = router;
`;

const DYNAMIC_FIXTURE = `const path = require('path');
const fs = require('fs');

// D1: require with a variable
const mod = 'crypto';
const m = require(mod);

// D2: dynamic import with variable
const name = 'lodash';
import(name);

// D3: require with template literal
const lib = require(\`./lib/\${process.env.LIB}\`);

// D4: app.use with env var
const app = require('express')();
app.use(require(process.env.MIDDLEWARE));

// D6: new Function
const fn = new Function('a', 'return a');

// D9: eval
const mod = '1+2';
const result = eval(mod);
`;

function makeWorkspace(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-pm-test-'));
    for (const [relPath, content] of Object.entries(files)) {
        const fullPath = path.join(dir, relPath);
        fs.mkdirSync(path.dirname(fullPath), { recursive: true });
        fs.writeFileSync(fullPath, content, 'utf8');
    }
    return dir;
}

describe('Project Map — parser', () => {
    it('parses JavaScript source and returns an AST root', async () => {
        const parsed = await parseSource('const x = 1;', 'javascript');
        expect(parsed).not.toBeNull();
        expect(parsed!.root).toBeDefined();
    });

    it('returns null for unsupported language', async () => {
        const parsed = await parseSource('x = 1', 'unknown' as any);
        expect(parsed).toBeNull();
    });
});

describe('Project Map — Layer 1 endpoint extraction', () => {
    it('extracts endpoints from an Express router fixture', async () => {
        const parsed = await parseSource(EXPRESS_FIXTURE, 'javascript');
        expect(parsed).not.toBeNull();
        const result = extractLayer1('routes/users.js', EXPRESS_FIXTURE, parsed!.root);
        expect(result.endpoints.length).toBe(3);

        const getEndpoint = result.endpoints.find(e => e.method === 'GET');
        expect(getEndpoint).toBeDefined();
        expect(getEndpoint!.path).toBe('/users/:id');
        expect(getEndpoint!.handlerName).toBeDefined();
        expect(getEndpoint!.middleware.length).toBeGreaterThan(0);
        expect(getEndpoint!.dataLayer).toBe('prisma');

        const postEndpoint = result.endpoints.find(e => e.method === 'POST');
        expect(postEndpoint).toBeDefined();
        expect(postEndpoint!.path).toBe('/users');
        expect(postEndpoint!.dataLayer).toBe('prisma');

        const deleteEndpoint = result.endpoints.find(e => e.method === 'DELETE');
        expect(deleteEndpoint).toBeDefined();
        expect(deleteEndpoint!.middleware.length).toBeGreaterThan(0);
    });
});

describe('Project Map — Layer 2 dynamic detection', () => {
    it('detects D1-D10 dynamic patterns', async () => {
        const parsed = await parseSource(DYNAMIC_FIXTURE, 'javascript');
        expect(parsed).not.toBeNull();
        const patterns = detectDynamicPatterns('dynamic.js', DYNAMIC_FIXTURE, parsed!.root);
        const types = patterns.map(p => p.type);
        expect(types).toContain('D1');
        expect(types).toContain('D2');
        expect(types).toContain('D3');
        expect(types).toContain('D4');
        expect(types).toContain('D6');
        expect(types).toContain('D9');
    });
});

describe('Project Map — standalone builder', () => {
    let workspace: string;

    beforeAll(() => {
        workspace = makeWorkspace({
            'routes/users.js': EXPRESS_FIXTURE,
            'dynamic.js': DYNAMIC_FIXTURE,
            'package.json': JSON.stringify({ name: 'test', scripts: { dev: 'node index.js' } }),
            'node_modules/dummy.js': 'module.exports = {};', // should be skipped
        });
    });

    it('builds the map from source files', async () => {
        const result = await buildProjectMap({ workspaceRoot: workspace });
        expect(result.filesProcessed).toBe(2); // routes/users.js + dynamic.js
        expect(result.map.endpoints.length).toBe(3);
        expect(result.map.endpoints[0].method).toBeDefined();
        expect(result.map.endpoints[0].path).toBeDefined();
        expect(result.map.endpoints[0].sourceFile).toBe('routes/users.js');
    });

    it('skips node_modules and unsupported files', async () => {
        const result = await buildProjectMap({ workspaceRoot: workspace });
        expect(result.map.files).not.toHaveProperty('node_modules/dummy.js');
        expect(result.map.files).not.toHaveProperty('package.json');
    });

    it('captures dynamic patterns across files', async () => {
        const result = await buildProjectMap({ workspaceRoot: workspace });
        expect(result.map.dynamicPatterns.length).toBeGreaterThan(0);
        const types = result.map.dynamicPatterns.map(p => p.type);
        expect(types).toContain('D1');
    });
});

describe('Project Map — cache', () => {
    let workspace: string;

    beforeAll(() => {
        workspace = makeWorkspace({
            'app.js': EXPRESS_FIXTURE,
        });
    });

    it('writeCache and readCache round-trip', async () => {
        const result = await buildProjectMap({ workspaceRoot: workspace });
        writeCache(workspace, result.map);
        const cached = readCache(workspace);
        expect(cached).not.toBeNull();
        expect(cached!.endpoints.length).toBe(3);
        expect(cached!.version).toBe(1);
    });

    it('cacheStatus reports metadata', async () => {
        const status = cacheStatus(workspace);
        expect(status.exists).toBe(true);
        expect(status.endpointCount).toBe(3);
        expect(status.version).toBe(1);
    });

    it('readCache returns null when no cache exists', () => {
        const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-empty-'));
        const cached = readCache(empty);
        expect(cached).toBeNull();
        const status = cacheStatus(empty);
        expect(status.exists).toBe(false);
        try { fs.rmSync(empty, { recursive: true, force: true }); } catch { }
    });

    it('cachePath returns the correct path', () => {
        const p = cachePath('/my/workspace');
        expect(p).toContain('.securecode');
        expect(p).toContain('project-map.json');
    });
});
