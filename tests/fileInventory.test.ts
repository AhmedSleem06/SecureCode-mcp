import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { buildFileInventory, INVENTORY_LIST_CAP, type FileInventory } from '../src/assurance/fileInventory';

const FIVE_BUG_SERVER = `const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const db = require('./db');

const app = express();
const STRIPE_SECRET_KEY = '${'sk_' + 'live_'}51Hq8xKJ2eZvKYlo2C9a7bQx4mT0pLrV3sN6dW8yF1gH5jU';

app.get('/user', (req, res) => {
    const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
    db.query(query, (err, rows) => {
        if (err) return res.status(500).send('error');
        res.json(rows);
    });
});

app.get('/ping', (req, res) => {
    exec(\`ping -c 1 \${req.query.host}\`, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/file', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.query.name);
    res.send(fs.readFileSync(filePath, 'utf8'));
});

app.get('/calc', (req, res) => {
    const result = eval(req.query.expr);
    res.send(String(result));
});

app.get('/charge', (req, res) => {
    res.json({ key: STRIPE_SECRET_KEY.slice(0, 7) });
});

module.exports = app;

if (require.main === module) {
    app.listen(3000);
}
`;

const ADMIN_SERVER = `import express, { NextFunction, Request, Response } from 'express';
import Database from 'better-sqlite3';
import crypto from 'crypto';
import { loadSettings } from './config';

type Role = 'admin' | 'member';

interface SessionUser {
    id: number;
    role: Role;
}

const db = new Database(process.env.TEAMDESK_DB_PATH || 'teamdesk.db');
const app = express();
app.use(express.json({ limit: '100kb' }));

function verifySessionToken(token: string): SessionUser | null {
    const [payload, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', loadSettings().secret).update(payload).digest('base64url');
    if (signature !== expected) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const row = db.prepare('SELECT id, role FROM users WHERE id = ?').get(data.uid) as any;
    return row ? { id: row.id, role: row.role === 'admin' ? 'admin' : 'member' } : null;
}

function requireAuth(req: Request, res: Response, next: NextFunction) {
    const header = req.headers.authorization || '';
    const user = header.startsWith('Bearer ') ? verifySessionToken(header.slice(7)) : null;
    if (!user) return res.status(401).json({ error: 'authentication required' });
    (req as any).user = user;
    next();
}

function requireAdmin(req: Request, res: Response, next: NextFunction) {
    if ((req as any).user?.role !== 'admin') {
        return res.status(403).json({ error: 'administrator access required' });
    }
    next();
}

function isTeamMember(userId: number, teamId: number): boolean {
    return !!db.prepare('SELECT 1 FROM memberships WHERE user_id = ? AND team_id = ?').get(userId, teamId);
}

app.get('/api/teams/:teamId/projects', requireAuth, (req, res) => {
    const teamId = Number(req.params.teamId);
    if (!isTeamMember((req as any).user.id, teamId)) return res.status(403).json({ error: 'forbidden' });
    res.json(db.prepare('SELECT * FROM projects WHERE team_id = ?').all(teamId));
});

app.delete('/api/teams/:teamId/projects/:id', requireAuth, (req, res) => {
    const row = db.prepare('SELECT * FROM projects WHERE id = ?').get(Number(req.params.id)) as any;
    if (row.created_by !== (req as any).user.id && (req as any).user.role !== 'admin') {
        return res.status(403).json({ error: 'forbidden' });
    }
    db.prepare('DELETE FROM projects WHERE id = ?').run(row.id);
    res.status(204).end();
});

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
    res.json(db.prepare('SELECT id, email, role FROM users').all());
});

app.post('/api/admin/users/:id/disable', requireAuth, requireAdmin, (req, res) => {
    db.prepare('UPDATE users SET disabled = 1 WHERE id = ?').run(Number(req.params.id));
    res.json({ ok: true });
});

const ROLES = new Set<Role>(['admin', 'member']);

app.post('/api/admin/users/:id/role', requireAuth, (req, res) => {
    const id = Number(req.params.id);
    const role = req.body?.role;
    if (!ROLES.has(role)) return res.status(400).json({ error: 'invalid role' });
    db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
    res.json({ ok: true });
});

app.listen(4310);
`;

const SYNARA_RPC = `import { Effect } from 'effect';
import { execSync } from 'child_process';
import { WS_METHODS } from './contracts';
import { requireOwnerSession } from './auth';

export function canManageExternalMcp(role: 'owner' | 'client'): boolean {
    return role === 'owner';
}

export const makeWsRpcHandlers = (session: { role: 'owner' | 'client' }) => ({
    [WS_METHODS.terminalOpen]: (input) =>
        Effect.gen(function* () {
            if (session.role !== 'owner') {
                return yield* Effect.fail(new Error('Forbidden'));
            }
            const pty = yield* terminalManager.open({ cwd: input.cwd, shell: input.shell });
            return pty;
        }),
    [WS_METHODS.terminalWrite]: (input) => terminalManager.write(input.terminalId, input.data),
    [WS_METHODS.projectsReadFile]: (input) =>
        requireOwnerSession(session).pipe(Effect.flatMap(() => workspaceFileSystem.readFile(input))),
    [WS_METHODS.shellRun]: (input) => Effect.sync(() => execSync(input.command)),
});

socket.on('message', (raw) => dispatch(JSON.parse(raw)));
`;

function makeWorkspace(files: Record<string, string>): string {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'inv-test-'));
    for (const [rel, body] of Object.entries(files)) {
        const abs = path.join(root, rel);
        fs.mkdirSync(path.dirname(abs), { recursive: true });
        fs.writeFileSync(abs, body, 'utf8');
    }
    return root;
}

function withoutStats(inv: FileInventory): Omit<FileInventory, 'stats'> {
    const { stats: _s, ...rest } = inv;
    return rest;
}

function entry(inv: FileInventory, name: string) {
    const e = inv.entryPoints.find(x => x.name === name);
    expect(e, `entry ${name}`).toBeDefined();
    return e!;
}

const roots: string[] = [];
afterAll(() => {
    for (const r of roots) {
        try { fs.rmSync(r, { recursive: true, force: true }); } catch {}
    }
});

describe('buildFileInventory — 5-bug Express file', () => {
    let root: string;
    let inv: FileInventory;

    beforeAll(async () => {
        root = makeWorkspace({
            'server.js': FIVE_BUG_SERVER,
            'db.js': 'module.exports = { query() {} };\n',
            'routes.js': "const app = require('./server');\nmodule.exports = app;\n",
            'package.json': '{"name":"lab","dependencies":{"express":"4.17.1"}}\n',
        });
        roots.push(root);
        inv = await buildFileInventory(root, 'server.js', FIVE_BUG_SERVER);
    });

    it('finds every HTTP route plus the export and the CLI start', () => {
        const http = inv.entryPoints.filter(e => e.kind === 'http');
        expect(http.map(e => e.name)).toEqual(['GET /user', 'GET /ping', 'GET /file', 'GET /calc', 'GET /charge']);
        expect(http.every(e => e.method === 'GET' && e.path?.startsWith('/'))).toBe(true);
        expect(entry(inv, 'GET /user')).toMatchObject({ line: 10, endLine: 16 });
        expect(inv.entryPoints.some(e => e.kind === 'export' && e.name === 'app')).toBe(true);
        expect(inv.entryPoints.some(e => e.kind === 'cli' && e.name === 'main')).toBe(true);
    });

    it('finds the SQL, shell, path, eval and hardcoded secret sinks', () => {
        const types = inv.sinks.map(s => s.attackType);
        expect(types).toEqual(expect.arrayContaining(['sql_injection', 'command_injection', 'path_traversal', 'secret_exposure']));
        expect(inv.sinks.find(s => s.kind === 'eval')?.line).toBe(30);
        expect(inv.sinks.find(s => s.kind === 'exec')?.entryId).toBe(entry(inv, 'GET /ping').id);
        expect(inv.sinks.find(s => s.kind === 'hardcoded_secret')?.line).toBe(8);
    });

    it('ties each query input to its route and links input → sink flows', () => {
        const id = inv.inputs.find(i => i.source === 'req.query.id');
        expect(id).toMatchObject({ line: 11, entryId: entry(inv, 'GET /user').id });
        expect(inv.flows).toHaveLength(4);
        const sql = inv.flows.find(f => f.attackType === 'sql_injection')!;
        expect(sql.from).toBe(id!.id);
        expect(inv.sinks.find(s => s.id === sql.to)?.attackType).toBe('sql_injection');
        expect(sql.via.length).toBeGreaterThan(0);
        expect(inv.flows.every(f => f.crossFile === false)).toBe(true);
    });

    it('lists imports, importers and config as connected files', () => {
        expect(inv.connected).toEqual(expect.arrayContaining([
            expect.objectContaining({ file: 'db.js', relation: 'imports' }),
            expect.objectContaining({ file: 'routes.js', relation: 'imported_by' }),
            expect.objectContaining({ file: 'package.json', relation: 'config' }),
        ]));
        expect(inv.connected[0].relation).toBe('imports');
    });

    it('uses stable sequential ids and returns the same result twice', async () => {
        inv.entryPoints.forEach((e, i) => expect(e.id).toBe(`ep${i + 1}`));
        inv.sinks.forEach((s, i) => expect(s.id).toBe(`sk${i + 1}`));
        inv.inputs.forEach((s, i) => expect(s.id).toBe(`in${i + 1}`));
        const again = await buildFileInventory(root, path.join(root, 'server.js'), FIVE_BUG_SERVER);
        expect(withoutStats(again)).toEqual(withoutStats(inv));
        expect(inv.stats?.failedSteps).toEqual([]);
    });
});

describe('buildFileInventory — admin server with role checks', () => {
    let inv: FileInventory;

    beforeAll(async () => {
        const root = makeWorkspace({
            'src/adminServer.ts': ADMIN_SERVER,
            'src/config.ts': 'export function loadSettings() { return { secret: process.env.SECRET ?? "" }; }\n',
        });
        roots.push(root);
        inv = await buildFileInventory(root, 'src/adminServer.ts', ADMIN_SERVER);
    });

    it('records route middleware per entry point', () => {
        expect(inv.entryPoints.filter(e => e.kind === 'http')).toHaveLength(5);
        expect(entry(inv, 'GET /api/admin/users').middleware).toEqual(['requireAuth', 'requireAdmin']);
        expect(entry(inv, 'POST /api/admin/users/:id/role').middleware).toEqual(['requireAuth']);
    });

    it('maps which entries each guard protects, exposing the unguarded admin route', () => {
        const requireAdmin = inv.guards.find(g => g.name === 'requireAdmin')!;
        const requireAuth = inv.guards.find(g => g.name === 'requireAuth')!;
        expect(requireAdmin.kind).toBe('middleware');
        expect(requireAdmin.protects).toEqual([entry(inv, 'GET /api/admin/users').id, entry(inv, 'POST /api/admin/users/:id/disable').id]);
        expect(requireAdmin.protects).not.toContain(entry(inv, 'POST /api/admin/users/:id/role').id);
        expect(requireAuth.protects).toHaveLength(5);
        expect(inv.guards.find(g => g.name === 'isTeamMember')?.protects).toEqual([entry(inv, 'GET /api/teams/:teamId/projects').id]);
        const ownership = inv.guards.find(g => g.kind === 'inline' && g.name.includes('created_by'));
        expect(ownership?.protects).toEqual([entry(inv, 'DELETE /api/teams/:teamId/projects/:id').id]);
        expect(inv.guards.some(g => g.kind === 'inline' && g.name.includes("role !== 'admin'"))).toBe(true);
    });

    it('finds roles, data writes and the request inputs of the role route', () => {
        expect(inv.roles).toEqual(expect.arrayContaining(['admin', 'member']));
        const roleRoute = entry(inv, 'POST /api/admin/users/:id/role');
        const write = inv.sinks.find(s => s.callExpression.includes('UPDATE users SET role'));
        expect(write).toMatchObject({ kind: 'db_write', entryId: roleRoute.id });
        const sources = inv.inputs.filter(i => i.entryId === roleRoute.id).map(i => i.source);
        expect(sources).toEqual(expect.arrayContaining(['req.params.id', 'req.body.role']));
        expect(inv.connected.some(c => c.file === 'src/config.ts' && c.relation === 'imports')).toBe(true);
    });
});

const CROSS_PART_ROOT = path.resolve(__dirname, '../../test_lab/cross-part-bac');
const CROSS_PART_FILE = path.join(CROSS_PART_ROOT, 'src/adminServer.ts');

describe.skipIf(!fs.existsSync(CROSS_PART_FILE))('buildFileInventory — test_lab/cross-part-bac (large file)', () => {
    it('inventories the 2,000+ line admin server quickly and within caps', async () => {
        const content = fs.readFileSync(CROSS_PART_FILE, 'utf8');
        const started = Date.now();
        const inv = await buildFileInventory(CROSS_PART_ROOT, 'src/adminServer.ts', content);
        const elapsed = Date.now() - started;
        expect(elapsed).toBeLessThan(10_000);
        expect(inv.entryPoints.filter(e => e.kind === 'http').length).toBeGreaterThan(150);
        for (const list of [inv.entryPoints, inv.inputs, inv.sinks, inv.guards, inv.flows]) {
            expect(list.length).toBeLessThanOrEqual(INVENTORY_LIST_CAP);
        }
        expect(inv.roles).toEqual(expect.arrayContaining(['admin', 'member']));
        const roleRoute = entry(inv, 'POST /api/admin/users/:id/role');
        expect(roleRoute.middleware).toEqual(['requireAuth']);
        const requireAdmin = inv.guards.find(g => g.name === 'requireAdmin')!;
        expect(requireAdmin.protects!.length).toBeGreaterThan(20);
        expect(requireAdmin.protects).not.toContain(roleRoute.id);
        expect(inv.sinks.some(s => s.entryId === roleRoute.id && s.kind === 'db_write')).toBe(true);
        expect(inv.inputs.some(i => i.entryId === roleRoute.id)).toBe(true);
        expect(inv.stats?.failedSteps).toEqual([]);
    }, 30_000);
});

describe('buildFileInventory — Synara-shaped RPC method table', () => {
    let inv: FileInventory;

    beforeAll(async () => {
        const root = makeWorkspace({
            'src/wsRpc.ts': SYNARA_RPC,
            'src/contracts.ts': "export const WS_METHODS = { terminalOpen: 'terminal.open' } as const;\n",
            'src/auth.ts': 'export const requireOwnerSession = (s: unknown) => s;\n',
        });
        roots.push(root);
        inv = await buildFileInventory(root, 'src/wsRpc.ts', SYNARA_RPC);
    });

    it('finds each RPC method, the socket event and the exports', () => {
        const rpc = inv.entryPoints.filter(e => e.kind === 'rpc').map(e => e.name);
        expect(rpc).toEqual([
            'WS_METHODS.terminalOpen', 'WS_METHODS.terminalWrite', 'WS_METHODS.projectsReadFile', 'WS_METHODS.shellRun',
        ]);
        expect(entry(inv, 'WS_METHODS.terminalOpen').endLine).toBe(18);
        expect(inv.entryPoints.some(e => e.kind === 'event' && e.name.includes("'message'"))).toBe(true);
        expect(inv.entryPoints.filter(e => e.kind === 'export').map(e => e.name))
            .toEqual(['canManageExternalMcp', 'makeWsRpcHandlers']);
    });

    it('treats handler parameters as inputs of their RPC method', () => {
        const open = entry(inv, 'WS_METHODS.terminalOpen');
        const write = entry(inv, 'WS_METHODS.terminalWrite');
        expect(inv.inputs.filter(i => i.entryId === open.id).map(i => i.source)).toEqual(['input.cwd', 'input.shell']);
        expect(inv.inputs.filter(i => i.entryId === write.id).map(i => i.source)).toEqual(['input.terminalId', 'input.data']);
        expect(inv.inputs.every(i => i.entryId === null || i.sourceType !== undefined)).toBe(true);
    });

    it('finds the owner check, the owner guard, both roles and the shell sink', () => {
        const ownerCheck = inv.guards.find(g => g.kind === 'inline' && g.name.includes("session.role !== 'owner'"));
        expect(ownerCheck?.protects).toEqual([entry(inv, 'WS_METHODS.terminalOpen').id]);
        const named = inv.guards.find(g => g.name === 'requireOwnerSession');
        expect(named?.protects).toEqual([entry(inv, 'WS_METHODS.projectsReadFile').id]);
        expect(inv.roles).toEqual(['owner', 'client']);
        const shell = inv.sinks.find(s => s.attackType === 'command_injection');
        expect(shell?.entryId).toBe(entry(inv, 'WS_METHODS.shellRun').id);
        expect(inv.connected.map(c => c.file)).toEqual(expect.arrayContaining(['src/contracts.ts', 'src/auth.ts']));
    });
});

describe('buildFileInventory — robustness', () => {
    it('never throws on unknown languages, empty content or a missing workspace', async () => {
        const root = makeWorkspace({});
        roots.push(root);
        const a = await buildFileInventory('', 'notes.md', '# hello');
        expect(a.file).toBe('notes.md');
        expect(a.entryPoints).toEqual([]);
        const b = await buildFileInventory(path.join(root, 'does-not-exist'), 'x.ts', '');
        expect(b.sinks).toEqual([]);
        const c = await buildFileInventory(root, 'broken.ts', 'export function (((( {{{ app.get(');
        expect(Array.isArray(c.guards)).toBe(true);
    });

    it('caps lists at 200 entries and reports the truncation', async () => {
        const root = makeWorkspace({});
        roots.push(root);
        const routes = Array.from({ length: 260 }, (_, i) => `app.get('/r${i}', (req, res) => res.send(req.query.q${i}));`).join('\n');
        const inv = await buildFileInventory(root, 'many-routes.js', `const app = require('express')();\n${routes}\n`);
        expect(inv.entryPoints).toHaveLength(INVENTORY_LIST_CAP);
        expect(inv.inputs.length).toBeLessThanOrEqual(INVENTORY_LIST_CAP);
        expect(inv.stats?.truncated.some(t => t.startsWith('entryPoints'))).toBe(true);
    });
});
