import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
    buildProjectSecurityHints,
    clearProjectSecurityContextCache,
    extractPolicyStatements,
} from '../src/project-map/projectSecurityContext';

const LOCKFILE = {
    name: 'app',
    lockfileVersion: 3,
    packages: {
        '': { name: 'app', dependencies: { lodash: '4.17.11', express: '4.18.2' } },
        'node_modules/lodash': { version: '4.17.11' },
        'node_modules/express': { version: '4.18.2' },
        'node_modules/express/node_modules/lodash': { version: '4.17.21' },
        'node_modules/@supabase/supabase-js': { version: '2.39.0' },
    },
};

const MIGRATION = `
-- messages are private to their owner
ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner can read"
    ON public.messages
    FOR SELECT
    USING (user_id = auth.uid());

ALTER TABLE public.licenses DISABLE ROW LEVEL SECURITY;

CREATE TABLE public.audit_log (id uuid primary key);
CREATE POLICY "audit insert" ON public.audit_log FOR INSERT WITH CHECK (true);
`;

const ROUTE_FILE = [
    "const _ = require('lodash');",
    "const merge = require('lodash/merge');",
    "const { data } = await supabase.from('messages').select('*');",
    'app.post("/x", (req, res) => res.json(_.merge({}, req.body)));',
].join('\n');

const write = (root: string, rel: string, content: string) => {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
    return full;
};

describe('buildProjectSecurityHints', () => {
    let root: string;

    beforeEach(() => {
        clearProjectSecurityContextCache();
        root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-projctx-'));
        write(root, 'package-lock.json', JSON.stringify(LOCKFILE));
        write(root, 'supabase/migrations/001.sql', MIGRATION);
    });

    afterEach(() => {
        fs.rmSync(root, { recursive: true, force: true });
    });

    it('sends only imported packages and the statements for referenced tables', async () => {
        const hints = await buildProjectSecurityHints(root, 'src/routes/messages.js', ROUTE_FILE);
        expect(hints.dependencies).toEqual(['lodash@4.17.11']);
        expect(hints.databasePolicies).toEqual([
            'ALTER TABLE public.messages ENABLE ROW LEVEL SECURITY;',
            'CREATE POLICY "owner can read" ON public.messages FOR SELECT USING (user_id = auth.uid());',
        ]);
    });

    it('sends nothing for a file without imports or tables', async () => {
        const hints = await buildProjectSecurityHints(root, 'src/util.js', 'export const add = (a, b) => a + b;');
        expect(hints).toEqual({});
    });

    it('sends no policies when the referenced tables have none', async () => {
        const code = "const { data } = await supabase.from('profiles').select('*');";
        expect(await buildProjectSecurityHints(root, 'src/p.js', code)).toEqual({});
    });

    it('caches the parsed lockfile and migrations until their mtime changes', async () => {
        const lockPath = path.join(root, 'package-lock.json');
        const sqlPath = path.join(root, 'supabase/migrations/001.sql');
        const pinned = new Date('2026-01-01T00:00:00Z');
        fs.utimesSync(lockPath, pinned, pinned);
        fs.utimesSync(sqlPath, pinned, pinned);
        await buildProjectSecurityHints(root, 'src/a.js', ROUTE_FILE);

        const bumped = JSON.parse(JSON.stringify(LOCKFILE));
        bumped.packages['node_modules/lodash'].version = '4.17.21';
        fs.writeFileSync(lockPath, JSON.stringify(bumped));
        fs.writeFileSync(sqlPath, 'ALTER TABLE public.messages DISABLE ROW LEVEL SECURITY;');
        fs.utimesSync(lockPath, pinned, pinned);
        fs.utimesSync(sqlPath, pinned, pinned);

        const cached = await buildProjectSecurityHints(root, 'src/a.js', ROUTE_FILE);
        expect(cached.dependencies).toEqual(['lodash@4.17.11']);
        expect(cached.databasePolicies).toHaveLength(2);

        const later = new Date('2026-01-02T00:00:00Z');
        fs.utimesSync(lockPath, later, later);
        fs.utimesSync(sqlPath, later, later);

        const fresh = await buildProjectSecurityHints(root, 'src/a.js', ROUTE_FILE);
        expect(fresh.dependencies).toEqual(['lodash@4.17.21']);
        expect(fresh.databasePolicies).toEqual(['ALTER TABLE public.messages DISABLE ROW LEVEL SECURITY;']);
    });

    it('swallows errors', async () => {
        fs.writeFileSync(path.join(root, 'package-lock.json'), '{not json');
        const hints = await buildProjectSecurityHints(root, 'src/a.js', ROUTE_FILE);
        expect(hints.dependencies).toBeUndefined();
        expect(hints.databasePolicies).toHaveLength(2);

        expect(await buildProjectSecurityHints(path.join(root, 'missing'), 'a.js', ROUTE_FILE)).toEqual({});
        expect(await buildProjectSecurityHints(root, 'a.js', undefined as unknown as string)).toEqual({});
    });

    it('resolves Python imports against Pipfile.lock', async () => {
        write(root, 'Pipfile.lock', JSON.stringify({ default: { pyyaml: { version: '==5.3' }, jinja2: { version: '==2.10' } }, develop: {} }));
        const hints = await buildProjectSecurityHints(root, 'app.py', 'from jinja2 import Template\nimport os\n');
        expect(hints.dependencies).toEqual(['jinja2@2.10']);
    });
});

describe('extractPolicyStatements', () => {
    it('extracts RLS, policy and grant statements with their tables', () => {
        const sql = [
            'ALTER TABLE ONLY "public"."notes" FORCE ROW LEVEL SECURITY;',
            '/* comment; with semicolon */ DROP POLICY IF EXISTS "x" ON notes;',
            'ALTER POLICY "y" ON public.notes USING (true);',
            'GRANT SELECT, INSERT ON TABLE public.notes, public.tags TO anon;',
            'GRANT USAGE ON SCHEMA public TO authenticated;',
            'GRANT ALL ON ALL TABLES IN SCHEMA public TO anon;',
            'GRANT SELECT ON public.notes TO service_role;',
            'ALTER TABLE public.notes ADD COLUMN x int;',
        ].join('\n');
        const out = extractPolicyStatements(sql);
        expect(out.map(s => s.tables)).toEqual([['notes'], ['notes'], ['notes'], ['notes', 'tags'], [], ['*']]);
        expect(out[1].text).toBe('DROP POLICY IF EXISTS "x" ON notes;');
    });
});
