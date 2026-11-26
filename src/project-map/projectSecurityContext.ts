import * as fs from 'fs';
import * as path from 'path';
import { findLockfiles, parseLockfile } from '../dependency/resolver';

/**
 * Project facts the API's Juror needs to judge exploitability but cannot see
 * from one file: the installed versions of the packages the file imports
 * (`_.merge` is only exploitable on lodash < 4.17.12) and the RLS / grant
 * statements covering the tables the file queries (a Supabase query without an
 * owner filter is safe when a policy pins rows to `auth.uid()`).
 *
 * Sent as `workspaceHints.dependencies` / `workspaceHints.databasePolicies`.
 * Everything here is best-effort: any failure yields an empty result.
 */
export interface ProjectSecurityHints {
    dependencies?: string[];
    databasePolicies?: string[];
}

const MAX_DEPENDENCIES = 200;
const MAX_POLICIES = 60;
const MAX_POLICY_CHARS = 600;
const MAX_MIGRATION_FILES = 200;
const MAX_MIGRATION_BYTES = 2 * 1024 * 1024;
const LOCKFILE_DISCOVERY_TTL_MS = 30_000;

const JS_LOCKFILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);
const PY_LOCKFILES = new Set(['Pipfile.lock', 'requirements.txt']);

const lockfileDiscoveryCache = new Map<string, { at: number; paths: string[] }>();
const lockfileCache = new Map<string, { mtimeMs: number; versions: Map<string, string> }>();

interface PolicyStatement {
    text: string;
    /** Normalized table names; `*` for schema-wide grants. */
    tables: string[];
}
const migrationCache = new Map<string, { signature: string; statements: PolicyStatement[] }>();

export function clearProjectSecurityContextCache(): void {
    lockfileDiscoveryCache.clear();
    lockfileCache.clear();
    migrationCache.clear();
}

const normalizePackageName = (name: string): string => name.toLowerCase().replace(/_/g, '-');

const jsPackageRoot = (specifier: string): string | null => {
    const spec = specifier.trim();
    if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('#')) return null;
    if (/^[a-z]+:/i.test(spec)) return null;
    const parts = spec.split('/');
    if (spec.startsWith('@')) return parts.length >= 2 && parts[1] ? `${parts[0]}/${parts[1]}` : null;
    return parts[0] || null;
};

const JS_IMPORT_PATTERNS: RegExp[] = [
    /\brequire\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /\bimport\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
    /\b(?:import|export)\s[^'"`;]*?\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
];
const PY_FROM_IMPORT = /^[ \t]*from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b/gm;
const PY_IMPORT = /^[ \t]*import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*)[ \t]*(?:#.*)?$/gm;

/** Root package names the code imports (`lodash/merge` → `lodash`), normalized. */
export function extractImportedPackages(code: string): Set<string> {
    const out = new Set<string>();
    for (const pattern of JS_IMPORT_PATTERNS) {
        for (const match of code.matchAll(pattern)) {
            const root = jsPackageRoot(match[1]);
            if (root) out.add(normalizePackageName(root));
        }
    }
    for (const match of code.matchAll(PY_FROM_IMPORT)) {
        out.add(normalizePackageName(match[1].split('.')[0]));
    }
    for (const match of code.matchAll(PY_IMPORT)) {
        for (const part of match[1].split(',')) {
            const mod = part.trim().split(/\s+/)[0];
            if (mod) out.add(normalizePackageName(mod.split('.')[0]));
        }
    }
    return out;
}

const tableKey = (raw: string): string =>
    (raw.replace(/"/g, '').split('.').pop() || raw).trim().toLowerCase();

/** Tables the code references: Supabase `.from('t')` and SQL FROM/JOIN/INTO/UPDATE/TABLE. */
export function extractReferencedTables(code: string): Set<string> {
    const out = new Set<string>();
    const withoutPyImports = code.replace(/^[ \t]*from[ \t]+[\w.]+[ \t]+import\b.*$/gm, '');
    for (const match of withoutPyImports.matchAll(/(?<!Buffer|Array)\.from\(\s*['"`]([\w.]+)['"`]/g)) {
        out.add(tableKey(match[1]));
    }
    const sqlRef = /\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+(?:ONLY\s+)?(?:IF\s+(?:NOT\s+)?EXISTS\s+)?((?:\w+\.)?\w+)\b/gi;
    for (const match of withoutPyImports.matchAll(sqlRef)) {
        out.add(tableKey(match[1]));
    }
    return out;
}

const isPythonFile = (filePath: string): boolean => /\.pyi?$/i.test(filePath);

function discoverLockfiles(workspaceRoot: string): string[] {
    const cached = lockfileDiscoveryCache.get(workspaceRoot);
    if (cached && Date.now() - cached.at < LOCKFILE_DISCOVERY_TTL_MS) return cached.paths;
    const found = findLockfiles(workspaceRoot);
    const paths = [...found.npm, ...found.yarn, ...found.pnpm, ...found.pipenv, ...found.pip];
    lockfileDiscoveryCache.set(workspaceRoot, { at: Date.now(), paths });
    return paths;
}

/** normalized name → `name@version`, top-level installs preferred over nested ones. */
function lockfileVersions(lockfilePath: string): Map<string, string> {
    const mtimeMs = fs.statSync(lockfilePath).mtimeMs;
    const cached = lockfileCache.get(lockfilePath);
    if (cached && cached.mtimeMs === mtimeMs) return cached.versions;

    const versions = new Map<string, string>();
    const nested = new Set<string>();
    const parsed = parseLockfile(lockfilePath);
    for (const pkg of parsed?.packages ?? []) {
        if (pkg.unresolved || !pkg.version || !pkg.name) continue;
        const nm = pkg.name.lastIndexOf('node_modules/');
        const name = nm >= 0 ? pkg.name.slice(nm + 'node_modules/'.length) : pkg.name;
        const isNested = nm >= 0;
        const key = normalizePackageName(name);
        if (versions.has(key) && !(nested.has(key) && !isNested)) continue;
        versions.set(key, `${name}@${pkg.version.split('(')[0]}`);
        if (isNested) nested.add(key);
        else nested.delete(key);
    }
    lockfileCache.set(lockfilePath, { mtimeMs, versions });
    return versions;
}

function buildDependencies(workspaceRoot: string, absFilePath: string, fileContent: string): string[] {
    const imported = extractImportedPackages(fileContent);
    if (imported.size === 0) return [];

    const python = isPythonFile(absFilePath);
    const relevant = discoverLockfiles(workspaceRoot)
        .filter(p => (python ? PY_LOCKFILES : JS_LOCKFILES).has(path.basename(p)));
    if (relevant.length === 0) return [];

    const fileLower = absFilePath.toLowerCase();
    const isAncestor = (lockfile: string) => {
        const dir = path.dirname(lockfile).toLowerCase() + path.sep;
        return fileLower.startsWith(dir);
    };
    const ancestors = relevant.filter(isAncestor);
    const ordered = (ancestors.length > 0 ? ancestors : relevant)
        .sort((a, b) => path.dirname(b).length - path.dirname(a).length);

    const out: string[] = [];
    const pending = new Set(imported);
    for (const lockfile of ordered) {
        if (pending.size === 0) break;
        let versions: Map<string, string>;
        try {
            versions = lockfileVersions(lockfile);
        } catch {
            continue;
        }
        for (const name of [...pending]) {
            const entry = versions.get(name);
            if (!entry) continue;
            out.push(entry);
            pending.delete(name);
            if (out.length >= MAX_DEPENDENCIES) return out;
        }
    }
    return out;
}

function listMigrationFiles(workspaceRoot: string): string[] {
    const out: string[] = [];
    const walk = (dir: string, depth: number, accept: (name: string) => boolean) => {
        if (depth > 6 || out.length >= MAX_MIGRATION_FILES) return;
        let entries: fs.Dirent[];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            return;
        }
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const e of entries) {
            if (out.length >= MAX_MIGRATION_FILES) return;
            const full = path.join(dir, e.name);
            if (e.isDirectory()) walk(full, depth + 1, accept);
            else if (e.isFile() && accept(e.name)) out.push(full);
        }
    };
    const isSql = (name: string) => /\.sql$/i.test(name);
    walk(path.join(workspaceRoot, 'supabase', 'migrations'), 0, isSql);
    walk(path.join(workspaceRoot, 'migrations'), 0, isSql);
    walk(path.join(workspaceRoot, 'prisma', 'migrations'), 0, name => name === 'migration.sql');
    return out;
}

const POLICY_STATEMENT = new RegExp(
    '^(?:' + [
        'ALTER\\s+TABLE\\b[\\s\\S]*\\b(?:ENABLE|DISABLE|FORCE)\\s+ROW\\s+LEVEL\\s+SECURITY\\b',
        'CREATE\\s+POLICY\\b',
        'ALTER\\s+POLICY\\b',
        'DROP\\s+POLICY\\b',
        'GRANT\\b[\\s\\S]*\\bON\\b[\\s\\S]*\\bTO\\b[\\s\\S]*\\b(?:anon|authenticated|public)\\b',
    ].join('|') + ')',
    'i',
);

function statementTables(statement: string): string[] {
    if (/^ALTER\s+TABLE/i.test(statement)) {
        const m = statement.match(/^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w."]+)/i);
        return m ? [tableKey(m[1])] : [];
    }
    if (/^GRANT/i.test(statement)) {
        const m = statement.match(/\bON\s+([\s\S]+?)\s+TO\b/i);
        if (!m) return [];
        const target = m[1].trim();
        if (/^ALL\s+TABLES\s+IN\s+SCHEMA\b/i.test(target)) return ['*'];
        if (/^(?:ALL\s+\w+\s+IN\s+SCHEMA|FUNCTION|PROCEDURE|ROUTINE|SEQUENCE|SCHEMA|DATABASE|TYPE|DOMAIN|LANGUAGE|FOREIGN|LARGE|TABLESPACE)\b/i.test(target)) return [];
        return target.replace(/^TABLE\s+/i, '').split(',').map(t => tableKey(t)).filter(Boolean);
    }
    const m = statement.match(/\bON\s+(?:TABLE\s+)?([\w."]+)/i);
    return m ? [tableKey(m[1])] : [];
}

/** RLS / policy / grant statements in a migration file, whitespace-collapsed. */
export function extractPolicyStatements(sql: string): PolicyStatement[] {
    const withoutComments = sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, '');
    const out: PolicyStatement[] = [];
    for (const chunk of withoutComments.split(';')) {
        const statement = chunk.replace(/\s+/g, ' ').trim();
        if (!statement || !POLICY_STATEMENT.test(statement)) continue;
        const text = `${statement};`.slice(0, MAX_POLICY_CHARS);
        out.push({ text, tables: statementTables(statement) });
    }
    return out;
}

function migrationStatements(workspaceRoot: string): PolicyStatement[] {
    const files = listMigrationFiles(workspaceRoot);
    if (files.length === 0) return [];
    const stats = files.map(f => ({ file: f, stat: fs.statSync(f) }));
    const signature = stats.map(s => `${s.file}:${s.stat.mtimeMs}`).join('|');
    const cached = migrationCache.get(workspaceRoot);
    if (cached && cached.signature === signature) return cached.statements;

    const statements: PolicyStatement[] = [];
    let bytes = 0;
    for (const { file, stat } of stats) {
        if (bytes + stat.size > MAX_MIGRATION_BYTES) break;
        bytes += stat.size;
        try {
            statements.push(...extractPolicyStatements(fs.readFileSync(file, 'utf8')));
        } catch {
            // Unreadable migration: skip it.
        }
    }
    migrationCache.set(workspaceRoot, { signature, statements });
    return statements;
}

function buildDatabasePolicies(workspaceRoot: string, fileContent: string): string[] {
    const tables = extractReferencedTables(fileContent);
    if (tables.size === 0) return [];
    const statements = migrationStatements(workspaceRoot);
    if (statements.length === 0) return [];
    const specific = statements.filter(s => s.tables.some(t => tables.has(t)));
    if (specific.length === 0) return [];
    const selected = statements.filter(s => s.tables.includes('*') || s.tables.some(t => tables.has(t)));
    return [...new Set(selected.map(s => s.text))].slice(-MAX_POLICIES);
}

export async function buildProjectSecurityHints(
    workspaceRoot: string,
    filePath: string,
    fileContent: string,
): Promise<ProjectSecurityHints> {
    if (!workspaceRoot || !filePath || typeof fileContent !== 'string' || !fileContent) return {};
    const absFilePath = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);

    let dependencies: string[] = [];
    try {
        dependencies = buildDependencies(workspaceRoot, absFilePath, fileContent);
    } catch {
        dependencies = [];
    }
    let databasePolicies: string[] = [];
    try {
        databasePolicies = buildDatabasePolicies(workspaceRoot, fileContent);
    } catch {
        databasePolicies = [];
    }
    return {
        ...(dependencies.length > 0 && { dependencies }),
        ...(databasePolicies.length > 0 && { databasePolicies }),
    };
}
