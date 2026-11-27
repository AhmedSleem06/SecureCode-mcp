import * as fs from 'fs';
import * as path from 'path';
import { ParsedLockfile, ResolvedPackage, Ecosystem } from './types';
import { parseNpmLockfile } from './parsers/npm';
import { parseYarnLockfile } from './parsers/yarn';
import { parsePnpmLockfile } from './parsers/pnpm';
import { parseRequirementsTxt } from './parsers/requirements';
import { parsePipfileLock } from './parsers/pipfile';
import { parseGoMod } from './parsers/gomod';
import { parseCargoLock } from './parsers/cargo';
import { parseGemfileLock } from './parsers/gemfile';
import { parseComposerLock } from './parsers/composer';
import { parsePoetryLock } from './parsers/poetry';
import { parseUvLock } from './parsers/uv';
import { parsePackagesLockJson } from './parsers/nuget';
import { parsePubspecLock } from './parsers/pubspec';

/**
 * The "resolver". For npm/yarn/pnpm/Pipfile.lock the lockfile ALREADY contains
 * the fully-resolved transitive tree, so resolving = walking it (no network).
 * For requirements.txt with no lockfile, entries are already individual; we
 * just propagate `unresolved` flags so the checker can surface them instead
 * of querying OSV with a version we don't actually know.
 *
 * This module is also responsible for finding lockfiles in the workspace.
 */

const LOCKFILE_NAMES: Array<{ name: string; ecosystem: Ecosystem }> = [
    { name: 'package-lock.json', ecosystem: 'npm' },
    { name: 'yarn.lock', ecosystem: 'yarn' },
    { name: 'pnpm-lock.yaml', ecosystem: 'pnpm' },
    { name: 'Pipfile.lock', ecosystem: 'pipenv' },
    { name: 'requirements.txt', ecosystem: 'pip' },
    { name: 'go.mod', ecosystem: 'go' },
    { name: 'Cargo.lock', ecosystem: 'cargo' },
    { name: 'Gemfile.lock', ecosystem: 'rubygems' },
    { name: 'composer.lock', ecosystem: 'composer' },
    { name: 'poetry.lock', ecosystem: 'pip' },
    { name: 'uv.lock', ecosystem: 'pip' },
    { name: 'packages.lock.json', ecosystem: 'nuget' },
    { name: 'pubspec.lock', ecosystem: 'pub' },
];

export interface WorkspaceLockfiles {
    npm: string[];
    yarn: string[];
    pnpm: string[];
    pipenv: string[];
    pip: string[];
    go: string[];
    cargo: string[];
    rubygems: string[];
    composer: string[];
    nuget: string[];
    pub: string[];
}

/**
 * Walk the workspace looking for known lockfiles. Skips `node_modules`,
 * `.git`, `.venv`, `venv`, and `dist` to avoid duplicate hits from
 * vendored deps.
 */
export function findLockfiles(workspaceRoot: string): WorkspaceLockfiles {
    const out: WorkspaceLockfiles = {
        npm: [], yarn: [], pnpm: [], pipenv: [], pip: [],
        go: [], cargo: [], rubygems: [], composer: [], nuget: [], pub: [],
    };
    const skip = new Set(['node_modules', '.git', '.venv', 'venv', 'env', 'dist', 'build', '.next', '.turbo']);

    const walk = (dir: string, depth: number) => {
        if (depth > 8) return;
        let entries: fs.Dirent[];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            return;
        }
        for (const e of entries) {
            const full = path.join(dir, e.name);
            if (e.isDirectory()) {
                if (skip.has(e.name)) continue;
                walk(full, depth + 1);
            } else if (e.isFile()) {
                for (const lf of LOCKFILE_NAMES) {
                    if (e.name === lf.name) {
                        out[lf.ecosystem].push(full);
                        break;
                    }
                }
            }
        }
    };
    walk(workspaceRoot, 0);

    // De-duplicate by directory+ecosystem (a project should only have one
    // lockfile per ecosystem per folder, but monorepos can have several).
    const dedup = (arr: string[]) => Array.from(new Set(arr));
    for (const key of Object.keys(out) as Array<keyof WorkspaceLockfiles>) {
        out[key] = dedup(out[key]);
    }
    return out;
}

/** Parse a single lockfile path into a ParsedLockfile (or null). */
export function parseLockfile(lockfilePath: string): ParsedLockfile | null {
    const base = path.basename(lockfilePath);
    switch (base) {
        case 'package-lock.json':
            return parseNpmLockfile(lockfilePath);
        case 'yarn.lock':
            return parseYarnLockfile(lockfilePath);
        case 'pnpm-lock.yaml':
            return parsePnpmLockfile(lockfilePath);
        case 'Pipfile.lock':
            return parsePipfileLock(lockfilePath);
        case 'requirements.txt':
            return parseRequirementsTxt(lockfilePath);
        case 'go.mod':
            return parseGoMod(lockfilePath);
        case 'Cargo.lock':
            return parseCargoLock(lockfilePath);
        case 'Gemfile.lock':
            return parseGemfileLock(lockfilePath);
        case 'composer.lock':
            return parseComposerLock(lockfilePath);
        case 'poetry.lock':
            return parsePoetryLock(lockfilePath);
        case 'uv.lock':
            return parseUvLock(lockfilePath);
        case 'packages.lock.json':
            return parsePackagesLockJson(lockfilePath);
        case 'pubspec.lock':
            return parsePubspecLock(lockfilePath);
        default:
            return null;
    }
}

/**
 * Resolve the full transitive dependency set across all parsed lockfiles.
 *
 * The "resolution" is essentially deduplication:
 *   - Same (ecosystem-family, name, version) seen in two lockfiles is reported once.
 *   - `family` collapses npm/yarn/pnpm into one (they share the npm registry)
 *     so a dep found in both package-lock.json and yarn.lock is not queried twice.
 *   - pip/pipenv are similarly collapsed into one PyPI family.
 *
 * Returns the flat list of resolved packages ready for OSV batching.
 */
export function resolveAll(parsed: ParsedLockfile[]): ResolvedPackage[] {
    const familyOf = (e: Ecosystem): string => {
        switch (e) {
            case 'npm': case 'yarn': case 'pnpm': return 'npm';
            case 'pip': case 'pipenv': return 'pypi';
            case 'go': return 'go';
            case 'cargo': return 'cargo';
            case 'rubygems': return 'rubygems';
            case 'composer': return 'composer';
            case 'nuget': return 'nuget';
            case 'pub': return 'pub';
            default: return e;
        }
    };
    const seen = new Set<string>();
    const out: ResolvedPackage[] = [];

    for (const lf of parsed) {
        if (!lf) continue;
        for (const pkg of lf.packages) {
            // For npm-family, names are case-sensitive on disk but the registry
            // treats them case-insensitively for lookup; normalize to lower for
            // dedup so we don't double-query OSV.
            const fam = familyOf(pkg.ecosystem);
            const nameKey = fam === 'npm' ? pkg.name : pkg.name.toLowerCase();
            const id = `${fam}:${nameKey}@${pkg.version || 'unknown'}`;
            if (seen.has(id)) continue;
            seen.add(id);
            out.push(pkg);
        }
    }
    return out;
}
