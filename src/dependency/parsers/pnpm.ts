import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';
import { ParsedLockfile, ResolvedPackage } from '../types';

/**
 * Parse a pnpm-lock.yaml (v6+).
 *
 * pnpm lockfiles contain the resolved transitive tree under `packages`,
 * keyed as `<name>@<version>` (with optional peer suffixes). We walk that
 * section. Importers (`importers`) tell us which deps are direct; we use
 * it to flag direct vs transitive, but every package ends up in the list
 * regardless (transitive deps need scanning too).
 */
export function parsePnpmLockfile(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }
    let data: any;
    try {
        data = parseYaml(raw);
    } catch {
        return null;
    }
    if (!data || typeof data !== 'object') return null;

    const manifestPath = path.join(path.dirname(lockfilePath), 'package.json');
    let projectLicense: string | undefined;
    try {
        const pkg = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        if (typeof pkg.license === 'string') projectLicense = pkg.license;
        else if (pkg.license && typeof pkg.license === 'object' && typeof pkg.license.type === 'string') {
            projectLicense = pkg.license.type;
        }
    } catch {
        // optional
    }

    // Collect direct dependency names from the lockfile's `importers` section
    // (more reliable than reading package.json for pnpm, since pnpm prunes).
    const directKeys = new Set<string>();
    const importers: Record<string, any> = data.importers || {};
    for (const importer of Object.values(importers)) {
        for (const cat of ['dependencies', 'devDependencies', 'optionalDependencies']) {
            const deps = importer?.[cat];
            if (deps && typeof deps === 'object') {
                for (const name of Object.keys(deps)) directKeys.add(name);
            }
        }
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();
    const pkgSection: Record<string, any> = data.packages || {};
    for (const key of Object.keys(pkgSection)) {
        const entry = pkgSection[key];
        // pnpm v6+: key like "lodash@4.17.19" or "/lodash/4.17.19"
        // v9+: key like "lodash@4.17.19(peerdeps...)"
        const { name, version } = parsePnpmPkgKey(key);
        if (!name || !version) continue;
        const id = `${name}@${version}`;
        if (seen.has(id)) continue;
        seen.add(id);
        packages.push({
            ecosystem: 'pnpm',
            name,
            version,
            manifestPath,
            direct: directKeys.has(name),
        });
    }

    return {
        ecosystem: 'pnpm',
        lockfilePath,
        manifestPath,
        packages,
        projectLicense,
    };
}

/**
 * Parse a pnpm `packages.<key>` entry. Supported forms:
 *   "lodash@4.17.19"
 *   "/lodash/4.17.19"          (older)
 *   "@babel/core@7.0.0"
 *   "lodash@4.17.19(react@18)" (peer-suffixed; we strip the parens)
 */
function parsePnpmPkgKey(key: string): { name: string; version: string } {
    // Strip peer suffix in parens.
    const parenIdx = key.indexOf('(');
    let k = parenIdx >= 0 ? key.slice(0, parenIdx) : key;
    k = k.trim();
    if (k.startsWith('/')) k = k.slice(1);
    // For scoped: leading "@" then name then "@version"
    if (k.startsWith('@')) {
        const at = k.indexOf('@', 1);
        if (at < 0) return { name: '', version: '' };
        return { name: k.slice(0, at), version: k.slice(at + 1) };
    }
    const at = k.indexOf('@');
    if (at < 0) return { name: '', version: '' };
    return { name: k.slice(0, at), version: k.slice(at + 1) };
}
