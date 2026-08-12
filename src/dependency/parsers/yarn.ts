import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYarnLock, LockFileObject, FirstLevelDependency } from '@yarnpkg/lockfile';
import { ParsedLockfile, ResolvedPackage } from '../types';

/**
 * Parse a yarn v1 `yarn.lock` (the classic format). v2+ (Berry) uses a
 * different text format and is NOT covered here — we deliberately bail in
 * that case so the caller can skip the file gracefully.
 *
 * yarn v1 lockfiles contain the resolved transitive tree: every package
 * entry has a `version` and a `resolved` URL, including transitive deps.
 */
export function parseYarnLockfile(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }

    // Detect Yarn Berry (v2+) which uses a different format. The classic
    // parser will produce garbage on it, so bail.
    if (raw.includes('__metadata:')) {
        return null;
    }

    let parsed: { type: 'success' | 'merge' | 'conflict'; object: LockFileObject };
    try {
        parsed = parseYarnLock(raw);
    } catch {
        return null;
    }
    if (!parsed || parsed.type !== 'success') {
        // 'merge' / 'conflict' lockfiles are not directly usable.
        return null;
    }

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

    // Collect direct dependency names from package.json so we can flag direct vs transitive.
    const directNames = new Set<string>();
    try {
        const pkg = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        for (const k of Object.keys(pkg.dependencies || {})) directNames.add(k);
        for (const k of Object.keys(pkg.devDependencies || {})) directNames.add(k);
        for (const k of Object.keys(pkg.optionalDependencies || {})) directNames.add(k);
    } catch {
        // optional
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();
    const obj = parsed.object as Record<string, FirstLevelDependency>;
    for (const [key, entry] of Object.entries(obj)) {
        // Key looks like "@scope/name@version, @scope/name@npm:^1.2.3, ..."
        // The actual package name is everything up to the last "@" that
        // is not part of a scoped leading "@". We pull the canonical name
        // from the entry itself when possible (yarn exposes `name` only in
        // some versions), otherwise from the key.
        const name = extractYarnName(key);
        const version = entry.version;
        if (!name || !version) continue;
        const id = `${name}@${version}`;
        if (seen.has(id)) continue;
        seen.add(id);
        packages.push({
            ecosystem: 'yarn',
            name,
            version,
            manifestPath,
            direct: directNames.has(name),
        });
    }

    return {
        ecosystem: 'yarn',
        lockfilePath,
        manifestPath,
        packages,
        projectLicense,
    };
}

/**
 * Extract the package name from a yarn lockfile key.
 * Examples:
 *   "lodash@^4.17.19"                       -> "lodash"
 *   "@babel/core@^7.0.0"                    -> "@babel/core"
 *   "lodash@npm:^4.17.19, lodash@^4.17.20"  -> "lodash"
 */
function extractYarnName(key: string): string | undefined {
    const first = key.split(',')[0].trim();
    // For scoped: leading "@" then name then "@version"
    if (first.startsWith('@')) {
        const at = first.indexOf('@', 1);
        if (at < 0) return undefined;
        return first.slice(0, at);
    }
    const at = first.indexOf('@');
    if (at < 0) return undefined;
    return first.slice(0, at);
}
