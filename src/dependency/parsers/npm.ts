import * as fs from 'fs';
import * as path from 'path';
import { ParsedLockfile, ResolvedPackage } from '../types';

/**
 * Parse a package-lock.json (npm v2/v3, lockfileVersion >= 2).
 *
 * npm lockfiles already contain the fully-resolved transitive tree — every
 * installed package (direct and transitive) is a `packages.*` entry with a
 * resolved `version`. The resolver therefore does not need to hit the
 * network; it just walks `packages`.
 *
 * v1 (lockfileVersion 1) uses a `dependencies` tree instead; we support it
 * too, recursively.
 */
export function parseNpmLockfile(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }
    let data: any;
    try {
        data = JSON.parse(raw);
    } catch {
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
        // package.json optional; ignore
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();

    const lockfileVersion: number = typeof data.lockfileVersion === 'number' ? data.lockfileVersion : 0;

    if (lockfileVersion >= 2 && data.packages) {
        // v2/v3: keyed by install path, `node_modules/<name>`.
        for (const [key, entry] of Object.entries<any>(data.packages)) {
            // The root project itself is keyed by "" — skip it.
            if (key === '') continue;
            // Extract the package name from the path. Scoped packages live at
            // `node_modules/@scope/name`. Optional deps may have their own paths.
            const nmIdx = key.indexOf('node_modules/');
            if (nmIdx < 0) continue;
            const name = key.slice(nmIdx + 'node_modules/'.length);
            // Nested node_modules paths (e.g. "node_modules/a/node_modules/b")
            // describe a deduped alternative install; the canonical entry is the
            // top-level one. We keep the first occurrence per name+version.
            if (entry.link === true) continue; // symlinked, not a real install
            const version: string | undefined = entry.version;
            if (!version) continue;
            const id = `${name}@${version}`;
            if (seen.has(id)) continue;
            seen.add(id);
            packages.push({
                ecosystem: 'npm',
                name,
                version,
                license: typeof entry.license === 'string' ? entry.license : undefined,
                manifestPath,
                direct: entry.dev === undefined && entry.optional === undefined
                    ? isDirectNpm(key)
                    : false,
            });
        }
    } else if (data.dependencies) {
        // v1: recursive `dependencies` tree.
        walkNpmV1(data.dependencies, '', manifestPath, packages, seen);
    }

    return {
        ecosystem: 'npm',
        lockfilePath,
        manifestPath,
        packages,
        projectLicense,
    };
}

function walkNpmV1(
    deps: Record<string, any>,
    parentPath: string,
    manifestPath: string,
    out: ResolvedPackage[],
    seen: Set<string>,
) {
    for (const [name, entry] of Object.entries(deps || {})) {
        const version: string | undefined = entry && entry.version;
        if (!version) continue;
        const id = `${name}@${version}`;
        if (!seen.has(id)) {
            seen.add(id);
            out.push({
                ecosystem: 'npm',
                name,
                version,
                license: entry && typeof entry.license === 'string' ? entry.license : undefined,
                manifestPath,
                direct: parentPath === '',
            });
        }
        if (entry && entry.dependencies) {
            walkNpmV1(entry.dependencies, `${parentPath}${name}/`, manifestPath, out, seen);
        }
    }
}

/**
 * Best-effort: did this `packages` key correspond to a top-level dependency?
 * Top-level keys look exactly like `node_modules/<name>` (no nested node_modules).
 */
function isDirectNpm(key: string): boolean {
    const nmIdx = key.indexOf('node_modules/');
    const tail = key.slice(nmIdx + 'node_modules/'.length);
    return !tail.includes('node_modules/');
}
