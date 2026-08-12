import * as fs from 'fs';
import * as path from 'path';
import { ParsedLockfile, ResolvedPackage } from '../types';
import { normalizePipName } from './requirements';

/**
 * Parse a `Pipfile.lock` (Pipenv). It is a JSON document with two top-level
 * sections, `default` and `develop`, each keyed by package name with `version`
 * (without leading `==`) and optional `hashes`. Both sections contain the
 * resolved transitive tree, so we walk them and return everything.
 */
export function parsePipfileLock(lockfilePath: string): ParsedLockfile | null {
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
    if (!data || typeof data !== 'object') return null;

    const manifestPath = path.join(path.dirname(lockfilePath), 'Pipfile');
    let projectLicense: string | undefined;
    try {
        const pipfile = fs.readFileSync(manifestPath, 'utf8');
        // Pipfile is TOML; we don't depend on a TOML parser. Best-effort regex
        // for the top-level `license = "..."` line.
        const m = pipfile.match(/^\s*license\s*=\s*"([^"]+)"/m);
        if (m) projectLicense = m[1];
    } catch {
        // optional
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();

    for (const section of ['default', 'develop'] as const) {
        const deps: Record<string, any> | undefined = data[section];
        if (!deps || typeof deps !== 'object') continue;
        for (const [rawName, entry] of Object.entries(deps)) {
            const name = normalizePipName(rawName);
            const version: string | undefined = entry && typeof entry.version === 'string'
                ? entry.version.replace(/^==/, '')
                : undefined;
            if (!version) continue;
            const id = `${name}@${version}`;
            if (seen.has(id)) continue;
            seen.add(id);
            packages.push({
                ecosystem: 'pipenv',
                name,
                version,
                manifestPath,
                direct: section === 'default',
            });
        }
    }

    return {
        ecosystem: 'pipenv',
        lockfilePath,
        manifestPath,
        packages,
        projectLicense,
    };
}
