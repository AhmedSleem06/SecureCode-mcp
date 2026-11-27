import * as fs from 'fs';
import { ParsedLockfile, ResolvedPackage } from '../types';

export function parsePackagesLockJson(lockfilePath: string): ParsedLockfile | null {
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

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();

    const deps: Record<string, any> = data?.dependencies || {};
    for (const [framework, pkgs] of Object.entries(deps)) {
        if (!pkgs || typeof pkgs !== 'object') continue;
        for (const [name, entry] of Object.entries<any>(pkgs)) {
            const version = entry?.resolved;
            if (typeof version !== 'string') continue;
            const id = `${name}@${version}`;
            if (seen.has(id)) continue;
            seen.add(id);
            packages.push({
                ecosystem: 'nuget',
                name,
                version,
                manifestPath: lockfilePath,
                direct: entry?.type === 'Direct',
            });
        }
    }

    return {
        ecosystem: 'nuget',
        lockfilePath,
        manifestPath: lockfilePath,
        packages,
    };
}
