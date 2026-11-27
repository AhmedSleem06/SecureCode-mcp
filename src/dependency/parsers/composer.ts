import * as fs from 'fs';
import { ParsedLockfile, ResolvedPackage } from '../types';

export function parseComposerLock(lockfilePath: string): ParsedLockfile | null {
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

    for (const section of ['packages', 'packages-dev'] as const) {
        const pkgs: any[] = data[section];
        if (!Array.isArray(pkgs)) continue;
        for (const pkg of pkgs) {
            const name: string | undefined = pkg?.name;
            let version: string | undefined = pkg?.version;
            if (!name || !version) continue;
            version = version.replace(/^v/, '');
            const id = `${name}@${version}`;
            if (seen.has(id)) continue;
            seen.add(id);
            packages.push({
                ecosystem: 'composer',
                name,
                version,
                manifestPath: lockfilePath,
                direct: section === 'packages',
            });
        }
    }

    return {
        ecosystem: 'composer',
        lockfilePath,
        manifestPath: lockfilePath,
        packages,
    };
}
