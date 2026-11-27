import * as fs from 'fs';
import { ParsedLockfile, ResolvedPackage } from '../types';

export function parsePubspecLock(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();
    let inPackages = false;
    let currentName = '';
    let currentVersion = '';

    for (const line of raw.split(/\r?\n/)) {
        if (line.match(/^packages:/)) {
            inPackages = true;
            continue;
        }
        if (!inPackages) continue;

        if (/^\S/.test(line) && !line.startsWith(' ')) {
            if (currentName && currentVersion) {
                const id = `${currentName}@${currentVersion}`;
                if (!seen.has(id)) {
                    seen.add(id);
                    packages.push({
                        ecosystem: 'pub',
                        name: currentName,
                        version: currentVersion,
                        manifestPath: lockfilePath,
                    });
                }
            }
            inPackages = false;
            continue;
        }

        const pkgMatch = line.match(/^\s{2}(\S+):$/);
        if (pkgMatch) {
            if (currentName && currentVersion) {
                const id = `${currentName}@${currentVersion}`;
                if (!seen.has(id)) {
                    seen.add(id);
                    packages.push({
                        ecosystem: 'pub',
                        name: currentName,
                        version: currentVersion,
                        manifestPath: lockfilePath,
                    });
                }
            }
            currentName = pkgMatch[1];
            currentVersion = '';
            continue;
        }

        const versionMatch = line.match(/^\s{4}version:\s*"?([^"\s]+)"?/);
        if (versionMatch) currentVersion = versionMatch[1];
    }
    if (currentName && currentVersion) {
        const id = `${currentName}@${currentVersion}`;
        if (!seen.has(id)) {
            seen.add(id);
            packages.push({
                ecosystem: 'pub',
                name: currentName,
                version: currentVersion,
                manifestPath: lockfilePath,
            });
        }
    }

    return {
        ecosystem: 'pub',
        lockfilePath,
        manifestPath: lockfilePath,
        packages,
    };
}
