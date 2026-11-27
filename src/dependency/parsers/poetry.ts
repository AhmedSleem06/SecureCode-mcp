import * as fs from 'fs';
import { ParsedLockfile, ResolvedPackage } from '../types';
import { normalizePipName } from './requirements';

export function parsePoetryLock(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();
    let currentName = '';
    let currentVersion = '';

    for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed === '[[package]]') {
            if (currentName && currentVersion) {
                const name = normalizePipName(currentName);
                const id = `${name}@${currentVersion}`;
                if (!seen.has(id)) {
                    seen.add(id);
                    packages.push({
                        ecosystem: 'pip',
                        name,
                        version: currentVersion,
                        manifestPath: lockfilePath,
                    });
                }
            }
            currentName = '';
            currentVersion = '';
            continue;
        }
        const nameMatch = trimmed.match(/^name\s*=\s*"([^"]+)"/);
        if (nameMatch) { currentName = nameMatch[1]; continue; }
        const versionMatch = trimmed.match(/^version\s*=\s*"([^"]+)"/);
        if (versionMatch) currentVersion = versionMatch[1];
    }
    if (currentName && currentVersion) {
        const name = normalizePipName(currentName);
        const id = `${name}@${currentVersion}`;
        if (!seen.has(id)) {
            seen.add(id);
            packages.push({
                ecosystem: 'pip',
                name,
                version: currentVersion,
                manifestPath: lockfilePath,
            });
        }
    }

    return {
        ecosystem: 'pip',
        lockfilePath,
        manifestPath: lockfilePath,
        packages,
    };
}
