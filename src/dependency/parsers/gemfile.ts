import * as fs from 'fs';
import { ParsedLockfile, ResolvedPackage } from '../types';

export function parseGemfileLock(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();
    let inSpecs = false;

    for (const line of raw.split(/\r?\n/)) {
        if (/^\s{2}specs:/.test(line) || line.trim() === 'specs:') {
            inSpecs = true;
            continue;
        }
        if (inSpecs && /^\S/.test(line)) {
            inSpecs = false;
        }
        if (!inSpecs) continue;

        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (!match) continue;
        const name = match[1];
        const version = match[2];
        const id = `${name}@${version}`;
        if (seen.has(id)) continue;
        seen.add(id);
        packages.push({
            ecosystem: 'rubygems',
            name,
            version,
            manifestPath: lockfilePath,
        });
    }

    return {
        ecosystem: 'rubygems',
        lockfilePath,
        manifestPath: lockfilePath,
        packages,
    };
}
