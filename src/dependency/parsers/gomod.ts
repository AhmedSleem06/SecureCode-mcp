import * as fs from 'fs';
import { ParsedLockfile, ResolvedPackage } from '../types';

export function parseGoMod(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }

    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();
    let inRequire = false;

    for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed === 'require (') {
            inRequire = true;
            continue;
        }
        if (trimmed === ')') {
            inRequire = false;
            continue;
        }

        let match: RegExpMatchArray | null = null;
        if (inRequire) {
            match = trimmed.match(/^([^\s]+)\s+(v[^\s]+)/);
        } else if (trimmed.startsWith('require ')) {
            match = trimmed.match(/^require\s+([^\s]+)\s+(v[^\s]+)/);
        }
        if (!match) continue;

        const name = match[1];
        const version = match[2].replace(/^v/, '');
        const id = `${name}@${version}`;
        if (seen.has(id)) continue;
        seen.add(id);
        packages.push({
            ecosystem: 'go',
            name,
            version,
            manifestPath: lockfilePath,
            direct: true,
        });
    }

    return {
        ecosystem: 'go',
        lockfilePath,
        manifestPath: lockfilePath,
        packages,
    };
}
