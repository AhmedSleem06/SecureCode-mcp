import * as fs from 'fs';
import * as path from 'path';
import { ParsedLockfile, ResolvedPackage } from '../types';

/**
 * Parse a `requirements.txt` file.
 *
 * Supported pins:
 *   name==1.2.3
 *   name>=1.2.3
 *   name~=1.2.3
 *   name>1.0,<2.0
 *   name (unpinned — marked unresolved)
 *
 * `#`-comments, blank lines, `-r other.txt`, `-e .`, and VCS/URL specs are
 * skipped (URL specs are treated as unpinned/unresolved under the package
 * name extracted from the URL when possible, otherwise skipped entirely).
 *
 * IMPORTANT: no network calls are made. When a pin is not an exact `==`,
 * the entry is marked `unresolved` and surfaced to the user as such rather
 * than queried against OSV (since the installed version is unknown). A
 * Pipfile.lock alongside the requirements.txt will be preferred when
 * present (handled by the resolver/dependencyChecker, not here).
 */
export function parseRequirementsTxt(lockfilePath: string): ParsedLockfile | null {
    let raw: string;
    try {
        raw = fs.readFileSync(lockfilePath, 'utf8');
    } catch {
        return null;
    }

    const manifestPath = lockfilePath; // requirements.txt IS the manifest
    const packages: ResolvedPackage[] = [];
    const seen = new Set<string>();

    for (const line of raw.split(/\r?\n/)) {
        let s = line.trim();
        if (!s) continue;
        // Strip inline comment.
        const hash = s.indexOf('#');
        if (hash >= 0) s = s.slice(0, hash).trim();
        if (!s) continue;

        // Skip option lines and recursive includes; we don't follow them.
        if (s.startsWith('-')) continue;
        if (s.startsWith('-e ') || s.startsWith('--')) continue;

        // Skip VCS / URL specs entirely (we cannot resolve them offline).
        // Examples: git+https://..., https://..., file:///...
        if (/^[a-z]+(\+[a-z]+)?:\/\//i.test(s)) continue;

        // Strip environment markers: "name==1.0 ; python_version>='3.8'"
        const semi = s.indexOf(';');
        if (semi >= 0) s = s.slice(0, semi).trim();
        if (!s) continue;

        // Strip extras: "name[extra1,extra2]==1.0"
        const nameMatch = s.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/);
        if (!nameMatch) continue;
        const rawName = nameMatch[1];
        const spec = (nameMatch[3] || '').trim();
        const name = normalizePipName(rawName);

        if (seen.has(name)) continue;
        seen.add(name);

        // Exact pin: "name==1.2.3"
        const exact = spec.match(/^==\s*([A-Za-z0-9_.!+*-]+)$/);
        if (exact) {
            packages.push({
                ecosystem: 'pip',
                name,
                version: exact[1],
                manifestPath,
                direct: true,
            });
            continue;
        }

        // Range pins (>=, >, ~=, <=, <, comma-separated): unresolved.
        if (spec && /([<>=~!]=?)/.test(spec)) {
            packages.push({
                ecosystem: 'pip',
                name,
                version: spec, // best-effort: keep the spec for display
                manifestPath,
                direct: true,
                unresolved: true,
            });
            continue;
        }

        // Bare "name" (no pin): unresolved.
        if (!spec) {
            packages.push({
                ecosystem: 'pip',
                name,
                version: '',
                manifestPath,
                direct: true,
                unresolved: true,
            });
            continue;
        }
    }

    return {
        ecosystem: 'pip',
        lockfilePath,
        manifestPath,
        packages,
    };
}

/** Normalize a PyPI package name per PEP 503 (lowercase, runs of [-_.] -> "-"). */
export function normalizePipName(name: string): string {
    return name.toLowerCase().replace(/[-_.]+/g, '-');
}
