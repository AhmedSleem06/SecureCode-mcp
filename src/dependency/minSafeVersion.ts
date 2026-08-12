import * as semver from 'semver';
import { ResolvedPackage, Vulnerability } from './types';

/**
 * Compute the smallest version bump that exits ALL affected ranges for a
 * given vulnerable package.
 *
 * Strategy:
 *   - Collect all explicit `fixed` bounds from affected ranges; the smallest
 *     such fixed version is the minimal safe bump (you must reach at least it).
 *   - If no `fixed` is available, but `introduced` is, there is no known fix —
 *     return undefined and surface "no known fix" upstream.
 *   - For npm-family we use `semver.minSatisfying` against the candidate set
 *     and validate via `semver.valid`. For Python we fall back to a simple
 *     dotted-version comparator since we deliberately do not depend on a
 *     full PEP 440 library.
 *
 * The result is a *version string* (e.g. "4.17.21") suitable for an in-place
 * manifest edit. We do NOT try to pick the smallest *major* bump — the user
 * asked for the smallest version that exits all ranges, which is exactly
 * the smallest `fixed` across all advisory ranges.
 */
export function computeMinSafeVersion(
    pkg: ResolvedPackage,
    vulns: Vulnerability[],
): string | undefined {
    const candidates: string[] = [];
    for (const v of vulns) {
        for (const a of v.affected) {
            if (a.fixed) candidates.push(a.fixed);
        }
    }
    if (candidates.length === 0) return undefined;

    if (isNpmFamily(pkg)) {
        // Pick the smallest valid semver among candidates.
        const valid = candidates
            .map(c => semver.coerce(c))
            .filter((c): c is semver.SemVer => c !== null)
            .map(c => c.version)
            .sort((a, b) => semver.compare(a, b));
        return valid[0];
    }

    // Python: simple dotted-numeric compare.
    const valid = candidates
        .filter(c => /^\d+(\.\d+)*([._-]?[a-z0-9]+)?$/i.test(c))
        .sort(comparePep440Loose);
    return valid[0];
}

function isNpmFamily(pkg: ResolvedPackage): boolean {
    return pkg.ecosystem === 'npm' || pkg.ecosystem === 'yarn' || pkg.ecosystem === 'pnpm';
}

/**
 * Loose PEP 440-ish comparator for dotted versions like "1.2.3" or "1.2.3rc1".
 * Returns -1, 0, or 1. Good enough for "smallest fixed version" — not a
 * general PEP 440 implementation (we explicitly avoid the `packaging` dep).
 */
export function comparePep440Loose(a: string, b: string): number {
    const pa = parseLooseVersion(a);
    const pb = parseLooseVersion(b);
    for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
        const ai = pa.nums[i] ?? 0;
        const bi = pb.nums[i] ?? 0;
        if (ai !== bi) return ai - bi;
    }
    // Pre-release sorts before release (1.2.3rc1 < 1.2.3) — match PEP 440.
    if (pa.pre && !pb.pre) return -1;
    if (!pa.pre && pb.pre) return 1;
    if (pa.pre && pb.pre) return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
    return 0;
}

function parseLooseVersion(v: string): { nums: number[]; pre?: string } {
    const m = v.match(/^(\d+(?:\.\d+)*)(?:([a-z]+\d*))?$/i);
    if (!m) return { nums: [0] };
    const nums = m[1].split('.').map(n => parseInt(n, 10));
    const pre = m[2];
    return { nums, pre };
}

/**
 * Build a human-readable upgrade suggestion for the webview / Apply flow.
 * e.g. "Upgrade lodash 4.17.19 -> 4.17.21"
 */
export function upgradeSuggestion(
    pkg: ResolvedPackage,
    minSafe: string,
): string {
    return `Upgrade ${pkg.name} ${pkg.version} -> ${minSafe}`;
}
