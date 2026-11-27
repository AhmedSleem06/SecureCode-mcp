import * as semver from 'semver';
import { ResolvedPackage, Vulnerability, AffectedRange } from './types';

export function computeMinSafeVersion(
    pkg: ResolvedPackage,
    vulns: Vulnerability[],
): string | undefined {
    const ecoFamily = ecosystemFamily(pkg.ecosystem);
    const ranges: Array<{ introduced?: string; fixed?: string; lastAffected?: string }> = [];
    for (const v of vulns) {
        for (const a of v.affected) {
            if (a.raw) {
                try {
                    const parsed = JSON.parse(a.raw);
                    if (parsed.type === 'GIT') continue;
                } catch {}
            }
            if (ecoFamily && a.ecosystem && ecosystemFamily(a.ecosystem) !== ecoFamily) continue;
            ranges.push({
                introduced: a.introduced,
                fixed: a.fixed && /^\d/.test(a.fixed) ? a.fixed : undefined,
                lastAffected: a.lastAffected,
            });
        }
    }
    if (ranges.length === 0) return undefined;

    const cmp = isNpmFamily(pkg) ? compareSemver : comparePep440Loose;

    let candidate = pkg.version;
    for (let iter = 0; iter < 200; iter++) {
        let advanced = false;
        for (const r of ranges) {
            if (!isInRange(candidate, r, cmp)) continue;
            if (!r.fixed) return undefined;
            if (cmp(r.fixed, candidate) > 0) {
                candidate = r.fixed;
                advanced = true;
            }
        }
        if (!advanced) break;
    }

    if (cmp(candidate, pkg.version) <= 0) {
        return undefined;
    }
    return candidate;
}

function ecosystemFamily(eco: string): string {
    switch (eco) {
        case 'npm': case 'yarn': case 'pnpm': return 'npm';
        case 'pip': case 'pipenv': case 'PyPI': return 'pypi';
        case 'go': case 'Go': return 'go';
        case 'cargo': case 'crates.io': return 'cargo';
        case 'rubygems': case 'RubyGems': return 'rubygems';
        case 'composer': case 'Packagist': return 'composer';
        case 'nuget': case 'NuGet': return 'nuget';
        case 'pub': case 'Pub': return 'pub';
        default: return eco.toLowerCase();
    }
}

function isInRange(
    version: string,
    range: { introduced?: string; fixed?: string; lastAffected?: string },
    cmp: (a: string, b: string) => number,
): boolean {
    if (range.introduced && range.introduced !== '0') {
        if (cmp(version, range.introduced) < 0) return false;
    }
    if (range.fixed) {
        if (cmp(version, range.fixed) >= 0) return false;
    }
    if (!range.fixed && range.lastAffected) {
        if (cmp(version, range.lastAffected) > 0) return false;
    }
    return true;
}

function compareSemver(a: string, b: string): number {
    const sa = semver.coerce(a);
    const sb = semver.coerce(b);
    if (!sa || !sb) return comparePep440Loose(a, b);
    return semver.compare(sa, sb);
}

function isNpmFamily(pkg: ResolvedPackage): boolean {
    return pkg.ecosystem === 'npm' || pkg.ecosystem === 'yarn' || pkg.ecosystem === 'pnpm'
        || pkg.ecosystem === 'cargo' || pkg.ecosystem === 'nuget' || pkg.ecosystem === 'pub';
}

export function comparePep440Loose(a: string, b: string): number {
    const pa = parseLooseVersion(a);
    const pb = parseLooseVersion(b);
    for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
        const ai = pa.nums[i] ?? 0;
        const bi = pb.nums[i] ?? 0;
        if (ai !== bi) return ai - bi;
    }
    if (pa.pre && !pb.pre) return -1;
    if (!pa.pre && pb.pre) return 1;
    if (pa.pre && pb.pre) return pa.pre < pb.pre ? -1 : pa.pre > pb.pre ? 1 : 0;
    return 0;
}

function parseLooseVersion(v: string): { nums: number[]; pre?: string } {
    const m = v.match(/^(\d+(?:\.\d+)*)(?:[._-]?([a-z]+\d*))?$/i);
    if (!m) return { nums: [0] };
    const nums = m[1].split('.').map(n => parseInt(n, 10));
    const pre = m[2];
    return { nums, pre };
}

export function upgradeSuggestion(
    pkg: ResolvedPackage,
    minSafe: string,
): string {
    return `Upgrade ${pkg.name} ${pkg.version} -> ${minSafe}`;
}
