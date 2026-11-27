import { describe, it, expect } from 'vitest';
import { computeMinSafeVersion } from '../src/dependency/minSafeVersion';
import type { ResolvedPackage, Vulnerability } from '../src/dependency/types';

function pkg(name: string, version: string, ecosystem: ResolvedPackage['ecosystem'] = 'npm'): ResolvedPackage {
    return { ecosystem, name, version };
}

function vuln(id: string, ranges: Array<{ introduced?: string; fixed?: string; lastAffected?: string }>, eco: string = 'npm'): Vulnerability {
    return {
        id,
        source: 'osv',
        sources: ['osv'],
        summary: '',
        affected: ranges.map(r => ({
            ecosystem: eco as any,
            introduced: r.introduced,
            fixed: r.fixed,
            lastAffected: r.lastAffected,
        })),
    };
}

describe('computeMinSafeVersion — iterative range-exit', () => {
    it('lodash 4.17.15: single range 0..4.17.21 → 4.17.21', () => {
        const v = vuln('GHSA-1', [{ introduced: '0', fixed: '4.17.21' }]);
        expect(computeMinSafeVersion(pkg('lodash', '4.17.15'), [v])).toBe('4.17.21');
    });

    it('lodash 4.17.15 with extra range to 4.18.0 → 4.18.0', () => {
        const v1 = vuln('GHSA-1', [{ introduced: '0', fixed: '4.17.21' }]);
        const v2 = vuln('GHSA-2', [{ introduced: '4.0.0', fixed: '4.18.0' }]);
        expect(computeMinSafeVersion(pkg('lodash', '4.17.15'), [v1, v2])).toBe('4.18.0');
    });

    it('minimist 1.2.0: two ranges → 1.2.6', () => {
        const v1 = vuln('GHSA-1', [{ introduced: '0', fixed: '0.2.1' }, { introduced: '1.0.0', fixed: '1.2.6' }]);
        const v2 = vuln('GHSA-2', [{ introduced: '0', fixed: '0.2.4' }, { introduced: '1.0.0', fixed: '1.2.6' }]);
        expect(computeMinSafeVersion(pkg('minimist', '1.2.0'), [v1, v2])).toBe('1.2.6');
    });

    it('branch case: 2.2.x fixes exist for some but others only fix in 3.x → 3.x', () => {
        const v1 = vuln('GHSA-A', [{ introduced: '2.0', fixed: '2.2.28' }], 'PyPI');
        const v2 = vuln('GHSA-B', [{ introduced: '2.0', fixed: '2.2.25' }], 'PyPI');
        const v3 = vuln('GHSA-C', [{ introduced: '2.0', fixed: '3.0.1' }], 'PyPI');
        const result = computeMinSafeVersion(pkg('django', '2.2.0', 'pip'), [v1, v2, v3]);
        expect(result).toBe('3.0.1');
    });

    it('no fix: a range with no fixed version → undefined', () => {
        const v = vuln('GHSA-1', [{ introduced: '0' }]);
        expect(computeMinSafeVersion(pkg('test', '1.0.0'), [v])).toBeUndefined();
    });

    it('mixed: some ranges have fix, one has no fix → undefined', () => {
        const v1 = vuln('GHSA-1', [{ introduced: '0', fixed: '1.5.0' }]);
        const v2 = vuln('GHSA-2', [{ introduced: '1.0.0' }]);
        expect(computeMinSafeVersion(pkg('test', '1.0.0'), [v1, v2])).toBeUndefined();
    });

    it('already safe: current version above all ranges → undefined (no upgrade needed)', () => {
        const v = vuln('GHSA-1', [{ introduced: '0', fixed: '1.0.0' }]);
        expect(computeMinSafeVersion(pkg('test', '2.0.0'), [v])).toBeUndefined();
    });

    it('python: picks smallest version above all ranges', () => {
        const v1 = vuln('GHSA-A', [{ introduced: '2.2', fixed: '2.2.28' }], 'PyPI');
        const v2 = vuln('GHSA-B', [{ introduced: '2.2', fixed: '2.2.25' }], 'PyPI');
        const result = computeMinSafeVersion(pkg('django', '2.2.0', 'pip'), [v1, v2]);
        expect(result).toBe('2.2.28');
    });

    it('cascading: fix of one range lands inside another → continues to next fix', () => {
        const v1 = vuln('GHSA-1', [{ introduced: '1.0.0', fixed: '1.5.0' }]);
        const v2 = vuln('GHSA-2', [{ introduced: '1.3.0', fixed: '1.8.0' }]);
        const result = computeMinSafeVersion(pkg('test', '1.2.0'), [v1, v2]);
        expect(result).toBe('1.8.0');
    });

    it('filters out non-version fix strings (commit hashes)', () => {
        const v = vuln('GHSA-1', [{ introduced: '0', fixed: 'abc123def456' }]);
        expect(computeMinSafeVersion(pkg('test', '1.0.0'), [v])).toBeUndefined();
    });

    it('lastAffected: range with no fix but lastAffected below current → not affected', () => {
        const v1 = vuln('GHSA-1', [{ introduced: '0', fixed: '4.17.21' }]);
        const v2 = vuln('GHSA-2', [{ introduced: '4.0.0', lastAffected: '4.5.1' }]);
        const result = computeMinSafeVersion(pkg('lodash', '4.17.15'), [v1, v2]);
        expect(result).toBe('4.17.21');
    });

    it('lastAffected: range with no fix and lastAffected above current → no fix', () => {
        const v = vuln('GHSA-1', [{ introduced: '1.0.0', lastAffected: '2.0.0' }]);
        expect(computeMinSafeVersion(pkg('test', '1.5.0'), [v])).toBeUndefined();
    });
});
