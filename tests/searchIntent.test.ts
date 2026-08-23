import { describe, it, expect } from 'vitest';
import { normalizeSearchPattern, isEquivalentSearchIntent } from '../src/attack/searchIntent';

describe('normalizeSearchPattern', () => {
    it('lowercases the pattern', () => {
        expect(normalizeSearchPattern('RequireOwner')).toBe('requireowner');
    });

    it('sorts alternatives alphabetically', () => {
        expect(normalizeSearchPattern('zebra|apple|mango')).toBe('apple|mango|zebra');
    });

    it('deduplicates alternatives', () => {
        expect(normalizeSearchPattern('foo|bar|foo|bar')).toBe('bar|foo');
    });

    it('handles single term', () => {
        expect(normalizeSearchPattern('isProjectOwner')).toBe('isprojectowner');
    });

    it('handles empty string', () => {
        expect(normalizeSearchPattern('')).toBe('');
    });

    it('trims whitespace', () => {
        expect(normalizeSearchPattern('  foo  ')).toBe('foo');
    });

    it('trims alternatives', () => {
        expect(normalizeSearchPattern('  foo  |  bar  ')).toBe('bar|foo');
    });

    it('filters empty alternatives', () => {
        expect(normalizeSearchPattern('foo|||bar')).toBe('bar|foo');
    });
});

describe('isEquivalentSearchIntent', () => {
    it('detects identical patterns', () => {
        expect(isEquivalentSearchIntent('requireOwner', 'requireOwner')).toBe(true);
    });

    it('detects reordered alternatives as equivalent', () => {
        expect(isEquivalentSearchIntent(
            'requireOwner|CurrentWsSessionRole',
            'CurrentWsSessionRole|requireOwner',
        )).toBe(true);
    });

    it('detects subset as equivalent (current is subset of previous)', () => {
        expect(isEquivalentSearchIntent(
            'requireOwner|CurrentWsSessionRole|isLoopbackHost',
            'requireOwner|CurrentWsSessionRole',
        )).toBe(true);
    });

    it('detects subset as equivalent (previous is subset of current)', () => {
        expect(isEquivalentSearchIntent(
            'requireOwner|CurrentWsSessionRole',
            'requireOwner|CurrentWsSessionRole|isLoopbackHost',
        )).toBe(true);
    });

    it('detects case-insensitive equivalence', () => {
        expect(isEquivalentSearchIntent('RequireOwner', 'requireowner')).toBe(true);
    });

    it('detects non-equivalent patterns', () => {
        expect(isEquivalentSearchIntent('requireOwner', 'isLoopbackHost')).toBe(false);
    });

    it('detects partially overlapping patterns as non-equivalent', () => {
        expect(isEquivalentSearchIntent(
            'requireOwner|isLoopbackHost',
            'requireOwner|checkAuth',
        )).toBe(false);
    });
});
