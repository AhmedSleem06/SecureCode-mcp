import { describe, it, expect } from 'vitest';
import { calculateBatchCredits } from '../src/attack/agentScanCreditPlan';

describe('calculateBatchCredits', () => {
    it('charges 5 credits for quick architecture', () => {
        const plan = calculateBatchCredits({
            depth: 'quick',
            architectureCacheHit: false,
            uncachedFileCount: 0,
            cachedFileCount: 0,
            policy: 'base-only',
        });
        expect(plan.architectureCredits).toBe(5);
    });

    it('charges 10 credits for standard architecture', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: false,
            uncachedFileCount: 0,
            cachedFileCount: 0,
            policy: 'base-only',
        });
        expect(plan.architectureCredits).toBe(10);
    });

    it('charges 20 credits for deep architecture', () => {
        const plan = calculateBatchCredits({
            depth: 'deep',
            architectureCacheHit: false,
            uncachedFileCount: 0,
            cachedFileCount: 0,
            policy: 'base-only',
        });
        expect(plan.architectureCredits).toBe(20);
    });

    it('charges 0 for cached architecture', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 3,
            cachedFileCount: 0,
            policy: 'base-only',
        });
        expect(plan.architectureCredits).toBe(0);
    });

    it('charges 5 credits per uncached agent scan', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 3,
            cachedFileCount: 0,
            policy: 'base-only',
        });
        expect(plan.agentRunCredits).toBe(15);
    });

    it('charges 0 for cached completed files', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 0,
            cachedFileCount: 3,
            policy: 'base-only',
        });
        expect(plan.agentRunCredits).toBe(0);
    });

    it('base-only policy has no verification credits', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 3,
            cachedFileCount: 0,
            policy: 'base-only',
        });
        expect(plan.verificationCredits).toBe(0);
    });

    it('verification-bounded adds per-file verification reserve', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 3,
            cachedFileCount: 0,
            policy: 'verification-bounded',
            verificationCreditsPerFile: 10,
        });
        expect(plan.verificationCredits).toBe(30);
    });

    it('default policy is verification-bounded with 10 per file', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 2,
            cachedFileCount: 0,
        });
        expect(plan.verificationCredits).toBe(20);
        expect(plan.breakdown.policy).toBe('verification-bounded');
        expect(plan.breakdown.verificationCreditsPerFile).toBe(10);
    });

    it('fix reserve is always zero', () => {
        const plan = calculateBatchCredits({
            depth: 'deep',
            architectureCacheHit: false,
            uncachedFileCount: 5,
            cachedFileCount: 0,
        });
        expect(plan.fixReserveCredits).toBe(0);
    });

    it('total is sum of all components', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: false,
            uncachedFileCount: 3,
            cachedFileCount: 0,
            policy: 'verification-bounded',
            verificationCreditsPerFile: 10,
        });
        expect(plan.total).toBe(10 + 15 + 30 + 0);
    });

    it('total is integer-valued', () => {
        const plan = calculateBatchCredits({
            depth: 'deep',
            architectureCacheHit: false,
            uncachedFileCount: 7,
            cachedFileCount: 2,
        });
        expect(Number.isInteger(plan.total)).toBe(true);
    });

    it('caps verificationCreditsPerFile at 60', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 1,
            cachedFileCount: 0,
            verificationCreditsPerFile: 100,
        });
        expect(plan.breakdown.verificationCreditsPerFile).toBe(60);
        expect(plan.verificationCredits).toBe(60);
    });

    it('counts only uncached files for agent runs and verification', () => {
        const plan = calculateBatchCredits({
            depth: 'standard',
            architectureCacheHit: true,
            uncachedFileCount: 2,
            cachedFileCount: 3,
            policy: 'verification-bounded',
            verificationCreditsPerFile: 10,
        });
        expect(plan.agentRunCredits).toBe(10);
        expect(plan.verificationCredits).toBe(20);
    });
});
