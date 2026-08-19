import { describe, it, expect } from 'vitest';
import { confidenceCeilingForFinding, applyConfidenceClamp } from '../src/tools/agentScan';

describe('confidence clamp policy', () => {
    it('UNPROVEN with ≥2 evidence tools is clamped to 25 (tightest bound wins)', () => {
        expect(applyConfidenceClamp(95, 'UNPROVEN', 'deep', 3)).toBe(25);
        expect(applyConfidenceClamp(50, 'UNPROVEN', 'deep', 2)).toBe(25);
        expect(applyConfidenceClamp(20, 'UNPROVEN', 'deep', 0)).toBe(20);
    });

    it('NOT_REPRODUCIBLE is clamped to 35 (distinct from UNPROVEN=25 and INCONCLUSIVE=up to 75)', () => {
        expect(applyConfidenceClamp(95, 'NOT_REPRODUCIBLE', 'deep', 3)).toBe(35);
        expect(applyConfidenceClamp(95, 'UNPROVEN', 'deep', 3)).toBe(25);
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'deep', 3)).toBe(75);
    });

    it('PROVEN has no ceiling and is floored at 80', () => {
        expect(applyConfidenceClamp(95, 'PROVEN', 'deep', 0)).toBe(95);
        expect(applyConfidenceClamp(40, 'PROVEN', 'deep', 0)).toBe(80);
        expect(applyConfidenceClamp(80, 'PROVEN', 'fallback', 0)).toBe(80);
    });

    it('INCONCLUSIVE on fallback tier caps at 55 regardless of evidence tools', () => {
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'fallback', 3)).toBe(55);
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'fallback', 0)).toBe(55);
    });

    it('INCONCLUSIVE on deep tier scales with structural evidence', () => {
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'deep', 0)).toBe(40);
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'deep', 1)).toBe(60);
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'deep', 2)).toBe(75);
        expect(applyConfidenceClamp(95, 'INCONCLUSIVE', 'deep', 3)).toBe(75);
    });

    it('SKIPPED behaves like INCONCLUSIVE (low severity was not tested)', () => {
        expect(applyConfidenceClamp(95, 'SKIPPED', 'deep', 2)).toBe(75);
        expect(applyConfidenceClamp(95, 'SKIPPED', 'fallback', 2)).toBe(55);
    });

    it('clamp is monotonic — higher original confidence never produces a lower clamped value when below the ceiling', () => {
        for (const verdict of ['UNPROVEN', 'NOT_REPRODUCIBLE', 'INCONCLUSIVE'] as const) {
            for (const tier of ['deep', 'standard', 'fallback'] as const) {
                for (const tools of [0, 1, 2, 3]) {
                    const ceiling = confidenceCeilingForFinding(verdict, tier, tools)!;
                    const below = applyConfidenceClamp(ceiling - 5, verdict, tier, tools);
                    const at = applyConfidenceClamp(ceiling, verdict, tier, tools);
                    const above = applyConfidenceClamp(ceiling + 30, verdict, tier, tools);
                    expect(below).toBe(ceiling - 5);
                    expect(at).toBe(ceiling);
                    expect(above).toBe(ceiling);
                }
            }
        }
    });
});
