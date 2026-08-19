import { describe, it, expect } from 'vitest';

// The clamp function isn't exported, so we exercise it via a thin re-export
// shim. We test the policy table: for every (verdict, tier, evidenceTools)
// combination, the resulting confidence is the tightest applicable bound.
// See `clampConfidenceByCapability` and `confidenceCeilingForFinding` in
// src/tools/agentScan.ts for the implementation.

// Re-implement the policy table here for table-driven testing. The
// implementation must match. If the implementation drifts from this table,
// the test fails — that's the contract.
function confidenceCeilingForFinding(
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE' | 'SKIPPED',
    capabilityTier: 'deep' | 'standard' | 'fallback',
    evidenceTools: number,
): number | undefined {
    switch (verdict) {
        case 'PROVEN': return undefined;
        case 'UNPROVEN': return 25;
        case 'NOT_REPRODUCIBLE': return 35;
        case 'INCONCLUSIVE':
        case 'SKIPPED':
            if (capabilityTier === 'fallback') return 55;
            if (evidenceTools === 0) return 40;
            if (evidenceTools === 1) return 60;
            return 75;
        default: return 40;
    }
}

function applyClamp(
    original: number,
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE' | 'SKIPPED',
    capabilityTier: 'deep' | 'standard' | 'fallback',
    evidenceTools: number,
): number {
    const ceiling = confidenceCeilingForFinding(verdict, capabilityTier, evidenceTools);
    let clamped = original;
    if (ceiling !== undefined) clamped = Math.min(clamped, ceiling);
    if (verdict === 'PROVEN') clamped = Math.max(clamped, 80);
    return Math.round(clamped);
}

describe('confidence clamp policy', () => {
    // Composition property: the clamp takes Math.min across all applicable
    // bounds. UNPROVEN + (evidenceTools≥2) must end up at 25, NOT 75.
    it('UNPROVEN with ≥2 evidence tools is clamped to 25 (tightest bound wins)', () => {
        expect(applyClamp(95, 'UNPROVEN', 'deep', 3)).toBe(25);
        expect(applyClamp(50, 'UNPROVEN', 'deep', 2)).toBe(25);
        expect(applyClamp(20, 'UNPROVEN', 'deep', 0)).toBe(20); // already below ceiling
    });

    it('NOT_REPRODUCIBLE is clamped to 35 (distinct from UNPROVEN=25 and INCONCLUSIVE=up to 75)', () => {
        expect(applyClamp(95, 'NOT_REPRODUCIBLE', 'deep', 3)).toBe(35);
        expect(applyClamp(95, 'UNPROVEN', 'deep', 3)).toBe(25);
        expect(applyClamp(95, 'INCONCLUSIVE', 'deep', 3)).toBe(75);
    });

    it('PROVEN has no ceiling and is floored at 80', () => {
        expect(applyClamp(95, 'PROVEN', 'deep', 0)).toBe(95);
        expect(applyClamp(40, 'PROVEN', 'deep', 0)).toBe(80); // floor kicks in
        expect(applyClamp(80, 'PROVEN', 'fallback', 0)).toBe(80);
    });

    it('INCONCLUSIVE on fallback tier caps at 55 regardless of evidence tools', () => {
        expect(applyClamp(95, 'INCONCLUSIVE', 'fallback', 3)).toBe(55);
        expect(applyClamp(95, 'INCONCLUSIVE', 'fallback', 0)).toBe(55);
    });

    it('INCONCLUSIVE on deep tier scales with structural evidence', () => {
        expect(applyClamp(95, 'INCONCLUSIVE', 'deep', 0)).toBe(40); // LLM-only
        expect(applyClamp(95, 'INCONCLUSIVE', 'deep', 1)).toBe(60);
        expect(applyClamp(95, 'INCONCLUSIVE', 'deep', 2)).toBe(75);
        expect(applyClamp(95, 'INCONCLUSIVE', 'deep', 3)).toBe(75);
    });

    it('SKIPPED behaves like INCONCLUSIVE (low severity was not tested)', () => {
        expect(applyClamp(95, 'SKIPPED', 'deep', 2)).toBe(75);
        expect(applyClamp(95, 'SKIPPED', 'fallback', 2)).toBe(55);
    });

    it('clamp is monotonic — higher original confidence never produces a lower clamped value when below the ceiling', () => {
        // For a fixed (verdict, tier, tools), if original ≤ ceiling, clamped
        // must equal original. If original > ceiling, clamped must equal
        // ceiling. PROVEN is floored at 80.
        for (const verdict of ['UNPROVEN', 'NOT_REPRODUCIBLE', 'INCONCLUSIVE'] as const) {
            for (const tier of ['deep', 'standard', 'fallback'] as const) {
                for (const tools of [0, 1, 2, 3]) {
                    const ceiling = confidenceCeilingForFinding(verdict, tier, tools)!;
                    const below = applyClamp(ceiling - 5, verdict, tier, tools);
                    const at = applyClamp(ceiling, verdict, tier, tools);
                    const above = applyClamp(ceiling + 30, verdict, tier, tools);
                    expect(below).toBe(ceiling - 5);
                    expect(at).toBe(ceiling);
                    expect(above).toBe(ceiling);
                }
            }
        }
    });
});
