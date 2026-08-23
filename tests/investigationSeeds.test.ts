import { describe, it, expect } from 'vitest';
import {
    SYNARA_INVESTIGATION_SEEDS,
    getSeedsForTarget,
    getMissingSeeds,
    type InvestigationSeed,
} from './fixtures/investigationSeeds';
import { InvestigationState } from '../src/attack/investigationState';

describe('Investigation Seeds', () => {
    it('defines seeds for three critical Synara files', () => {
        expect(SYNARA_INVESTIGATION_SEEDS.length).toBeGreaterThanOrEqual(3);
        const files = SYNARA_INVESTIGATION_SEEDS.map(s => s.file);
        expect(files).toContain('apps/server/src/http.ts');
        expect(files).toContain('apps/server/src/wsRpc.ts');
        expect(files).toContain('apps/server/src/auth/Layers/ServerAuth.ts');
    });

    it('each seed has required evidence', () => {
        for (const seed of SYNARA_INVESTIGATION_SEEDS) {
            expect(seed.requiredEvidence.length).toBeGreaterThan(0);
            expect(seed.concern).toBeTruthy();
        }
    });

    it('getSeedsForTarget matches by file path', () => {
        const seeds = getSeedsForTarget('apps/server/src/http.ts');
        expect(seeds).toHaveLength(1);
        expect(seeds[0].concern).toBe('legacy token authorization branch');
    });

    it('getSeedsForTarget is case-insensitive', () => {
        const seeds = getSeedsForTarget('apps/server/src/HTTP.ts');
        expect(seeds.length).toBeGreaterThanOrEqual(1);
    });

    it('getSeedsForTarget normalizes backslashes', () => {
        const seeds = getSeedsForTarget('apps\\server\\src\\http.ts');
        expect(seeds.length).toBeGreaterThanOrEqual(1);
    });

    it('getSeedsForTarget returns empty for unrelated file', () => {
        const seeds = getSeedsForTarget('src/utils/helper.ts');
        expect(seeds).toHaveLength(0);
    });

    it('getMissingSeeds returns seeds not covered', () => {
        const state = new InvestigationState();
        state.recordActualRead('apps/server/src/http.ts', 280, 340, 500, false);

        const missing = getMissingSeeds('apps/server/src/http.ts', (f, s, e) =>
            state.isCovered(f, s, e),
        );
        expect(missing).toHaveLength(0);
    });

    it('getMissingSeeds returns seeds with partial coverage', () => {
        const state = new InvestigationState();
        state.recordActualRead('apps/server/src/http.ts', 280, 300, 500, false);

        const missing = getMissingSeeds('apps/server/src/http.ts', (f, s, e) =>
            state.isCovered(f, s, e),
        );
        expect(missing).toHaveLength(1);
    });

    it('getMissingSeeds returns all seeds when nothing is covered', () => {
        const state = new InvestigationState();
        const missing = getMissingSeeds('apps/server/src/http.ts', (f, s, e) =>
            state.isCovered(f, s, e),
        );
        expect(missing).toHaveLength(1);
    });

    it('a seed range fully within a larger read is covered', () => {
        const state = new InvestigationState();
        state.recordActualRead('apps/server/src/http.ts', 250, 350, 500, false);

        const missing = getMissingSeeds('apps/server/src/http.ts', (f, s, e) =>
            state.isCovered(f, s, e),
        );
        expect(missing).toHaveLength(0);
    });
});
