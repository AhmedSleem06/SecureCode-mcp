/**
 * Regression investigation seeds for the Synara project.
 *
 * Seeds are specific file ranges that MUST be investigated on every fresh
 * scan run. A seed does NOT mean "must report a vulnerability" — it means
 * "must read this range and record an investigation result (finding, note,
 * refutation, or coverage gap)."
 *
 * A missing seed range (one that was never read during the scan) is a
 * failed regression test — the scan was incomplete.
 */

export interface InvestigationSeed {
    file: string;
    startLine: number;
    endLine: number;
    concern: string;
    requiredEvidence: string[];
}

export const SYNARA_INVESTIGATION_SEEDS: InvestigationSeed[] = [
    {
        file: 'apps/server/src/http.ts',
        startLine: 280,
        endLine: 340,
        concern: 'legacy token authorization branch',
        requiredEvidence: [
            'Inspect auth token configuration',
            'Check loopback and remote exposure conditions',
            'Establish local-process threat model',
        ],
    },
    {
        file: 'apps/server/src/wsRpc.ts',
        startLine: 1080,
        endLine: 1140,
        concern: 'file operation RPC authorization',
        requiredEvidence: [
            'Trace method-level authorization',
            'Trace workspace ownership',
            'Verify unauthorized read/write behavior',
        ],
    },
    {
        file: 'apps/server/src/auth/Layers/ServerAuth.ts',
        startLine: 230,
        endLine: 270,
        concern: 'pairing credential role handling',
        requiredEvidence: [
            'Trace role input validation',
            'Verify owner/client role transition',
            'Run exact production import proof if possible',
        ],
    },
];

/**
 * Get the seeds that are applicable to a given target file.
 * A seed is applicable if the target file matches the seed file path
 * (case-insensitive, forward-slash normalized).
 */
export function getSeedsForTarget(targetFilePath: string): InvestigationSeed[] {
    const normalized = targetFilePath.replace(/\\/g, '/').toLowerCase();
    return SYNARA_INVESTIGATION_SEEDS.filter(s => {
        const seedPath = s.file.replace(/\\/g, '/').toLowerCase();
        return seedPath === normalized ||
            normalized.includes(seedPath) ||
            seedPath.includes(normalized);
    });
}

/**
 * Check which seeds were covered by the investigation state.
 * Returns the seeds that were NOT read (missing coverage).
 */
export function getMissingSeeds(
    targetFilePath: string,
    isCovered: (filePath: string, startLine?: number, endLine?: number) => boolean,
): InvestigationSeed[] {
    const applicable = getSeedsForTarget(targetFilePath);
    return applicable.filter(seed => !isCovered(seed.file, seed.startLine, seed.endLine));
}
