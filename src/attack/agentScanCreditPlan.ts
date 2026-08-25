/**
 * Pure credit cost calculator for agent scan batch workflows.
 *
 * Calculates the total scan credits required for a batch run:
 *   architecture scout + N × agent scan + optional verification reserve
 *
 * Policies:
 *   base-only            — architecture + agent scans only
 *   verification-bounded — adds a per-file verification credit reserve
 *   Batch default: verification-bounded with a 10-credit-per-file cap.
 *
 * Fix reserve is always zero — the batch tool disables fix generation.
 */

import { AGENT_SCAN_DEFAULTS } from './agentScanProtocol';
import { scoutDefaultsForDepth } from './architectureScoutProtocol';
import type { ArchitectureDepth } from '../project-map/architectureContext';

export type CreditPlanPolicy = 'base-only' | 'verification-bounded';

export interface CreditPlanOptions {
    depth: ArchitectureDepth;
    architectureCacheHit: boolean;
    uncachedFileCount: number;
    cachedFileCount: number;
    policy?: CreditPlanPolicy;
    verificationCreditsPerFile?: number;
}

export interface CreditPlan {
    architectureCredits: number;
    agentRunCredits: number;
    verificationCredits: number;
    fixReserveCredits: number;
    total: number;
    breakdown: {
        depth: ArchitectureDepth;
        architectureCacheHit: boolean;
        uncachedFiles: number;
        cachedFiles: number;
        policy: CreditPlanPolicy;
        verificationCreditsPerFile: number;
        creditsPerRun: number;
    };
}

const DEFAULT_VERIFICATION_CREDITS_PER_FILE = 10;
const MAX_VERIFICATION_CREDITS_PER_FILE = 60;

export function calculateBatchCredits(options: CreditPlanOptions): CreditPlan {
    const policy: CreditPlanPolicy = options.policy ?? 'verification-bounded';
    const verificationCreditsPerFile = Math.min(
        MAX_VERIFICATION_CREDITS_PER_FILE,
        options.verificationCreditsPerFile ?? DEFAULT_VERIFICATION_CREDITS_PER_FILE,
    );

    const architectureCredits = options.architectureCacheHit
        ? 0
        : scoutDefaultsForDepth(options.depth).creditsPerRun;

    const agentRunCredits = options.uncachedFileCount * AGENT_SCAN_DEFAULTS.creditsPerRun;

    const verificationCredits = policy === 'verification-bounded'
        ? options.uncachedFileCount * verificationCreditsPerFile
        : 0;

    const fixReserveCredits = 0;

    const total = architectureCredits + agentRunCredits + verificationCredits + fixReserveCredits;

    return {
        architectureCredits,
        agentRunCredits,
        verificationCredits,
        fixReserveCredits,
        total,
        breakdown: {
            depth: options.depth,
            architectureCacheHit: options.architectureCacheHit,
            uncachedFiles: options.uncachedFileCount,
            cachedFiles: options.cachedFileCount,
            policy,
            verificationCreditsPerFile,
            creditsPerRun: AGENT_SCAN_DEFAULTS.creditsPerRun,
        },
    };
}
