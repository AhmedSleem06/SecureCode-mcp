/**
 * Pure credit cost calculator for agent scan batch workflows.
 *
 * Calculates the total scan credits required for a batch run:
 *   architecture scout + N × agent scan + optional verification reserve
 *
 * Policies:
 *   base-only            — architecture + agent scans only
 *   verification-bounded — adds a per-file verification credit reserve
 *   Batch default: base-only. Verification draws from each scan's own
 *   budget (5 credits, extended 2 at a time up to 15), so the plan reserves
 *   5 per file and reports the 15-per-file ceiling as maxTotal.
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
    maxTotal: number;
    warning?: string;
    breakdown: {
        depth: ArchitectureDepth;
        architectureCacheHit: boolean;
        uncachedFiles: number;
        cachedFiles: number;
        policy: CreditPlanPolicy;
        verificationCreditsPerFile: number;
        creditsPerRun: number;
        maxCreditsPerRun: number;
    };
}

const DEFAULT_VERIFICATION_CREDITS_PER_FILE = 10;
const MAX_VERIFICATION_CREDITS_PER_FILE = 60;

export function calculateBatchCredits(options: CreditPlanOptions): CreditPlan {
    const policy: CreditPlanPolicy = options.policy ?? 'base-only';
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
    const maxTotal = Math.max(
        total,
        architectureCredits + options.uncachedFileCount * AGENT_SCAN_DEFAULTS.maxCreditsPerRun,
    );

    const warning = options.uncachedFileCount > 0
        ? `Planned ${AGENT_SCAN_DEFAULTS.creditsPerRun} credits per file (${total} total). Large files can use up to ${AGENT_SCAN_DEFAULTS.maxCreditsPerRun} credits each (up to ${maxTotal} total); unused extension credits are refunded.`
        : undefined;

    return {
        architectureCredits,
        agentRunCredits,
        verificationCredits,
        fixReserveCredits,
        total,
        maxTotal,
        ...(warning ? { warning } : {}),
        breakdown: {
            depth: options.depth,
            architectureCacheHit: options.architectureCacheHit,
            uncachedFiles: options.uncachedFileCount,
            cachedFiles: options.cachedFileCount,
            policy,
            verificationCreditsPerFile,
            creditsPerRun: AGENT_SCAN_DEFAULTS.creditsPerRun,
            maxCreditsPerRun: AGENT_SCAN_DEFAULTS.maxCreditsPerRun,
        },
    };
}
