/**
 * Pure credit cost calculator for agent scan batch workflows.
 *
 * Calculates the total scan credits required for a batch run:
 *   architecture scout + N × agent scan part + optional verification reserve
 *
 * Policies:
 *   base-only            — architecture + agent scans only
 *   verification-bounded — adds a per-file verification credit reserve
 *   Batch default: base-only. Verification draws from each scan's own
 *   budget (5 credits, extended 2 at a time up to 15), so the plan reserves
 *   5 per file part and reports the 15-per-part ceiling as maxTotal.
 *   Files over the segment threshold are scanned in parts; every part is
 *   its own run with the same 5–15 credit rules.
 *
 * Fix reserve is always zero — the batch tool disables fix generation.
 */

import { AGENT_SCAN_DEFAULTS, SEGMENT_THRESHOLD_LINES } from './agentScanProtocol';
import { scoutDefaultsForDepth } from './architectureScoutProtocol';
import type { ArchitectureDepth } from '../project-map/architectureContext';

export type CreditPlanPolicy = 'base-only' | 'verification-bounded';

export interface CreditPlanFileParts {
    filePath: string;
    parts: number;
}

export interface CreditPlanOptions {
    depth: ArchitectureDepth;
    architectureCacheHit: boolean;
    uncachedFileCount: number;
    cachedFileCount: number;
    policy?: CreditPlanPolicy;
    verificationCreditsPerFile?: number;
    fileParts?: CreditPlanFileParts[];
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
        totalParts: number;
        files?: CreditPlanFileParts[];
    };
}

const DEFAULT_VERIFICATION_CREDITS_PER_FILE = 10;
const MAX_VERIFICATION_CREDITS_PER_FILE = 60;

function plural(n: number, word: string): string {
    return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export function calculateBatchCredits(options: CreditPlanOptions): CreditPlan {
    const policy: CreditPlanPolicy = options.policy ?? 'base-only';
    const verificationCreditsPerFile = Math.min(
        MAX_VERIFICATION_CREDITS_PER_FILE,
        options.verificationCreditsPerFile ?? DEFAULT_VERIFICATION_CREDITS_PER_FILE,
    );

    const architectureCredits = options.architectureCacheHit
        ? 0
        : scoutDefaultsForDepth(options.depth).creditsPerRun;

    const fileParts = options.fileParts?.map(f => ({ filePath: f.filePath, parts: Math.max(1, Math.floor(f.parts || 1)) }));
    const knownFiles = fileParts?.length ?? 0;
    const totalParts = (fileParts ?? []).reduce((s, f) => s + f.parts, 0)
        + Math.max(0, options.uncachedFileCount - knownFiles);

    const agentRunCredits = totalParts * AGENT_SCAN_DEFAULTS.creditsPerRun;

    const verificationCredits = policy === 'verification-bounded'
        ? options.uncachedFileCount * verificationCreditsPerFile
        : 0;

    const fixReserveCredits = 0;

    const total = architectureCredits + agentRunCredits + verificationCredits + fixReserveCredits;
    const maxTotal = Math.max(
        total,
        architectureCredits + totalParts * AGENT_SCAN_DEFAULTS.maxCreditsPerRun,
    );

    const splitFiles = (fileParts ?? []).filter(f => f.parts > 1);
    let warning: string | undefined;
    if (options.uncachedFileCount > 0) {
        if (splitFiles.length > 0) {
            const list = splitFiles.map(f => `${f.filePath} ${f.parts} parts`).join(', ');
            warning = `Planned ${AGENT_SCAN_DEFAULTS.creditsPerRun} credits per file part (${plural(totalParts, 'part')} across ${plural(options.uncachedFileCount, 'file')}, ${total} total). Files over ${SEGMENT_THRESHOLD_LINES.toLocaleString('en-US')} lines are scanned in parts: ${list}. Each part can use up to ${AGENT_SCAN_DEFAULTS.maxCreditsPerRun} credits (up to ${maxTotal} total); unused extension credits are refunded.`;
        } else {
            warning = `Planned ${AGENT_SCAN_DEFAULTS.creditsPerRun} credits per file (${total} total). Large files can use up to ${AGENT_SCAN_DEFAULTS.maxCreditsPerRun} credits each (up to ${maxTotal} total); unused extension credits are refunded.`;
        }
    }

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
            totalParts,
            ...(fileParts ? { files: fileParts } : {}),
        },
    };
}
