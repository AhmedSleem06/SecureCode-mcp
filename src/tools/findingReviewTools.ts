/**
 * MCP tools for the finding review queue — list uncertain findings, decide
 * them (confirmed/rejected/deferred), and clear resolved items.
 *
 * When the verify subagent returns INCONCLUSIVE, the finding is added to a
 * non-blocking local review queue. The user can later adjudicate each item:
 *   - confirmed  → the user agrees the finding is real
 *   - rejected   → the user considers it a false positive (also recorded in
 *                  agent memory so future scans skip it)
 *   - deferred   → leave it unresolved for later
 *
 * Storage: <workspaceRoot>/.securecode/finding-review-queue.json (per-workspace)
 * Privacy: no source code or evidence strings are stored — only hashes,
 *          file paths, line numbers, and verdicts.
 */

import type { ServerContext } from '../mcp/types';
import {
    listFindingReviews,
    decideFindingReview,
    clearFindingReviews,
    formatReviewList,
    type ReviewDecision,
} from '../audit/findingReviewQueue';
import { recordFalsePositive } from '../project-map/agentMemory';

/** securecode.review-findings — list pending or previously decided uncertain findings. */
export async function toolReviewFindings(ctx: ServerContext, args: any): Promise<unknown> {
    const decision = args.decision as ReviewDecision | 'pending' | undefined;
    const filePath = args.filePath as string | undefined;

    const items = listFindingReviews(ctx.workspaceRoot, { decision, filePath });

    return {
        items: items.map(item => ({
            id: item.id,
            createdAt: item.createdAt,
            workspaceRelativePath: item.workspaceRelativePath,
            line: item.line,
            lineEnd: item.lineEnd,
            findingType: item.findingType,
            severity: item.severity,
            confidence: item.confidence,
            proven: item.proven,
            reviewReason: item.reviewReason,
            verificationReason: item.verificationReason,
            decision: item.decision || 'pending',
            decidedAt: item.decidedAt,
        })),
        count: items.length,
        formatted: formatReviewList(items),
    };
}

/** securecode.decide-finding — mark an uncertain finding as confirmed, rejected, or deferred. */
export async function toolDecideFinding(ctx: ServerContext, args: any): Promise<unknown> {
    if (!args.id) {
        throw new Error('Missing required parameter "id" for decide-finding.');
    }
    const decision = args.decision as ReviewDecision;
    if (!decision || !['confirmed', 'rejected', 'deferred'].includes(decision)) {
        throw new Error('Parameter "decision" must be one of: confirmed, rejected, deferred.');
    }
    const reason = args.reason as string | undefined;

    const updated = decideFindingReview(ctx.workspaceRoot, args.id, decision, reason);
    if (!updated) {
        return { success: false, error: `Review item ${args.id} not found.` };
    }

    // When the user rejects a finding, also record it as a false positive in
    // agent memory so future scans of this workspace skip similar patterns.
    // We use the review item's metadata to construct the false positive entry.
    if (decision === 'rejected') {
        try {
            // The evidence string itself isn't stored in the review queue (privacy),
            // but the evidenceHash is. We pass the hash as the evidence so
            // recordFalsePositive dedupes correctly. The pattern description
            // uses the finding type + file location instead.
            recordFalsePositive(ctx.workspaceRoot, {
                filePath: updated.workspaceRelativePath,
                findingType: updated.findingType,
                line: updated.line,
                evidence: updated.evidenceHash,
                reason: reason || `Rejected via review queue: ${updated.reviewReason}`,
                pattern: `${updated.findingType} at ${updated.workspaceRelativePath}:${updated.line}`,
            });
        } catch {
            // best-effort — memory recording failure must not block the decision
        }
    }

    return {
        success: true,
        decided: {
            id: updated.id,
            decision: updated.decision,
            decisionReason: updated.decisionReason,
            decidedAt: updated.decidedAt,
            findingType: updated.findingType,
            workspaceRelativePath: updated.workspaceRelativePath,
            line: updated.line,
        },
        message: decision === 'rejected'
            ? `Finding rejected. The agent will not report similar patterns in future scans of this workspace.`
            : decision === 'confirmed'
            ? `Finding confirmed. The review item is marked as a real vulnerability.`
            : `Finding deferred. The review item remains pending for later adjudication.`,
    };
}

/** securecode.clear-finding-reviews — delete resolved or all review items. */
export async function toolClearFindingReviews(ctx: ServerContext, args: any): Promise<unknown> {
    const id = args.id as string | undefined;
    const resolvedOnly = args.resolvedOnly as boolean | undefined;

    const removed = clearFindingReviews(ctx.workspaceRoot, { id, resolvedOnly });

    return {
        success: removed > 0,
        removed,
        message: id
            ? removed > 0
                ? `Removed review item ${id}.`
                : `Review item ${id} not found.`
            : resolvedOnly
            ? `Removed ${removed} resolved review item(s).`
            : removed > 0
            ? `Cleared all ${removed} review item(s).`
            : 'No review items to clear.',
    };
}
