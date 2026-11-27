import type { ServerContext } from '../mcp/types';
import {
    listFindingReviews,
    decideFindingReview,
    clearFindingReviews,
    formatReviewList,
    type ReviewDecision,
} from '../audit/findingReviewQueue';
import { recordFalsePositive } from '../project-map/agentMemory';

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

export async function toolDecideFinding(ctx: ServerContext, args: any): Promise<unknown> {
    const decision = args.decision as string;

    if (decision === 'clear') {
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

    if (!args.id) {
        throw new Error('Missing required parameter "id" for decide-finding.');
    }
    if (!decision || !['confirmed', 'rejected', 'deferred'].includes(decision)) {
        throw new Error('Parameter "decision" must be one of: confirmed, rejected, deferred, clear.');
    }
    const reason = args.reason as string | undefined;

    const updated = decideFindingReview(ctx.workspaceRoot, args.id, decision as ReviewDecision, reason);
    if (!updated) {
        return { success: false, error: `Review item ${args.id} not found.` };
    }

    if (decision === 'rejected') {
        try {
            recordFalsePositive(ctx.workspaceRoot, {
                filePath: updated.workspaceRelativePath,
                findingType: updated.findingType,
                line: updated.line,
                evidence: updated.evidenceHash,
                reason: reason || `Rejected via review queue: ${updated.reviewReason}`,
                pattern: `${updated.findingType} at ${updated.workspaceRelativePath}:${updated.line}`,
            });
        } catch {
            // best-effort
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
