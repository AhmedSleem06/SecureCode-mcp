/**
 * Finding review queue — non-blocking human review for INCONCLUSIVE findings.
 *
 * When the verify subagent cannot prove or disprove a finding (sandbox
 * unavailable, budget exhausted, test couldn't run), the finding is added
 * to this local review queue. The scan completes without blocking — the
 * user can later adjudicate each item as confirmed, rejected, or deferred.
 *
 * Privacy contract (same as scanAuditLog.ts + agentMemory.ts):
 *   - Source code NEVER leaves the machine.
 *   - Evidence strings, `why` explanations, fix code, full test scripts,
 *     and full API responses are NOT recorded. Only hashes, counts,
 *     verdicts, file paths, and line numbers are stored.
 *   - The review queue is per-workspace, stored at
 *     `<workspaceRoot>/.securecode/finding-review-queue.json`.
 *
 * Retention:
 *   - 500 review items per workspace.
 *   - Resolved items pruned after 90 days.
 *   - Unresolved items kept until explicitly resolved.
 *
 * Dedup: identical findings (fileHash + filePath + line + findingType +
 * evidenceHash) are not re-enqueued — the existing item is returned.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const REVIEW_DIR = '.securecode';
const REVIEW_FILE = 'finding-review-queue.json';
const REVIEW_VERSION = 1;
const MAX_ITEMS = 500;
const RESOLVED_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

// ── Types ───────────────────────────────────────────────────────────────────

export type ReviewDecision = 'confirmed' | 'rejected' | 'deferred';

export type ReviewReason =
    | 'inconclusive-verification'
    | 'sandbox-unavailable'
    | 'verification-budget-exhausted'
    | 'runtime-blocked'
    | 'test-generation-failed'
    | 'manual-request';

export interface FindingReviewItem {
    id: string;
    createdAt: string;
    updatedAt: string;

    workspaceRelativePath: string;
    fileHash: string;
    line: number;
    lineEnd?: number;

    findingType: string;
    severity: string;
    confidence: number;
    proven: 'INCONCLUSIVE' | 'SKIPPED' | 'UNPROVEN';

    reviewReason: ReviewReason;
    /** Short verification reason, truncated to a safe length. */
    verificationReason?: string;
    /** SHA-256 of the evidence string — for dedup + privacy. */
    evidenceHash: string;

    decision?: ReviewDecision;
    decisionReason?: string;
    decidedAt?: string;
}

export interface FindingReviewQueueFile {
    version: number;
    items: FindingReviewItem[];
}

// ── Path helpers ────────────────────────────────────────────────────────────

function reviewQueuePath(workspaceRoot: string): string {
    return path.join(workspaceRoot, REVIEW_DIR, REVIEW_FILE);
}

function ensureReviewDir(workspaceRoot: string): string {
    const dir = path.join(workspaceRoot, REVIEW_DIR);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return dir;
}

function hashEvidence(evidence: string): string {
    return crypto.createHash('sha256').update(evidence).digest('hex').slice(0, 16);
}

function hashFile(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

function genId(): string {
    return 'review-' + crypto.randomBytes(4).toString('hex');
}

const MAX_VERIFICATION_REASON_LEN = 300;

function truncateReason(reason: string | undefined): string | undefined {
    if (!reason) return undefined;
    if (reason.length <= MAX_VERIFICATION_REASON_LEN) return reason;
    return reason.slice(0, MAX_VERIFICATION_REASON_LEN) + '…';
}

// ── Read / Write ─────────────────────────────────────────────────────────────

/**
 * Load the review queue for a workspace. Returns an empty queue
 * (version + empty array) if the file doesn't exist or is corrupt.
 */
export function loadReviewQueue(workspaceRoot: string): FindingReviewQueueFile {
    const p = reviewQueuePath(workspaceRoot);
    try {
        if (!fs.existsSync(p)) {
            return { version: REVIEW_VERSION, items: [] };
        }
        const raw = fs.readFileSync(p, 'utf8');
        const data = JSON.parse(raw) as FindingReviewQueueFile;
        if (!data.version || data.version > REVIEW_VERSION) {
            return { version: REVIEW_VERSION, items: [] };
        }
        return {
            version: REVIEW_VERSION,
            items: data.items || [],
        };
    } catch {
        return { version: REVIEW_VERSION, items: [] };
    }
}

/** Save the review queue (atomic write — .tmp + rename). */
function saveReviewQueue(workspaceRoot: string, queue: FindingReviewQueueFile): void {
    ensureReviewDir(workspaceRoot);
    const p = reviewQueuePath(workspaceRoot);
    const tmp = p + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(queue, null, 2), 'utf8');
    fs.renameSync(tmp, p);
}

// ── Dedup key ────────────────────────────────────────────────────────────────

function dedupKey(item: { fileHash: string; workspaceRelativePath: string; line: number; findingType: string; evidenceHash: string }): string {
    return `${item.fileHash}:${item.workspaceRelativePath}:${item.line}:${item.findingType}:${item.evidenceHash}`;
}

// ── Public API ──────────────────────────────────────────────────────────────

export interface EnqueueFindingReviewInput {
    workspaceRelativePath: string;
    fileContent: string;
    line: number;
    lineEnd?: number;
    findingType: string;
    severity: string;
    confidence: number;
    proven: 'INCONCLUSIVE' | 'SKIPPED' | 'UNPROVEN';
    reviewReason: ReviewReason;
    verificationReason?: string;
    evidence: string;
}

/**
 * Enqueue a finding for human review. Dedupes by
 * (fileHash + filePath + line + findingType + evidenceHash).
 * Returns the item (existing if duplicate, new otherwise).
 *
 * Re-enqueuing a previously-resolved item with the same dedup key
 * reopens it (clears the decision) — the finding reappeared and needs
 * re-review.
 */
export function enqueueFindingReview(
    workspaceRoot: string,
    input: EnqueueFindingReviewInput,
): FindingReviewItem {
    const queue = loadReviewQueue(workspaceRoot);
    const fh = hashFile(input.fileContent);
    const eh = hashEvidence(input.evidence);
    const key = dedupKey({
        fileHash: fh,
        workspaceRelativePath: input.workspaceRelativePath,
        line: input.line,
        findingType: input.findingType,
        evidenceHash: eh,
    });

    const now = new Date().toISOString();
    const existingIdx = queue.items.findIndex(item => dedupKey(item) === key);
    if (existingIdx >= 0) {
        const existing = queue.items[existingIdx];
        existing.updatedAt = now;
        existing.severity = input.severity;
        existing.confidence = input.confidence;
        existing.proven = input.proven;
        existing.reviewReason = input.reviewReason;
        existing.verificationReason = truncateReason(input.verificationReason);
        // Reopen if previously resolved — the finding reappeared.
        existing.decision = undefined;
        existing.decisionReason = undefined;
        existing.decidedAt = undefined;
        saveReviewQueue(workspaceRoot, queue);
        return existing;
    }

    const item: FindingReviewItem = {
        id: genId(),
        createdAt: now,
        updatedAt: now,
        workspaceRelativePath: input.workspaceRelativePath,
        fileHash: fh,
        line: input.line,
        lineEnd: input.lineEnd,
        findingType: input.findingType,
        severity: input.severity,
        confidence: input.confidence,
        proven: input.proven,
        reviewReason: input.reviewReason,
        verificationReason: truncateReason(input.verificationReason),
        evidenceHash: eh,
    };

    queue.items.push(item);
    pruneItems(queue);
    saveReviewQueue(workspaceRoot, queue);
    return item;
}

export interface ListFindingReviewsOptions {
    decision?: ReviewDecision | 'pending';
    filePath?: string;
}

/**
 * List review items, optionally filtered by decision status and/or file path.
 */
export function listFindingReviews(
    workspaceRoot: string,
    options?: ListFindingReviewsOptions,
): FindingReviewItem[] {
    const queue = loadReviewQueue(workspaceRoot);
    let items = queue.items;

    if (options?.decision) {
        if (options.decision === 'pending') {
            items = items.filter(i => i.decision === undefined);
        } else {
            items = items.filter(i => i.decision === options.decision);
        }
    }

    if (options?.filePath) {
        items = items.filter(i => i.workspaceRelativePath === options.filePath);
    }

    return items;
}

/**
 * Mark a review item as confirmed, rejected, or deferred.
 * Returns the updated item, or null if the ID was not found.
 */
export function decideFindingReview(
    workspaceRoot: string,
    id: string,
    decision: ReviewDecision,
    reason?: string,
): FindingReviewItem | null {
    const queue = loadReviewQueue(workspaceRoot);
    const item = queue.items.find(i => i.id === id);
    if (!item) return null;

    const now = new Date().toISOString();
    item.decision = decision;
    item.decisionReason = reason ? reason.slice(0, 500) : undefined;
    item.decidedAt = now;
    item.updatedAt = now;
    saveReviewQueue(workspaceRoot, queue);
    return item;
}

/**
 * Remove a single review item by ID. Returns true if removed.
 */
export function removeFindingReview(
    workspaceRoot: string,
    id: string,
): boolean {
    const queue = loadReviewQueue(workspaceRoot);
    const before = queue.items.length;
    queue.items = queue.items.filter(i => i.id !== id);
    if (queue.items.length === before) return false;
    saveReviewQueue(workspaceRoot, queue);
    return true;
}

export interface ClearFindingReviewsOptions {
    id?: string;
    resolvedOnly?: boolean;
}

/**
 * Clear review items. If `id` is given, removes just that item.
 * If `resolvedOnly` is true, removes only items with a decision set.
 * Otherwise removes ALL items.
 * Returns the count of items removed.
 */
export function clearFindingReviews(
    workspaceRoot: string,
    options?: ClearFindingReviewsOptions,
): number {
    const queue = loadReviewQueue(workspaceRoot);

    if (options?.id) {
        const before = queue.items.length;
        queue.items = queue.items.filter(i => i.id !== options.id);
        const removed = before - queue.items.length;
        if (removed > 0) saveReviewQueue(workspaceRoot, queue);
        return removed;
    }

    if (options?.resolvedOnly) {
        const before = queue.items.length;
        queue.items = queue.items.filter(i => i.decision === undefined);
        const removed = before - queue.items.length;
        if (removed > 0) saveReviewQueue(workspaceRoot, queue);
        return removed;
    }

    const removed = queue.items.length;
    queue.items = [];
    if (removed > 0) saveReviewQueue(workspaceRoot, queue);
    return removed;
}

// ── Pruning ──────────────────────────────────────────────────────────────────

function pruneItems(queue: FindingReviewQueueFile): void {
    const cutoff = Date.now() - RESOLVED_TTL_MS;
    // Drop resolved items older than the TTL.
    queue.items = queue.items.filter(i => {
        if (i.decision === undefined) return true; // keep pending
        if (!i.decidedAt) return true;
        try {
            return new Date(i.decidedAt).getTime() >= cutoff;
        } catch {
            return true;
        }
    });
    // Enforce hard cap — drop oldest resolved first, then oldest pending.
    if (queue.items.length <= MAX_ITEMS) return;
    const resolved = queue.items
        .filter(i => i.decision !== undefined)
        .sort((a, b) => (a.decidedAt || a.updatedAt).localeCompare(b.decidedAt || b.updatedAt));
    const toRemove = queue.items.length - MAX_ITEMS;
    const removeIds = new Set(resolved.slice(0, toRemove).map(i => i.id));
    queue.items = queue.items.filter(i => !removeIds.has(i.id));
    // If still over cap (not enough resolved to drop), drop oldest pending.
    if (queue.items.length > MAX_ITEMS) {
        queue.items = queue.items
            .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))
            .slice(-MAX_ITEMS);
    }
}

// ── Formatting ───────────────────────────────────────────────────────────────

export function formatReviewItem(item: FindingReviewItem): string {
    const lines: string[] = [
        `Review ID: ${item.id}`,
        `File: ${item.workspaceRelativePath}:${item.line}${item.lineEnd ? `-${item.lineEnd}` : ''}`,
        `Type: ${item.findingType}`,
        `Severity: ${item.severity}`,
        `Confidence: ${item.confidence}%`,
        `Verification: ${item.proven}`,
        `Reason: ${item.reviewReason}`,
    ];
    if (item.verificationReason) {
        lines.push(`Verification detail: ${item.verificationReason}`);
    }
    lines.push(`Decision: ${item.decision || 'pending'}`);
    return lines.join('\n');
}

export function formatReviewList(items: FindingReviewItem[]): string {
    if (items.length === 0) {
        return 'No review items found.';
    }
    const lines: string[] = [`Review queue (${items.length} item${items.length === 1 ? '' : 's'}):`, ''];
    for (const item of items) {
        lines.push(formatReviewItem(item), '');
    }
    return lines.join('\n').trimEnd();
}
