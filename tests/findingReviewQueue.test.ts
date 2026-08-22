import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
    enqueueFindingReview,
    listFindingReviews,
    decideFindingReview,
    removeFindingReview,
    clearFindingReviews,
    loadReviewQueue,
    formatReviewItem,
    formatReviewList,
    type FindingReviewItem,
    type ReviewReason,
} from '../src/audit/findingReviewQueue';

let workspaceRoot: string;

beforeEach(() => {
    workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-review-'));
});

afterEach(() => {
    try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
});

function makeInput(overrides?: Partial<any>): any {
    return {
        workspaceRelativePath: 'src/auth.ts',
        fileContent: 'const x = 1;\nconst y = 2;\n',
        line: 42,
        lineEnd: 45,
        findingType: 'broken_access_control',
        severity: 'high',
        confidence: 68,
        proven: 'INCONCLUSIVE',
        reviewReason: 'sandbox-unavailable' as ReviewReason,
        verificationReason: 'No verification sandbox backend (Docker or Deno) was detected locally.',
        evidence: 'req.user.id used without ownership check',
        ...overrides,
    };
}

describe('enqueueFindingReview', () => {
    it('enqueues a pending INCONCLUSIVE finding', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        expect(item.id).toMatch(/^review-/);
        expect(item.decision).toBeUndefined();
        expect(item.proven).toBe('INCONCLUSIVE');
        expect(item.severity).toBe('high');

        const items = listFindingReviews(workspaceRoot);
        expect(items.length).toBe(1);
        expect(items[0].id).toBe(item.id);
    });

    it('deduplicates identical findings (same fileHash + path + line + type + evidenceHash)', () => {
        enqueueFindingReview(workspaceRoot, makeInput());
        const second = enqueueFindingReview(workspaceRoot, makeInput());
        const items = listFindingReviews(workspaceRoot);
        expect(items.length).toBe(1);
        expect(second.id).toBe(items[0].id);
    });

    it('does not deduplicate when evidence differs', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ evidence: 'evidence A' }));
        enqueueFindingReview(workspaceRoot, makeInput({ evidence: 'evidence B' }));
        expect(listFindingReviews(workspaceRoot).length).toBe(2);
    });

    it('does not deduplicate when line differs', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ line: 42 }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 100 }));
        expect(listFindingReviews(workspaceRoot).length).toBe(2);
    });

    it('reopens a previously resolved item when re-enqueued', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        decideFindingReview(workspaceRoot, item.id, 'rejected', 'false positive');
        expect(listFindingReviews(workspaceRoot, { decision: 'rejected' }).length).toBe(1);

        const reenqueued = enqueueFindingReview(workspaceRoot, makeInput());
        expect(reenqueued.id).toBe(item.id);
        expect(reenqueued.decision).toBeUndefined();
        expect(listFindingReviews(workspaceRoot, { decision: 'pending' }).length).toBe(1);
    });

    it('does not store source code or full evidence strings', () => {
        const fileContent = 'SECRET_API_KEY=sk-1234567890\nconst x = 1;\n';
        const evidence = 'db.query("SELECT * FROM users WHERE id=" + req.body.id) -- sensitive';
        enqueueFindingReview(workspaceRoot, makeInput({ fileContent, evidence }));

        const raw = fs.readFileSync(
            path.join(workspaceRoot, '.securecode', 'finding-review-queue.json'),
            'utf8',
        );
        expect(raw).not.toContain('SECRET_API_KEY');
        expect(raw).not.toContain('sk-1234567890');
        expect(raw).not.toContain('SELECT * FROM users');
        expect(raw).not.toContain('sensitive');
        // evidence hash IS stored
        const queue = JSON.parse(raw);
        expect(queue.items[0].evidenceHash).toMatch(/^[0-9a-f]{16}$/);
        expect(queue.items[0].fileHash).toMatch(/^[0-9a-f]{16}$/);
    });

    it('truncates long verification reasons', () => {
        const longReason = 'x'.repeat(500);
        const item = enqueueFindingReview(workspaceRoot, makeInput({ verificationReason: longReason }));
        expect(item.verificationReason!.length).toBeLessThanOrEqual(301);
        expect(item.verificationReason!.endsWith('…')).toBe(true);
    });
});

describe('listFindingReviews', () => {
    it('lists all items when no filter', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        expect(listFindingReviews(workspaceRoot).length).toBe(2);
    });

    it('filters by pending decision', () => {
        const a = enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        decideFindingReview(workspaceRoot, a.id, 'confirmed');
        expect(listFindingReviews(workspaceRoot, { decision: 'pending' }).length).toBe(1);
        expect(listFindingReviews(workspaceRoot, { decision: 'confirmed' }).length).toBe(1);
    });

    it('filters by file path', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ workspaceRelativePath: 'src/a.ts', evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ workspaceRelativePath: 'src/b.ts', evidence: 'b' }));
        expect(listFindingReviews(workspaceRoot, { filePath: 'src/a.ts' }).length).toBe(1);
        expect(listFindingReviews(workspaceRoot, { filePath: 'src/b.ts' }).length).toBe(1);
        expect(listFindingReviews(workspaceRoot, { filePath: 'src/c.ts' }).length).toBe(0);
    });
});

describe('decideFindingReview', () => {
    it('confirms an item', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        const updated = decideFindingReview(workspaceRoot, item.id, 'confirmed', 'real vuln');
        expect(updated).not.toBeNull();
        expect(updated!.decision).toBe('confirmed');
        expect(updated!.decisionReason).toBe('real vuln');
        expect(updated!.decidedAt).toBeDefined();
    });

    it('rejects an item', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        const updated = decideFindingReview(workspaceRoot, item.id, 'rejected', 'false positive');
        expect(updated!.decision).toBe('rejected');
    });

    it('defers an item', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        const updated = decideFindingReview(workspaceRoot, item.id, 'deferred');
        expect(updated!.decision).toBe('deferred');
        expect(updated!.decisionReason).toBeUndefined();
    });

    it('returns null for unknown ID', () => {
        expect(decideFindingReview(workspaceRoot, 'review-nonexistent', 'confirmed')).toBeNull();
    });

    it('truncates long decision reasons', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        const updated = decideFindingReview(workspaceRoot, item.id, 'confirmed', 'x'.repeat(600));
        expect(updated!.decisionReason!.length).toBeLessThanOrEqual(500);
    });
});

describe('removeFindingReview', () => {
    it('removes a resolved item', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        expect(removeFindingReview(workspaceRoot, item.id)).toBe(true);
        expect(listFindingReviews(workspaceRoot).length).toBe(0);
    });

    it('returns false for unknown ID', () => {
        expect(removeFindingReview(workspaceRoot, 'review-nonexistent')).toBe(false);
    });
});

describe('clearFindingReviews', () => {
    it('clears all items', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        const removed = clearFindingReviews(workspaceRoot);
        expect(removed).toBe(2);
        expect(listFindingReviews(workspaceRoot).length).toBe(0);
    });

    it('clears only resolved items when resolvedOnly is true', () => {
        const a = enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        decideFindingReview(workspaceRoot, a.id, 'confirmed');
        const removed = clearFindingReviews(workspaceRoot, { resolvedOnly: true });
        expect(removed).toBe(1);
        expect(listFindingReviews(workspaceRoot).length).toBe(1);
        expect(listFindingReviews(workspaceRoot)[0].decision).toBeUndefined();
    });

    it('removes a single item by id', () => {
        const a = enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        const removed = clearFindingReviews(workspaceRoot, { id: a.id });
        expect(removed).toBe(1);
        expect(listFindingReviews(workspaceRoot).length).toBe(1);
    });

    it('returns 0 when clearing empty queue', () => {
        expect(clearFindingReviews(workspaceRoot)).toBe(0);
    });
});

describe('corruption recovery', () => {
    it('recovers from corrupt JSON gracefully', () => {
        const dir = path.join(workspaceRoot, '.securecode');
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'finding-review-queue.json'), '{ not valid json');
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items).toEqual([]);
        expect(queue.version).toBe(1);
    });

    it('recovers from missing file', () => {
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items).toEqual([]);
    });

    it('resets when version is newer than supported', () => {
        const dir = path.join(workspaceRoot, '.securecode');
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(
            path.join(dir, 'finding-review-queue.json'),
            JSON.stringify({ version: 999, items: [{ id: 'x' }] }),
        );
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items).toEqual([]);
    });
});

describe('queue size cap', () => {
    it('enforces a maximum of 500 items', () => {
        for (let i = 0; i < 510; i++) {
            enqueueFindingReview(workspaceRoot, makeInput({
                line: i + 1,
                evidence: `evidence-${i}`,
            }));
        }
        const items = listFindingReviews(workspaceRoot);
        expect(items.length).toBeLessThanOrEqual(500);
    });
});

describe('atomic write recovery', () => {
    it('persists data across calls (atomic write)', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        // Reload from disk
        const queue = loadReviewQueue(workspaceRoot);
        expect(queue.items.length).toBe(2);
        expect(queue.items[0].id).toMatch(/^review-/);
    });

    it('does not leave a .tmp file after write', () => {
        enqueueFindingReview(workspaceRoot, makeInput());
        const dir = path.join(workspaceRoot, '.securecode');
        const files = fs.readdirSync(dir);
        expect(files).not.toContain('finding-review-queue.json.tmp');
    });
});

describe('formatting', () => {
    it('formats a single review item', () => {
        const item = enqueueFindingReview(workspaceRoot, makeInput());
        const formatted = formatReviewItem(item);
        expect(formatted).toContain('Review ID: ' + item.id);
        expect(formatted).toContain('File: src/auth.ts:42-45');
        expect(formatted).toContain('Type: broken_access_control');
        expect(formatted).toContain('Severity: high');
        expect(formatted).toContain('Confidence: 68%');
        expect(formatted).toContain('Verification: INCONCLUSIVE');
        expect(formatted).toContain('Decision: pending');
    });

    it('formats a review list', () => {
        enqueueFindingReview(workspaceRoot, makeInput({ line: 1, evidence: 'a' }));
        enqueueFindingReview(workspaceRoot, makeInput({ line: 2, evidence: 'b' }));
        const items = listFindingReviews(workspaceRoot);
        const formatted = formatReviewList(items);
        expect(formatted).toContain('Review queue (2 items)');
        expect(formatted).toContain('Review ID: review-');
    });

    it('formats an empty list', () => {
        expect(formatReviewList([])).toBe('No review items found.');
    });
});
