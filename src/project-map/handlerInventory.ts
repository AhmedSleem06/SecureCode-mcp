/**
 * Handler inventory — discovers and tracks HTTP handlers, RPC methods,
 * auth operations, and event handlers in a target file.
 *
 * A handler is "reviewed" when its source range was delivered AND its
 * relevant authentication/authorization path was inspected. A handler
 * is NOT reviewed because it appeared in a function map or search result.
 */

import type { LineRange } from '../attack/investigationState';

export type HandlerKind = 'http-handler' | 'rpc-method' | 'auth-operation' | 'event-handler';

export interface HandlerInventoryItem {
    id: string;
    filePath: string;
    symbol?: string;
    range: LineRange;
    route?: string;
    method?: string;
    kind: HandlerKind;
    securitySensitive: boolean;
    reviewed: boolean;
    evidenceRefs: string[];
}

let handlerIdCounter = 0;

export class HandlerInventory {
    private handlers = new Map<string, HandlerInventoryItem>();

    /**
     * Add a discovered handler to the inventory.
     */
    add(input: Omit<HandlerInventoryItem, 'id' | 'reviewed' | 'evidenceRefs'>): HandlerInventoryItem {
        const id = `handler-${++handlerIdCounter}`;
        const item: HandlerInventoryItem = {
            ...input,
            id,
            reviewed: false,
            evidenceRefs: [],
        };
        this.handlers.set(id, item);
        return item;
    }

    /**
     * Add handlers from discovered endpoints (HTTP route handlers).
     */
    addFromEndpoints(endpoints: { method: string; path: string; file: string; line: number }[], filePath: string): void {
        for (const ep of endpoints) {
            const normalizedFile = ep.file.replace(/\\/g, '/').toLowerCase();
            const targetFile = filePath.replace(/\\/g, '/').toLowerCase();
            if (normalizedFile !== targetFile && !normalizedFile.includes(targetFile)) continue;

            this.add({
                filePath: ep.file,
                symbol: ep.method.toLowerCase(),
                range: { start: ep.line, end: ep.line },
                route: ep.path,
                method: ep.method,
                kind: 'http-handler',
                securitySensitive: true,
            });
        }
    }

    /**
     * Add RPC methods from search results (e.g., WebSocket message handlers).
     */
    addRpcMethods(methods: { symbol: string; line: number; filePath: string }[]): void {
        for (const m of methods) {
            this.add({
                filePath: m.filePath,
                symbol: m.symbol,
                range: { start: m.line, end: m.line },
                kind: 'rpc-method',
                securitySensitive: true,
            });
        }
    }

    /**
     * Mark a handler as reviewed by linking evidence to it.
     */
    addEvidence(handlerId: string, evidenceRef: string): void {
        const handler = this.handlers.get(handlerId);
        if (handler && !handler.evidenceRefs.includes(evidenceRef)) {
            handler.evidenceRefs.push(evidenceRef);
            this.updateReviewedStatus(handlerId);
        }
    }

    /**
     * Mark a handler as reviewed explicitly (when source range was delivered
     * AND relevant auth/policy evidence was recorded).
     */
    markReviewed(handlerId: string): void {
        const handler = this.handlers.get(handlerId);
        if (handler) {
            handler.reviewed = true;
        }
    }

    /**
     * Check if a handler's source range was covered by an actual read.
     */
    isRangeCovered(handler: HandlerInventoryItem, coveredRanges: LineRange[]): boolean {
        return coveredRanges.some(r =>
            r.start <= handler.range.start && r.end >= handler.range.end,
        );
    }

    /**
     * Update a handler's reviewed status based on evidence and coverage.
     */
    private updateReviewedStatus(handlerId: string): void {
        const handler = this.handlers.get(handlerId);
        if (!handler || handler.reviewed) return;

        // A handler is reviewed when it has at least 2 evidence refs:
        // typically source-range + policy/guard/flow evidence
        if (handler.evidenceRefs.length >= 2) {
            handler.reviewed = true;
        }
    }

    /**
     * Get all handlers in the inventory.
     */
    getAll(): HandlerInventoryItem[] {
        return [...this.handlers.values()];
    }

    /**
     * Get handlers for a specific file.
     */
    getForFile(filePath: string): HandlerInventoryItem[] {
        const normalized = filePath.replace(/\\/g, '/').toLowerCase();
        return [...this.handlers.values()].filter(h =>
            h.filePath.replace(/\\/g, '/').toLowerCase() === normalized,
        );
    }

    /**
     * Get all unreviewed handlers.
     */
    getUnreviewed(): HandlerInventoryItem[] {
        return [...this.handlers.values()].filter(h => !h.reviewed);
    }

    /**
     * Get all reviewed handlers.
     */
    getReviewed(): HandlerInventoryItem[] {
        return [...this.handlers.values()].filter(h => h.reviewed);
    }

    /**
     * Check if all handlers have been reviewed.
     */
    allReviewed(): boolean {
        const all = this.getAll();
        if (all.length === 0) return true; // No handlers to review
        return all.every(h => h.reviewed);
    }

    /**
     * Get the count of security-sensitive unreviewed handlers.
     */
    getUnreviewedSensitiveCount(): number {
        return this.getUnreviewed().filter(h => h.securitySensitive).length;
    }

    /**
     * Get unreviewed handlers sorted by line number for efficient reading.
     */
    getUnreviewedSorted(): HandlerInventoryItem[] {
        return this.getUnreviewed().sort((a, b) => a.range.start - b.range.start);
    }

    /**
     * Get the next unreviewed handler's range, useful for scheduling reads.
     */
    getNextUnreviewedRange(): LineRange | null {
        const sorted = this.getUnreviewedSorted();
        if (sorted.length === 0) return null;
        const first = sorted[0];
        return first.range;
    }

    /**
     * Snapshot for audit/tracing.
     */
    snapshot(): { total: number; reviewed: number; unreviewed: number; sensitive: number } {
        const all = this.getAll();
        return {
            total: all.length,
            reviewed: all.filter(h => h.reviewed).length,
            unreviewed: all.filter(h => !h.reviewed).length,
            sensitive: all.filter(h => h.securitySensitive).length,
        };
    }

    /**
     * Clear the inventory (for tests).
     */
    clear(): void {
        this.handlers.clear();
    }
}
