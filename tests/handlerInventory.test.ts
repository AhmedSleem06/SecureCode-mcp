import { describe, it, expect, beforeEach } from 'vitest';
import { HandlerInventory } from '../src/project-map/handlerInventory';

describe('HandlerInventory', () => {
    let inventory: HandlerInventory;

    beforeEach(() => {
        inventory = new HandlerInventory();
    });

    it('adds a handler to the inventory', () => {
        const handler = inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handleLogin',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        expect(handler.id).toBeTruthy();
        expect(handler.reviewed).toBe(false);
        expect(inventory.getAll()).toHaveLength(1);
    });

    it('adds handlers from discovered endpoints', () => {
        inventory.addFromEndpoints([
            { method: 'GET', path: '/api/users', file: 'src/http.ts', line: 10 },
            { method: 'POST', path: '/api/login', file: 'src/http.ts', line: 50 },
            { method: 'GET', path: '/api/other', file: 'src/other.ts', line: 5 },
        ], 'src/http.ts');
        // Only handlers from src/http.ts should be added
        expect(inventory.getAll()).toHaveLength(2);
    });

    it('marks a handler as reviewed with evidence', () => {
        const handler = inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handleLogin',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.addEvidence(handler.id, 'ev-source-range');
        expect(inventory.getReviewed()).toHaveLength(0);
        inventory.addEvidence(handler.id, 'ev-policy-result');
        expect(inventory.getReviewed()).toHaveLength(1);
        expect(inventory.allReviewed()).toBe(true);
    });

    it('allReviewed returns true when no handlers exist', () => {
        expect(inventory.allReviewed()).toBe(true);
    });

    it('allReviewed returns false when any handler is unreviewed', () => {
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler2',
            range: { start: 30, end: 40 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        expect(inventory.allReviewed()).toBe(false);
    });

    it('getUnreviewedSensitiveCount counts security-sensitive unreviewed', () => {
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler2',
            range: { start: 30, end: 40 },
            kind: 'http-handler',
            securitySensitive: false,
        });
        expect(inventory.getUnreviewedSensitiveCount()).toBe(1);
    });

    it('isRangeCovered checks if a handler range is within covered ranges', () => {
        const handler = inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        expect(inventory.isRangeCovered(handler, [{ start: 1, end: 50 }])).toBe(true);
        expect(inventory.isRangeCovered(handler, [{ start: 1, end: 5 }])).toBe(false);
    });

    it('getNextUnreviewedRange returns the first unreviewed range sorted by line', () => {
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler2',
            range: { start: 50, end: 60 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        const range = inventory.getNextUnreviewedRange();
        expect(range).toEqual({ start: 10, end: 20 });
    });

    it('getNextUnreviewedRange returns null when all are reviewed', () => {
        const handler = inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.addEvidence(handler.id, 'ev1');
        inventory.addEvidence(handler.id, 'ev2');
        expect(inventory.getNextUnreviewedRange()).toBeNull();
    });

    it('addRpcMethods adds RPC methods', () => {
        inventory.addRpcMethods([
            { symbol: 'handleFileRead', line: 100, filePath: 'src/wsRpc.ts' },
            { symbol: 'handleFileWrite', line: 200, filePath: 'src/wsRpc.ts' },
        ]);
        expect(inventory.getAll()).toHaveLength(2);
        expect(inventory.getAll()[0].kind).toBe('rpc-method');
    });

    it('markReviewed explicitly marks a handler', () => {
        const handler = inventory.add({
            filePath: 'src/http.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.markReviewed(handler.id);
        expect(handler.reviewed).toBe(true);
    });

    it('getForFile filters by file path (case-insensitive)', () => {
        inventory.add({
            filePath: 'src/HTTP.ts',
            symbol: 'handler1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        expect(inventory.getForFile('src/http.ts')).toHaveLength(1);
    });

    it('snapshot returns summary counts', () => {
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'h1',
            range: { start: 10, end: 20 },
            kind: 'http-handler',
            securitySensitive: true,
        });
        inventory.add({
            filePath: 'src/http.ts',
            symbol: 'h2',
            range: { start: 30, end: 40 },
            kind: 'http-handler',
            securitySensitive: false,
        });
        const snap = inventory.snapshot();
        expect(snap.total).toBe(2);
        expect(snap.sensitive).toBe(1);
    });
});
