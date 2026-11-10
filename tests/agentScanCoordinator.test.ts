import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AgentScanCoordinator, SINGLE_SCAN_OPERATION_TIMEOUT_MS, batchOperationTimeoutMs } from '../src/attack/agentScanCoordinator';

describe('AgentScanCoordinator', () => {
    let coordinator: AgentScanCoordinator;

    beforeEach(() => {
        coordinator = new AgentScanCoordinator();
    });

    it('runs a single operation', async () => {
        const result = await coordinator.runExclusive('/ws', async () => 42);
        expect(result).toBe(42);
    });

    it('runs three simultaneous scans one at a time', async () => {
        const order: string[] = [];
        const promises = [
            coordinator.runExclusive('/ws', async () => {
                order.push('first');
                await new Promise(r => setTimeout(r, 20));
                order.push('first-done');
            }),
            coordinator.runExclusive('/ws', async () => {
                order.push('second');
                await new Promise(r => setTimeout(r, 10));
                order.push('second-done');
            }),
            coordinator.runExclusive('/ws', async () => {
                order.push('third');
                await new Promise(r => setTimeout(r, 5));
                order.push('third-done');
            }),
        ];

        await Promise.all(promises);

        expect(order).toEqual([
            'first', 'first-done',
            'second', 'second-done',
            'third', 'third-done',
        ]);
    });

    it('order is FIFO', async () => {
        const order: string[] = [];
        await Promise.all([
            coordinator.runExclusive('/ws', async () => { order.push('1'); }),
            coordinator.runExclusive('/ws', async () => { order.push('2'); }),
            coordinator.runExclusive('/ws', async () => { order.push('3'); }),
            coordinator.runExclusive('/ws', async () => { order.push('4'); }),
        ]);
        expect(order).toEqual(['1', '2', '3', '4']);
    });

    it('releases the lock after a failure', async () => {
        await expect(
            coordinator.runExclusive('/ws', async () => {
                throw new Error('boom');
            }),
        ).rejects.toThrow('boom');

        expect(coordinator.isRunning('/ws')).toBe(false);

        const result = await coordinator.runExclusive('/ws', async () => 'ok');
        expect(result).toBe('ok');
    });

    it('different workspaces run concurrently', async () => {
        let ws1Running = false;
        let ws2Running = false;
        let concurrent = false;

        const p1 = coordinator.runExclusive('/ws1', async () => {
            ws1Running = true;
            await new Promise(r => setTimeout(r, 30));
            if (ws2Running) concurrent = true;
            ws1Running = false;
        });
        const p2 = coordinator.runExclusive('/ws2', async () => {
            ws2Running = true;
            await new Promise(r => setTimeout(r, 30));
            if (ws1Running) concurrent = true;
            ws2Running = false;
        });

        await Promise.all([p1, p2]);
        expect(concurrent).toBe(true);
    });

    it('cancels waiting request on abort signal', async () => {
        const controller = new AbortController();
        const started: string[] = [];

        const p1 = coordinator.runExclusive('/ws', async () => {
            started.push('first');
            await new Promise(r => setTimeout(r, 50));
            started.push('first-done');
        });

        const p2 = coordinator.runExclusive('/ws', async () => {
            started.push('second');
        }, { signal: controller.signal });

        controller.abort();

        await expect(p2).rejects.toThrow('cancelled');
        await p1;

        expect(started).toEqual(['first', 'first-done']);
        expect(coordinator.isRunning('/ws')).toBe(false);
    });

    it('supports maxWaitMs timeout for waiting operations', async () => {
        const p1 = coordinator.runExclusive('/ws', async () => {
            await new Promise(r => setTimeout(r, 100));
        });

        const p2 = coordinator.runExclusive('/ws', async () => 'ok', { maxWaitMs: 20 });

        await expect(p2).rejects.toThrow('timed out');
        await p1;
    });

    it('isRunning returns true during active operation', async () => {
        let resolveOp: () => void;
        const opPromise = new Promise<void>(r => { resolveOp = r; });

        const runPromise = coordinator.runExclusive('/ws', async () => {
            await opPromise;
        });

        await new Promise(r => setTimeout(r, 10));
        expect(coordinator.isRunning('/ws')).toBe(true);

        resolveOp!();
        await runPromise;
        expect(coordinator.isRunning('/ws')).toBe(false);
    });

    it('queueDepth reports waiting operations', async () => {
        let resolveOp: () => void;
        const opPromise = new Promise<void>(r => { resolveOp = r; });

        const p1 = coordinator.runExclusive('/ws', async () => { await opPromise; });
        const p2 = coordinator.runExclusive('/ws', async () => {});
        const p3 = coordinator.runExclusive('/ws', async () => {});

        await new Promise(r => setTimeout(r, 10));
        expect(coordinator.queueDepth('/ws')).toBe(2);

        resolveOp!();
        await Promise.all([p1, p2, p3]);
        expect(coordinator.queueDepth('/ws')).toBe(0);
    });

    it('cleans up lock when queue is empty', async () => {
        await coordinator.runExclusive('/ws', async () => 'done');
        expect(coordinator.isRunning('/ws')).toBe(false);
        expect(coordinator.queueDepth('/ws')).toBe(0);
    });

    it('honours a per-operation timeout and releases the lock', async () => {
        const p = coordinator.runExclusive('/ws', () => new Promise(r => setTimeout(r, 200)), { operationTimeoutMs: 20 });
        await expect(p).rejects.toThrow('timed out');
        expect(coordinator.isRunning('/ws')).toBe(false);
    });

    it('single scan default timeout is the 45 min wall clock + 5 min', () => {
        expect(SINGLE_SCAN_OPERATION_TIMEOUT_MS).toBe(50 * 60 * 1000);
    });

    it('batch timeout scales with topN and architecture depth', () => {
        expect(batchOperationTimeoutMs(5, 'standard')).toBe(5 * 40 * 60_000 + 240_000 + 5 * 60_000);
        expect(batchOperationTimeoutMs(1, 'deep')).toBe(40 * 60_000 + 480_000 + 5 * 60_000);
        expect(batchOperationTimeoutMs(undefined, undefined)).toBe(3 * 40 * 60_000 + 240_000 + 5 * 60_000);
        expect(batchOperationTimeoutMs(100, 'quick')).toBe(20 * 40 * 60_000 + 120_000 + 5 * 60_000);
    });

    describe('with fake timers', () => {
        beforeEach(() => { vi.useFakeTimers(); });
        afterEach(() => { vi.useRealTimers(); });

        it('a 30-minute batch is not cut at 15 minutes', async () => {
            let finished = false;
            const p = coordinator.runExclusive('/ws', async () => {
                await new Promise(r => setTimeout(r, 30 * 60_000));
                finished = true;
                return 'batch-done';
            }, { operationTimeoutMs: batchOperationTimeoutMs(5, 'standard') });

            await vi.advanceTimersByTimeAsync(16 * 60_000);
            expect(coordinator.isRunning('/ws')).toBe(true);
            await vi.advanceTimersByTimeAsync(15 * 60_000);
            await expect(p).resolves.toBe('batch-done');
            expect(finished).toBe(true);
        });

        it('a single scan is not cut before 50 minutes but is released after', async () => {
            const p = coordinator.runExclusive('/ws', () => new Promise(() => undefined));
            const settled = p.catch(err => err as Error);
            await vi.advanceTimersByTimeAsync(49 * 60_000);
            expect(coordinator.isRunning('/ws')).toBe(true);
            await vi.advanceTimersByTimeAsync(2 * 60_000);
            const err = await settled;
            expect((err as Error).message).toMatch(/timed out after 3000s/);
            expect(coordinator.isRunning('/ws')).toBe(false);
        });
    });
});
