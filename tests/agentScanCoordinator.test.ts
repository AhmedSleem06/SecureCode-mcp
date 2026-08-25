import { describe, it, expect, beforeEach } from 'vitest';
import { AgentScanCoordinator } from '../src/attack/agentScanCoordinator';

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
});
