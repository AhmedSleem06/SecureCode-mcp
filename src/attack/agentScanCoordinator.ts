/**
 * Per-workspace agent scan coordinator.
 *
 * Ensures one active agent-scan workflow per workspace per MCP process.
 * Independent direct calls queue in FIFO order. A batch holds the lock for
 * its full workflow (map + architecture + all scans). Different workspaces
 * may run concurrently.
 *
 * Cancellation removes waiting requests. Releasing the lock occurs in finally.
 */

interface QueueEntry {
    resolve: () => void;
    reject: (err: Error) => void;
    signal?: AbortSignal;
    abortListener?: () => void;
}

class WorkspaceLock {
    private active = false;
    private queue: QueueEntry[] = [];

    get isActive(): boolean {
        return this.active;
    }

    get queueLength(): number {
        return this.queue.length;
    }

    async acquire(signal?: AbortSignal, maxWaitMs?: number): Promise<void> {
        if (!this.active) {
            this.active = true;
            return;
        }

        if (signal?.aborted) {
            throw new Error('Agent scan cancelled while waiting for workspace lock.');
        }

        return new Promise<void>((resolve, reject) => {
            const entry: QueueEntry = { resolve, reject, signal };

            const cleanup = () => {
                const idx = this.queue.indexOf(entry);
                if (idx >= 0) this.queue.splice(idx, 1);
                if (entry.abortListener && signal) {
                    signal.removeEventListener('abort', entry.abortListener);
                }
            };

            if (signal) {
                entry.abortListener = () => {
                    cleanup();
                    reject(new Error('Agent scan cancelled while waiting for workspace lock.'));
                };
                signal.addEventListener('abort', entry.abortListener);
            }

            if (maxWaitMs !== undefined) {
                const timeout = setTimeout(() => {
                    cleanup();
                    reject(new Error(`Agent scan timed out waiting for workspace lock after ${maxWaitMs}ms.`));
                }, maxWaitMs);
                const originalResolve = entry.resolve;
                const originalReject = entry.reject;
                entry.resolve = () => { clearTimeout(timeout); originalResolve(); };
                entry.reject = (err) => { clearTimeout(timeout); originalReject(err); };
            }

            this.queue.push(entry);
        });
    }

    release(): void {
        this.active = false;

        const next = this.queue.shift();
        if (next) {
            this.active = true;
            next.resolve();
        }
    }
}

export class AgentScanCoordinator {
    private readonly locks = new Map<string, WorkspaceLock>();

    private getLock(workspaceRoot: string): WorkspaceLock {
        let lock = this.locks.get(workspaceRoot);
        if (!lock) {
            lock = new WorkspaceLock();
            this.locks.set(workspaceRoot, lock);
        }
        return lock;
    }

    /**
     * Run an operation exclusively for the given workspace.
     * If another operation is already running for the same workspace,
     * this waits until it completes (FIFO queue) before starting.
     * Different workspaces run concurrently.
     */
    async runExclusive<T>(
        workspaceRoot: string,
        operation: () => Promise<T>,
        options?: {
            signal?: AbortSignal;
            maxWaitMs?: number;
        },
    ): Promise<T> {
        const lock = this.getLock(workspaceRoot);

        await lock.acquire(options?.signal, options?.maxWaitMs);

        try {
            return await operation();
        } finally {
            lock.release();
            if (!lock.isActive && lock.queueLength === 0) {
                this.locks.delete(workspaceRoot);
            }
        }
    }

    /**
     * Check if an operation is currently active for the given workspace.
     */
    isRunning(workspaceRoot: string): boolean {
        const lock = this.locks.get(workspaceRoot);
        return lock?.isActive ?? false;
    }

    /**
     * Get the number of queued operations waiting for the workspace lock.
     */
    queueDepth(workspaceRoot: string): number {
        const lock = this.locks.get(workspaceRoot);
        return lock?.queueLength ?? 0;
    }
}

export const globalScanCoordinator = new AgentScanCoordinator();
