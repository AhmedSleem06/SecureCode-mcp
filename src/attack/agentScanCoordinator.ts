/**
 * Per-workspace agent scan coordinator.
 *
 * Ensures one active agent-scan workflow per workspace per MCP process.
 * Independent direct calls queue in FIFO order. A batch holds the lock for
 * its full workflow (map + architecture + all scans). Different workspaces
 * may run concurrently.
 *
 * Cancellation removes waiting requests. Releasing the lock occurs in finally.
 * Each operation is force-released after a caller-provided timeout
 * (default: one agent scan's wall clock + 5 minutes).
 */

import { AGENT_SCAN_DEFAULTS } from './agentScanProtocol';
import { ARCHITECTURE_SCOUT_DEFAULTS } from './architectureScoutProtocol';

const LOCK_SLACK_MS = 5 * 60 * 1000;
const BATCH_PER_FILE_MS = 15 * 60 * 1000;

export const SINGLE_SCAN_OPERATION_TIMEOUT_MS = AGENT_SCAN_DEFAULTS.wallClockMs + LOCK_SLACK_MS;

export function batchOperationTimeoutMs(topN?: number, architectureDepth?: string): number {
    const n = Math.max(1, Math.min(20, Math.floor(Number.isFinite(topN) ? (topN as number) : 3)));
    const scout = ARCHITECTURE_SCOUT_DEFAULTS[(architectureDepth as keyof typeof ARCHITECTURE_SCOUT_DEFAULTS)]
        ?? ARCHITECTURE_SCOUT_DEFAULTS.standard;
    return n * BATCH_PER_FILE_MS + scout.wallClockMs + LOCK_SLACK_MS;
}

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
            operationTimeoutMs?: number;
        },
    ): Promise<T> {
        const lock = this.getLock(workspaceRoot);

        await lock.acquire(options?.signal, options?.maxWaitMs);

        let operationTimer: ReturnType<typeof setTimeout> | undefined;
        try {
            const operationPromise = operation();
            const timeoutMs = options?.operationTimeoutMs ?? SINGLE_SCAN_OPERATION_TIMEOUT_MS;
            const timeoutPromise = new Promise<never>((_, reject) => {
                operationTimer = setTimeout(() => {
                    reject(new Error(`Agent scan operation timed out after ${Math.round(timeoutMs / 1000)}s — releasing lock.`));
                }, timeoutMs);
            });
            return await Promise.race([operationPromise, timeoutPromise]);
        } finally {
            if (operationTimer) clearTimeout(operationTimer);
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
