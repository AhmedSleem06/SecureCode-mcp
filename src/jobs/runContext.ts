import { AsyncLocalStorage } from 'async_hooks';

export interface ApiRunObserver {
    onRunStarted(runId: string): void;
    onRunClosed(runId: string): void;
}

const storage = new AsyncLocalStorage<ApiRunObserver>();

export function runWithApiRunObserver<T>(observer: ApiRunObserver, fn: () => T): T {
    return storage.run(observer, fn);
}

export function currentApiRunObserver(): ApiRunObserver | undefined {
    return storage.getStore();
}

export function notifyApiRunObserver(observer: ApiRunObserver, path: string, body: unknown, data: unknown): void {
    try {
        if (path === '/agent/scan/start') {
            const runId = (data as any)?.runId;
            if (typeof runId === 'string' && runId) observer.onRunStarted(runId);
        } else if (path === '/agent/scan/close') {
            const runId = (body as any)?.runId;
            if (typeof runId === 'string' && runId) observer.onRunClosed(runId);
        }
    } catch {
        // observers must never break API calls
    }
}
