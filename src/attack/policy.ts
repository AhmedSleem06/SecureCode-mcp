import * as net from 'net';

export interface AttackBudget {
    maxSteps: number;
    maxRequests: number;
    wallClockMs: number;
    maxResponseBytes: number;
    requestTimeoutMs: number;
}

export const DEFAULT_BUDGET: AttackBudget = {
    maxSteps: 12,
    maxRequests: 50,
    wallClockMs: 90_000,
    maxResponseBytes: 1_000_000,
    requestTimeoutMs: 10_000,
};

const ALLOWED_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '0:0:0:0:0:0:0:1']);

export class PolicyError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'PolicyError';
    }
}

export function isLocalhostHost(host: string): boolean {
    const lower = host.toLowerCase();
    return ALLOWED_HOSTS.has(lower);
}

export function validateTarget(target: { host: string; port: number; path: string }): void {
    if (!isLocalhostHost(target.host)) {
        throw new PolicyError(
            `Target host '${target.host}' is not allowed. Only localhost targets (127.0.0.1, localhost, ::1) are permitted.`,
        );
    }
    if (!target.port || target.port < 1 || target.port > 65535) {
        throw new PolicyError(`Port ${target.port} is invalid. Must be 1-65535.`);
    }
    if (!target.path.startsWith('/')) {
        throw new PolicyError(`Path '${target.path}' must start with '/'.`);
    }
    if (target.path.includes('..')) {
        throw new PolicyError(`Path '${target.path}' contains path traversal sequence.`);
    }
}

export function isRedirectToNonLocal(statusCode: number, location: string | undefined): boolean {
    if (!location) return false;
    if (statusCode < 300 || statusCode >= 400) return false;
    try {
        if (location.startsWith('http://') || location.startsWith('https://')) {
            const parsed = new URL(location);
            return !isLocalhostHost(parsed.hostname);
        }
        if (location.startsWith('//')) {
            const host = location.slice(2).split('/')[0].split(':')[0];
            return !isLocalhostHost(host);
        }
    } catch {
        return true;
    }
    return false;
}

export function checkBudget(
    budget: AttackBudget,
    state: { stepsTaken: number; requestsMade: number; startTime: number },
): { exhausted: boolean; reason?: string } {
    if (state.stepsTaken >= budget.maxSteps) {
        return { exhausted: true, reason: `Max steps (${budget.maxSteps}) reached.` };
    }
    if (state.requestsMade >= budget.maxRequests) {
        return { exhausted: true, reason: `Max requests (${budget.maxRequests}) reached.` };
    }
    if (Date.now() - state.startTime > budget.wallClockMs) {
        return { exhausted: true, reason: `Wall clock limit (${budget.wallClockMs}ms) exceeded.` };
    }
    return { exhausted: false };
}
