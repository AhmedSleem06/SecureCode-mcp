import type { ServerContext } from '../mcp/types';
import { ApiClient } from '../api/client';
import { runWithApiRunObserver } from './runContext';
import {
    createJobId,
    jobTargetKey,
    listJobs,
    markInterruptedJobs,
    isOrphanedRunningJob,
    pruneJobs,
    readJob,
    sanitizeJobArgs,
    writeJob,
    type JobKind,
    type JobProgress,
    type JobRecord,
} from './jobStore';

export type JobOperation = (ctx: ServerContext, args: any) => Promise<unknown>;
export type ProgressListener = (current: number, total: number, message: string) => void;

export interface JobRunnerDeps {
    operations: Record<JobKind, JobOperation>;
    closeApiRun?: (ctx: ServerContext, runId: string) => Promise<void>;
    heartbeatMs?: number;
    progressWriteMs?: number;
}

export type JobStartResult =
    | { status: 'started'; job: JobRecord; estimatedMinutes: number }
    | { status: 'existing'; job: JobRecord; estimatedMinutes: number }
    | { status: 'busy'; runningJobId: string; runningJob: JobRecord };

interface ActiveJob {
    workspaceRoot: string;
    ctx: ServerContext;
    record: JobRecord;
    controller: AbortController;
    done: Promise<JobRecord>;
    listeners: Set<ProgressListener>;
    lastWriteAt: number;
    heartbeat?: ReturnType<typeof setInterval>;
}

const RECENT_LIMIT = 50;

export function estimateJobMinutes(kind: JobKind, args: Record<string, unknown> | undefined): number {
    if (kind === 'agent-scan-batch') {
        const topN = typeof args?.topN === 'number' && Number.isFinite(args.topN)
            ? Math.max(1, Math.min(20, Math.floor(args.topN)))
            : 3;
        return 5 + topN * 6;
    }
    return 8;
}

async function defaultCloseApiRun(ctx: ServerContext, runId: string): Promise<void> {
    const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken, timeoutMs: 15_000 });
    await client.postJson('/agent/scan/close', { runId, status: 'cancelled', terminationReason: 'cancelled' });
}

function nowIso(): string {
    return new Date().toISOString();
}

export class JobRunner {
    private readonly active = new Map<string, ActiveJob>();
    private readonly recent = new Map<string, { workspaceRoot: string; record: JobRecord }>();
    private readonly recovered = new Set<string>();
    private readonly heartbeatMs: number;
    private readonly progressWriteMs: number;

    constructor(private readonly deps: JobRunnerDeps) {
        this.heartbeatMs = deps.heartbeatMs ?? 30_000;
        this.progressWriteMs = deps.progressWriteMs ?? 2_000;
    }

    recover(ctx: ServerContext): Promise<JobRecord[]> {
        const ws = ctx.workspaceRoot;
        if (this.recovered.has(ws)) return Promise.resolve([]);
        this.recovered.add(ws);
        let interrupted: JobRecord[] = [];
        let needsClose: JobRecord[] = [];
        try {
            interrupted = markInterruptedJobs(ws, { ownedByThisProcess: (id) => this.active.has(id) });
            pruneJobs(ws);
            needsClose = listJobs(ws).filter((job) => job.status === 'interrupted' && job.apiRunId);
        } catch {
            return Promise.resolve([]);
        }
        const close = this.deps.closeApiRun ?? defaultCloseApiRun;
        const closes = needsClose.map((job) =>
            close(ctx, job.apiRunId!)
                .then(() => {
                    const latest = readJob(ws, job.id);
                    if (latest && latest.apiRunId === job.apiRunId) {
                        delete latest.apiRunId;
                        writeJob(ws, latest);
                    }
                })
                .catch(() => undefined));
        return Promise.all(closes).then(() => interrupted);
    }

    async shutdown(timeoutMs = 2_000): Promise<void> {
        const jobs = [...this.active.values()];
        if (jobs.length === 0) return;
        const close = this.deps.closeApiRun ?? defaultCloseApiRun;
        const closes: Promise<unknown>[] = [];
        for (const act of jobs) {
            if (act.heartbeat) clearInterval(act.heartbeat);
            const now = nowIso();
            act.record.status = 'interrupted';
            act.record.finishedAt = now;
            act.record.error = 'The SecureCode MCP server stopped (client disconnected) before this job finished. Start the scan again.';
            delete act.record.cancelRequested;
            this.persist(act, true);
            act.controller.abort();
            const runId = act.record.apiRunId;
            if (runId) {
                closes.push(close(act.ctx, runId).then(() => {
                    if (act.record.apiRunId === runId) {
                        delete act.record.apiRunId;
                        this.persist(act, true);
                    }
                }).catch(() => undefined));
            }
        }
        let timer: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([
            Promise.all(closes),
            new Promise<void>((resolve) => { timer = setTimeout(resolve, timeoutMs); }),
        ]);
        if (timer) clearTimeout(timer);
    }

    start(ctx: ServerContext, kind: JobKind, args: Record<string, any>): JobStartResult {
        const ws = ctx.workspaceRoot;
        void this.recover(ctx);
        const targetKey = jobTargetKey(kind, args);

        for (const job of this.active.values()) {
            if (job.workspaceRoot !== ws) continue;
            if (job.record.kind === kind && job.record.targetKey === targetKey && !job.record.cancelRequested) {
                return { status: 'existing', job: { ...job.record }, estimatedMinutes: estimateJobMinutes(kind, args) };
            }
            return { status: 'busy', runningJobId: job.record.id, runningJob: { ...job.record } };
        }

        for (const rec of listJobs(ws)) {
            if (rec.status !== 'running') continue;
            if (isOrphanedRunningJob(rec, { ownedByThisProcess: (id) => this.active.has(id) })) continue;
            if (rec.kind === kind && rec.targetKey === targetKey) {
                return { status: 'existing', job: rec, estimatedMinutes: estimateJobMinutes(kind, args) };
            }
            return { status: 'busy', runningJobId: rec.id, runningJob: rec };
        }

        const startedAt = nowIso();
        const record: JobRecord = {
            id: createJobId(),
            kind,
            args: sanitizeJobArgs(args),
            targetKey,
            status: 'running',
            progress: { current: 0, total: 1, message: 'Starting...' },
            startedAt,
            updatedAt: startedAt,
            pid: process.pid,
        };

        const controller = new AbortController();
        const jobCtx: ServerContext = { ...ctx };
        const active: ActiveJob = {
            workspaceRoot: ws,
            ctx: jobCtx,
            record,
            controller,
            done: Promise.resolve(record),
            listeners: new Set(),
            lastWriteAt: 0,
        };
        this.active.set(record.id, active);
        this.persist(active, true);

        const runArgs: Record<string, any> = {};
        for (const [k, v] of Object.entries(args || {})) {
            if (k === '_signal' || k === '_progress') continue;
            runArgs[k] = v;
        }
        runArgs._signal = controller.signal;
        runArgs._progress = (current: number, total: number, message: string) =>
            this.onProgress(active, current, total, message);

        const observer = {
            onRunStarted: (runId: string) => {
                active.record.apiRunId = runId;
                this.persist(active, true);
            },
            onRunClosed: (runId: string) => {
                if (active.record.apiRunId === runId) {
                    delete active.record.apiRunId;
                    this.persist(active, true);
                }
            },
        };

        const operation = this.deps.operations[kind];
        active.heartbeat = setInterval(() => this.persist(active, true), this.heartbeatMs);
        if (typeof active.heartbeat.unref === 'function') active.heartbeat.unref();

        active.done = new Promise<void>((resolve) => setImmediate(resolve))
            .then(() => runWithApiRunObserver(observer, () => operation(jobCtx, runArgs)))
            .then(
                (result) => this.finish(active, controller.signal.aborted || isCancelledResult(result) ? 'cancelled' : 'completed', result),
                (err) => this.finish(active, controller.signal.aborted ? 'cancelled' : 'failed', undefined, err),
            )
            .then(() => ({ ...active.record }));

        return { status: 'started', job: { ...record }, estimatedMinutes: estimateJobMinutes(kind, args) };
    }

    get(ctx: ServerContext, jobId?: string): JobRecord | null {
        const ws = ctx.workspaceRoot;
        void this.recover(ctx);
        if (jobId) {
            const act = this.active.get(jobId);
            if (act && act.workspaceRoot === ws) return { ...act.record };
            const rec = readJob(ws, jobId);
            if (rec) return rec;
            const mem = this.recent.get(jobId);
            return mem && mem.workspaceRoot === ws ? { ...mem.record } : null;
        }
        return this.list(ctx)[0] ?? null;
    }

    list(ctx: ServerContext): JobRecord[] {
        const ws = ctx.workspaceRoot;
        void this.recover(ctx);
        const byId = new Map<string, JobRecord>();
        for (const mem of this.recent.values()) {
            if (mem.workspaceRoot === ws) byId.set(mem.record.id, { ...mem.record });
        }
        for (const rec of listJobs(ws)) byId.set(rec.id, rec);
        for (const act of this.active.values()) {
            if (act.workspaceRoot === ws) byId.set(act.record.id, { ...act.record });
        }
        return [...byId.values()].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt) || (b.id < a.id ? -1 : 1));
    }

    cancel(ctx: ServerContext, jobId: string): { ok: boolean; job: JobRecord | null; message: string } {
        const act = this.active.get(jobId);
        if (act && act.workspaceRoot === ctx.workspaceRoot) {
            if (!act.record.cancelRequested) {
                act.record.cancelRequested = true;
                act.record.progress = { ...act.record.progress, message: 'Cancelling...' };
                this.persist(act, true);
                act.controller.abort();
            }
            return { ok: true, job: { ...act.record }, message: 'Cancellation requested. The scan stops at the next safe point; check securecode.job-status for the final state.' };
        }
        const rec = this.get(ctx, jobId);
        if (!rec) return { ok: false, job: null, message: `No job with id ${jobId} in this workspace.` };
        if (rec.status === 'running') {
            return { ok: false, job: rec, message: `Job ${jobId} is owned by another SecureCode MCP process (pid ${rec.pid}) and cannot be cancelled from here.` };
        }
        return { ok: false, job: rec, message: `Job ${jobId} already finished with status '${rec.status}'.` };
    }

    async wait(jobId: string, timeoutMs: number, signal?: AbortSignal): Promise<JobRecord | null> {
        const act = this.active.get(jobId);
        if (!act) {
            const mem = this.recent.get(jobId);
            if (mem) return { ...mem.record };
            return null;
        }
        let timer: ReturnType<typeof setTimeout> | undefined;
        let onAbort: (() => void) | undefined;
        const timeout = new Promise<null>((resolve) => {
            timer = setTimeout(() => resolve(null), Math.max(0, timeoutMs));
            if (signal) {
                onAbort = () => resolve(null);
                if (signal.aborted) resolve(null);
                else signal.addEventListener('abort', onAbort, { once: true });
            }
        });
        try {
            const settled = await Promise.race([act.done, timeout]);
            return settled ?? { ...act.record };
        } finally {
            if (timer) clearTimeout(timer);
            if (signal && onAbort) signal.removeEventListener('abort', onAbort);
        }
    }

    addProgressListener(jobId: string, listener: ProgressListener): () => void {
        const act = this.active.get(jobId);
        if (!act) return () => undefined;
        act.listeners.add(listener);
        const p = act.record.progress;
        try { listener(p.current, p.total, p.message); } catch { /* listener errors ignored */ }
        return () => { act.listeners.delete(listener); };
    }

    isActive(jobId: string): boolean {
        return this.active.has(jobId);
    }

    private onProgress(act: ActiveJob, current: number, total: number, message: string): void {
        const progress: JobProgress = {
            current: Number.isFinite(current) ? current : 0,
            total: Number.isFinite(total) ? total : 0,
            message: String(message ?? '').slice(0, 500),
        };
        act.record.progress = progress;
        this.persist(act, false);
        for (const l of act.listeners) {
            try { l(progress.current, progress.total, progress.message); } catch { /* listener errors ignored */ }
        }
    }

    private persist(act: ActiveJob, force: boolean): void {
        const now = Date.now();
        act.record.updatedAt = new Date(now).toISOString();
        if (!force && now - act.lastWriteAt < this.progressWriteMs) return;
        act.lastWriteAt = now;
        try {
            writeJob(act.workspaceRoot, act.record);
        } catch (err: any) {
            console.error(`[securecode-mcp] job ${act.record.id}: could not write job record: ${err?.message || err}`);
        }
    }

    private finish(act: ActiveJob, status: JobRecord['status'], result?: unknown, err?: unknown): void {
        if (act.heartbeat) clearInterval(act.heartbeat);
        if (act.record.status === 'interrupted') {
            this.active.delete(act.record.id);
            return;
        }
        const finishedAt = nowIso();
        act.record.status = status;
        act.record.finishedAt = finishedAt;
        if (result !== undefined) act.record.result = result;
        if (err !== undefined) act.record.error = (err as any)?.message || String(err);
        if (status === 'completed') {
            act.record.progress = { ...act.record.progress, current: act.record.progress.total, message: 'Completed.' };
        } else if (status === 'cancelled') {
            act.record.progress = { ...act.record.progress, message: 'Cancelled.' };
        } else if (status === 'failed') {
            act.record.progress = { ...act.record.progress, message: `Failed: ${act.record.error ?? 'unknown error'}`.slice(0, 500) };
        }
        delete act.record.cancelRequested;
        if (status !== 'completed' && !act.controller.signal.aborted) act.controller.abort();
        this.persist(act, true);
        this.active.delete(act.record.id);
        this.recent.set(act.record.id, { workspaceRoot: act.workspaceRoot, record: act.record });
        while (this.recent.size > RECENT_LIMIT) {
            const oldest = this.recent.keys().next().value;
            if (oldest === undefined) break;
            this.recent.delete(oldest);
        }
        try { pruneJobs(act.workspaceRoot); } catch { /* best effort */ }
    }
}

function isCancelledResult(result: unknown): boolean {
    const r = result as any;
    return !!r && (r.status === 'cancelled' || r.stopReason === 'cancelled');
}

let globalRunner: JobRunner | null = null;

export function setGlobalJobRunner(runner: JobRunner | null): void {
    globalRunner = runner;
}

export function getGlobalJobRunner(): JobRunner {
    if (!globalRunner) {
        const { toolAgentScan } = require('../tools/agentScan') as typeof import('../tools/agentScan');
        const { toolAgentScanBatch } = require('../tools/agentScanBatch') as typeof import('../tools/agentScanBatch');
        globalRunner = new JobRunner({
            operations: {
                'agent-scan': (ctx, args) => toolAgentScan(ctx, args),
                'agent-scan-batch': (ctx, args) => toolAgentScanBatch(ctx, args),
            },
        });
    }
    return globalRunner;
}
