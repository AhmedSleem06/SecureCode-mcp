import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { JobRunner, setGlobalJobRunner } from '../src/jobs/jobRunner';
import { readJob, writeJob, type JobRecord } from '../src/jobs/jobStore';
import { ApiClient } from '../src/api/client';
import {
    toolAgentScanViaJob,
    toolAgentScanStart,
    toolJobStatus,
    toolJobCancel,
    toolJobList,
} from '../src/tools/jobTools';
import type { ServerContext } from '../src/mcp/types';

interface Deferred<T> {
    promise: Promise<T>;
    resolve: (v: T) => void;
    reject: (e: unknown) => void;
}

function deferred<T>(): Deferred<T> {
    let resolve!: (v: T) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
    return { promise, resolve, reject };
}

function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
    const start = Date.now();
    return new Promise((resolve, reject) => {
        const tick = () => {
            if (cond()) return resolve();
            if (Date.now() - start > timeoutMs) return reject(new Error('waitFor timed out'));
            setTimeout(tick, 5);
        };
        tick();
    });
}

describe('JobRunner', () => {
    let ws: string;
    let ctx: ServerContext;
    let calls: Array<{ kind: string; args: any }>;
    let pending: Deferred<unknown>[];
    let runner: JobRunner;

    function makeRunner(extra: Partial<ConstructorParameters<typeof JobRunner>[0]> = {}): JobRunner {
        const myCalls = calls;
        const myPending = pending;
        const op = (kind: string) => (_ctx: ServerContext, args: any) => {
            myCalls.push({ kind, args });
            const d = deferred<unknown>();
            myPending.push(d);
            args._signal?.addEventListener('abort', () => d.resolve({ status: 'cancelled', agentFindings: [] }));
            return d.promise;
        };
        return new JobRunner({
            operations: { 'agent-scan': op('agent-scan'), 'agent-scan-batch': op('agent-scan-batch') },
            closeApiRun: async () => undefined,
            progressWriteMs: 0,
            ...extra,
        });
    }

    beforeEach(() => {
        ws = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-jobrunner-'));
        ctx = { apiUrl: 'http://127.0.0.1:9', apiToken: 'tok', workspaceRoot: ws };
        calls = [];
        pending = [];
        runner = makeRunner();
    });

    afterEach(async () => {
        await new Promise(r => setImmediate(r));
        for (const d of pending) d.resolve({ status: 'completed' });
        await new Promise(r => setTimeout(r, 10));
        setGlobalJobRunner(null);
        delete process.env.SECURECODE_TOOL_WAIT_MS;
        try { fs.rmSync(ws, { recursive: true, force: true }); } catch { /* best effort */ }
    });

    it('start returns immediately with a running job persisted to disk', () => {
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        expect(res.status).toBe('started');
        if (res.status !== 'started') return;
        expect(res.job.status).toBe('running');
        expect(res.estimatedMinutes).toBeGreaterThan(0);
        expect(calls).toHaveLength(0);
        expect(readJob(ws, res.job.id)?.status).toBe('running');
    });

    it('moves running → completed and persists the result', async () => {
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        if (res.status !== 'started') throw new Error('expected started');
        await waitFor(() => calls.length === 1);
        calls[0].args._progress(3, 10, 'step 3');
        expect(runner.get(ctx, res.job.id)?.progress).toEqual({ current: 3, total: 10, message: 'step 3' });
        expect(readJob(ws, res.job.id)?.progress.message).toBe('step 3');
        pending[0].resolve({ status: 'completed', agentFindings: [{ type: 'sqli' }] });
        const done = await runner.wait(res.job.id, 1000);
        expect(done?.status).toBe('completed');
        const disk = readJob(ws, res.job.id)!;
        expect(disk.status).toBe('completed');
        expect(disk.finishedAt).toBeDefined();
        expect((disk.result as any).agentFindings[0].type).toBe('sqli');
    });

    it('passes an abort signal and progress callback but never persists them', async () => {
        const ctrl = new AbortController();
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js', _signal: ctrl.signal, _progress: () => undefined, code: 'x' });
        if (res.status !== 'started') throw new Error('expected started');
        await waitFor(() => calls.length === 1);
        expect(calls[0].args._signal).toBeInstanceOf(AbortSignal);
        expect(calls[0].args._signal).not.toBe(ctrl.signal);
        const raw = fs.readFileSync(path.join(ws, '.securecode', 'jobs', `${res.job.id}.json`), 'utf8');
        expect(raw).not.toContain('_signal');
        expect(raw).not.toContain('_progress');
    });

    it('records failures with the error message', async () => {
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        if (res.status !== 'started') throw new Error('expected started');
        await waitFor(() => calls.length === 1);
        pending[0].reject(new Error('Agent scan failed to start.'));
        const done = await runner.wait(res.job.id, 1000);
        expect(done?.status).toBe('failed');
        expect(readJob(ws, res.job.id)?.error).toBe('Agent scan failed to start.');
    });

    it('result stays readable after a restart (new runner instance)', async () => {
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        if (res.status !== 'started') throw new Error('expected started');
        await waitFor(() => calls.length === 1);
        pending[0].resolve({ status: 'completed', summary: 'done' });
        await runner.wait(res.job.id, 1000);

        const restarted = makeRunner();
        await restarted.recover(ctx);
        const rec = restarted.get(ctx, res.job.id)!;
        expect(rec.status).toBe('completed');
        expect((rec.result as any).summary).toBe('done');
        expect(restarted.get(ctx)?.id).toBe(res.job.id);
    });

    it('marks jobs left running by a previous process as interrupted and closes their API run', async () => {
        const now = new Date().toISOString();
        const orphan: JobRecord = {
            id: 'job-orphan-0001',
            kind: 'agent-scan',
            args: { filePath: 'a.js' },
            targetKey: 'file:a.js',
            status: 'running',
            progress: { current: 5, total: 40, message: 'step 5' },
            apiRunId: 'run-orphan',
            startedAt: now,
            updatedAt: now,
            pid: 2 ** 22 + 4321,
        };
        writeJob(ws, orphan);
        const closed: string[] = [];
        const restarted = makeRunner({ closeApiRun: async (_c, runId) => { closed.push(runId); } });
        const interrupted = await restarted.recover(ctx);
        expect(interrupted.map(j => j.id)).toEqual(['job-orphan-0001']);
        expect(closed).toEqual(['run-orphan']);
        expect(readJob(ws, 'job-orphan-0001')?.status).toBe('interrupted');
        const started = restarted.start(ctx, 'agent-scan', { filePath: 'a.js' });
        expect(started.status).toBe('started');
    });

    it('shutdown marks running jobs interrupted and closes their API run', async () => {
        const closed: string[] = [];
        const r = makeRunner({ closeApiRun: async (_c, runId) => { closed.push(runId); } });
        const res = r.start(ctx, 'agent-scan', { filePath: 'a.js' });
        if (res.status !== 'started') throw new Error('expected started');
        await waitFor(() => calls.length === 1);
        const rec = readJob(ws, res.job.id)!;
        writeJob(ws, { ...rec, apiRunId: 'run-live' });
        (r as any).active.get(res.job.id).record.apiRunId = 'run-live';
        await r.shutdown(500);
        expect(closed).toEqual(['run-live']);
        expect(calls[0].args._signal.aborted).toBe(true);
        const disk = readJob(ws, res.job.id)!;
        expect(disk.status).toBe('interrupted');
        expect(disk.apiRunId).toBeUndefined();
        await new Promise(r2 => setTimeout(r2, 10));
        expect(readJob(ws, res.job.id)!.status).toBe('interrupted');
    });

    it('recovery retries closing API runs of interrupted jobs until it succeeds', async () => {
        const now = new Date().toISOString();
        writeJob(ws, {
            id: 'job-interrupted-01', kind: 'agent-scan', args: {}, targetKey: 'file:a.js',
            status: 'interrupted', progress: { current: 0, total: 1, message: '' }, apiRunId: 'run-left',
            startedAt: now, updatedAt: now, finishedAt: now, pid: 2 ** 22 + 77,
        });
        await makeRunner({ closeApiRun: async () => { throw new Error('offline'); } }).recover(ctx);
        expect(readJob(ws, 'job-interrupted-01')!.apiRunId).toBe('run-left');
        const closed: string[] = [];
        await makeRunner({ closeApiRun: async (_c, id) => { closed.push(id); } }).recover(ctx);
        expect(closed).toEqual(['run-left']);
        expect(readJob(ws, 'job-interrupted-01')!.apiRunId).toBeUndefined();
    });

    it('cancel aborts the job and ends as cancelled', async () => {
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        if (res.status !== 'started') throw new Error('expected started');
        await waitFor(() => calls.length === 1);
        const c = runner.cancel(ctx, res.job.id);
        expect(c.ok).toBe(true);
        expect(calls[0].args._signal.aborted).toBe(true);
        const done = await runner.wait(res.job.id, 1000);
        expect(done?.status).toBe('cancelled');
        expect(readJob(ws, res.job.id)?.status).toBe('cancelled');
        expect(runner.cancel(ctx, res.job.id).ok).toBe(false);
    });

    it('duplicate start for the same target returns the running job', async () => {
        const a = runner.start(ctx, 'agent-scan', { filePath: 'src/a.js' });
        const b = runner.start(ctx, 'agent-scan', { filePath: './src/a.js', noCache: true });
        expect(b.status).toBe('existing');
        if (a.status !== 'started' || b.status !== 'existing') return;
        expect(b.job.id).toBe(a.job.id);
        await waitFor(() => calls.length === 1);
        await new Promise(r => setTimeout(r, 20));
        expect(calls).toHaveLength(1);
    });

    it('a different job in the same workspace returns busy', () => {
        const a = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        const b = runner.start(ctx, 'agent-scan', { filePath: 'b.js' });
        const c = runner.start(ctx, 'agent-scan-batch', { topN: 3 });
        expect(b.status).toBe('busy');
        expect(c.status).toBe('busy');
        if (a.status !== 'started' || b.status !== 'busy') return;
        expect(b.runningJobId).toBe(a.job.id);
    });

    it('a different workspace is not busy', () => {
        const ws2 = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-jobrunner-'));
        try {
            runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
            const other = runner.start({ ...ctx, workspaceRoot: ws2 }, 'agent-scan', { filePath: 'b.js' });
            expect(other.status).toBe('started');
        } finally {
            fs.rmSync(ws2, { recursive: true, force: true });
        }
    });

    it('a running job owned by another live process is busy', () => {
        const now = new Date().toISOString();
        writeJob(ws, {
            id: 'job-other-0001', kind: 'agent-scan', args: { filePath: 'x.js' }, targetKey: 'file:x.js',
            status: 'running', progress: { current: 0, total: 1, message: '' },
            startedAt: now, updatedAt: now, pid: process.ppid,
        });
        const res = runner.start(ctx, 'agent-scan', { filePath: 'a.js' });
        expect(res.status).toBe('busy');
    });

    it('captures the API run id from /agent/scan/start and clears it on /agent/scan/close', async () => {
        const server = http.createServer((req, res) => {
            let body = '';
            req.on('data', c => { body += c; });
            req.on('end', () => {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(req.url === '/agent/scan/start' ? { runId: 'run-xyz' } : { ok: true }));
            });
        });
        await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()));
        const port = (server.address() as any).port;
        const gate = deferred<void>();
        const closeGate = deferred<void>();
        const apiRunner = new JobRunner({
            operations: {
                'agent-scan': async (c) => {
                    const client = new ApiClient({ baseUrl: `http://127.0.0.1:${port}`, token: c.apiToken });
                    await client.postJson('/agent/scan/start', {});
                    await gate.promise;
                    await client.postJson('/agent/scan/close', { runId: 'run-xyz', status: 'completed' });
                    await closeGate.promise;
                    return { status: 'completed' };
                },
                'agent-scan-batch': async () => ({}),
            },
            progressWriteMs: 0,
        });
        try {
            const res = apiRunner.start(ctx, 'agent-scan', { filePath: 'a.js' });
            if (res.status !== 'started') throw new Error('expected started');
            await waitFor(() => readJob(ws, res.job.id)?.apiRunId === 'run-xyz');
            gate.resolve();
            await waitFor(() => readJob(ws, res.job.id)?.apiRunId === undefined);
            closeGate.resolve();
            expect((await apiRunner.wait(res.job.id, 1000))?.status).toBe('completed');
        } finally {
            gate.resolve();
            closeGate.resolve();
            await new Promise<void>(r => server.close(() => r()));
        }
    });
});

describe('job tools', () => {
    let ws: string;
    let ctx: ServerContext;
    let pending: Deferred<unknown>[];

    beforeEach(() => {
        ws = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-jobtools-'));
        ctx = { apiUrl: 'http://127.0.0.1:9', apiToken: 'tok', workspaceRoot: ws };
        pending = [];
        const myPending = pending;
        const op = (_c: ServerContext, args: any) => {
            const d = deferred<unknown>();
            myPending.push(d);
            args._progress?.(1, 2, 'half way');
            args._signal?.addEventListener('abort', () => d.resolve({ status: 'cancelled' }));
            return d.promise;
        };
        setGlobalJobRunner(new JobRunner({
            operations: { 'agent-scan': op, 'agent-scan-batch': op },
            closeApiRun: async () => undefined,
            progressWriteMs: 0,
        }));
    });

    afterEach(async () => {
        await new Promise(r => setImmediate(r));
        for (const d of pending) d.resolve({ status: 'completed' });
        await new Promise(r => setTimeout(r, 10));
        setGlobalJobRunner(null);
        delete process.env.SECURECODE_TOOL_WAIT_MS;
        try { fs.rmSync(ws, { recursive: true, force: true }); } catch { /* best effort */ }
    });

    it('legacy agent-scan returns the normal result when it finishes inside the wait window', async () => {
        process.env.SECURECODE_TOOL_WAIT_MS = '2000';
        const progress: string[] = [];
        const p = toolAgentScanViaJob(ctx, { filePath: 'a.js', _progress: (_a: number, _b: number, m: string) => progress.push(m) });
        await waitFor(() => pending.length === 1);
        await new Promise(r => setTimeout(r, 10));
        pending[0].resolve({ status: 'completed', agentFindings: [] });
        const out = await p as any;
        expect(out).toEqual({ status: 'completed', agentFindings: [] });
        expect(progress).toContain('half way');
    });

    it('legacy agent-scan returns running + jobId after the wait window, then job-status has the result', async () => {
        process.env.SECURECODE_TOOL_WAIT_MS = '30';
        const out = await toolAgentScanViaJob(ctx, { filePath: 'a.js' }) as any;
        expect(out.status).toBe('running');
        expect(out.jobId).toMatch(/^job-/);
        expect(out.next).toMatch(/securecode\.job-status/);

        const running = await toolJobStatus(ctx, { jobId: out.jobId }) as any;
        expect(running.status).toBe('running');
        expect(running.progress.message).toBe('half way');

        pending[0].resolve({ status: 'completed', summary: 'all good' });
        await waitFor(() => readJob(ws, out.jobId)?.status === 'completed');
        const done = await toolJobStatus(ctx, {}) as any;
        expect(done.jobId).toBe(out.jobId);
        expect(done.status).toBe('completed');
        expect(done.result).toEqual({ status: 'completed', summary: 'all good' });
    });

    it('legacy agent-scan throws the job error on failure', async () => {
        process.env.SECURECODE_TOOL_WAIT_MS = '2000';
        const p = toolAgentScanViaJob(ctx, { filePath: 'a.js' });
        await waitFor(() => pending.length === 1);
        pending[0].reject(new Error('Insufficient credits'));
        await expect(p).rejects.toThrow('Insufficient credits');
    });

    it('busy is reported with the running job instead of a retry loop', async () => {
        const started = await toolAgentScanStart(ctx, { filePath: 'a.js' }) as any;
        expect(started.status).toBe('running');
        expect(typeof started.estimatedMinutes).toBe('number');
        process.env.SECURECODE_TOOL_WAIT_MS = '10';
        const busy = await toolAgentScanViaJob(ctx, { filePath: 'b.js' }) as any;
        expect(busy.status).toBe('busy');
        expect(busy.runningJobId).toBe(started.jobId);
        expect(busy.message).toContain(started.jobId);
        expect(busy.message).toContain('a.js');
    });

    it('job-cancel and job-list', async () => {
        const started = await toolAgentScanStart(ctx, { filePath: 'a.js' }) as any;
        await waitFor(() => pending.length === 1);
        const cancel = await toolJobCancel(ctx, { jobId: started.jobId }) as any;
        expect(cancel.cancelled).toBe(true);
        await waitFor(() => readJob(ws, started.jobId)?.status === 'cancelled');
        const list = await toolJobList(ctx, {}) as any;
        expect(list.count).toBe(1);
        expect(list.jobs[0].status).toBe('cancelled');
        expect(list.jobs[0]).not.toHaveProperty('result');
    });

    it('job-status without jobs and with a bad id', async () => {
        expect((await toolJobStatus(ctx, {}) as any).status).toBe('not-found');
        await expect(toolJobStatus(ctx, { jobId: '../x' })).rejects.toThrow('Invalid jobId');
    });
});
