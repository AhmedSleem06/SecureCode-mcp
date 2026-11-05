import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
    createJobId,
    isValidJobId,
    jobsDir,
    jobTargetKey,
    listJobs,
    markInterruptedJobs,
    pruneJobs,
    readJob,
    sanitizeJobArgs,
    writeJob,
    type JobRecord,
} from '../src/jobs/jobStore';

function makeRecord(overrides: Partial<JobRecord> = {}): JobRecord {
    const now = new Date().toISOString();
    return {
        id: createJobId(),
        kind: 'agent-scan',
        args: { filePath: 'a.js' },
        targetKey: 'file:a.js',
        status: 'completed',
        progress: { current: 1, total: 1, message: 'Completed.' },
        startedAt: now,
        updatedAt: now,
        finishedAt: now,
        pid: process.pid,
        ...overrides,
    };
}

describe('jobStore', () => {
    let ws: string;

    beforeEach(() => {
        ws = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-jobstore-'));
    });

    afterEach(() => {
        try { fs.rmSync(ws, { recursive: true, force: true }); } catch { /* best effort */ }
    });

    it('stores jobs under <workspace>/.securecode/jobs', () => {
        const rec = makeRecord();
        writeJob(ws, rec);
        expect(fs.existsSync(path.join(ws, '.securecode', 'jobs', `${rec.id}.json`))).toBe(true);
        expect(jobsDir(ws)).toBe(path.join(ws, '.securecode', 'jobs'));
    });

    it('round-trips a record and overwrites an existing file atomically', () => {
        const rec = makeRecord({ status: 'running', finishedAt: undefined });
        writeJob(ws, rec);
        writeJob(ws, { ...rec, status: 'completed', result: { ok: true } });
        const back = readJob(ws, rec.id);
        expect(back?.status).toBe('completed');
        expect(back?.result).toEqual({ ok: true });
        const leftovers = fs.readdirSync(jobsDir(ws)).filter(n => n.endsWith('.tmp'));
        expect(leftovers).toEqual([]);
    });

    it('rejects ids that could escape the jobs dir', () => {
        expect(isValidJobId('../evil')).toBe(false);
        expect(isValidJobId('job-..-x')).toBe(false);
        expect(readJob(ws, '../../etc/passwd')).toBeNull();
        expect(isValidJobId(createJobId())).toBe(true);
    });

    it('sanitizes args: no signals, callbacks, internals, or raw code', () => {
        const ctrl = new AbortController();
        const out = sanitizeJobArgs({
            filePath: 'src/a.ts',
            noCache: true,
            code: 'const secret = "sk_live_123";',
            _signal: ctrl.signal,
            _progress: () => undefined,
            _skipFix: true,
            apiToken: 'tok',
        });
        expect(out.filePath).toBe('src/a.ts');
        expect(out.noCache).toBe(true);
        expect(out.codeLength).toBe(29);
        expect(typeof out.codeHash).toBe('string');
        expect(JSON.stringify(out)).not.toContain('sk_live');
        expect(out).not.toHaveProperty('_signal');
        expect(out).not.toHaveProperty('_progress');
        expect(out).not.toHaveProperty('_skipFix');
        expect(out).not.toHaveProperty('apiToken');
        expect(out).not.toHaveProperty('code');
    });

    it('target keys normalise file paths', () => {
        expect(jobTargetKey('agent-scan', { filePath: './src/a.ts' })).toBe(jobTargetKey('agent-scan', { filePath: 'src/a.ts' }));
        expect(jobTargetKey('agent-scan', { filePath: 'a.ts' })).not.toBe(jobTargetKey('agent-scan', { filePath: 'b.ts' }));
        expect(jobTargetKey('agent-scan-batch', {})).toBe('batch:3:standard:recommendedScanOrder');
    });

    it('lists newest first', () => {
        const older = makeRecord({ startedAt: new Date(Date.now() - 10_000).toISOString() });
        const newer = makeRecord();
        writeJob(ws, older);
        writeJob(ws, newer);
        expect(listJobs(ws).map(j => j.id)).toEqual([newer.id, older.id]);
    });

    it('prunes to the newest 50 finished jobs and drops jobs older than 7 days', () => {
        const base = Date.now();
        const ids: string[] = [];
        for (let i = 0; i < 55; i++) {
            const t = new Date(base - i * 1000).toISOString();
            const rec = makeRecord({ id: `job-test-${String(i).padStart(3, '0')}`, startedAt: t, updatedAt: t, finishedAt: t });
            ids.push(rec.id);
            writeJob(ws, rec);
        }
        const ancient = new Date(base - 8 * 24 * 60 * 60 * 1000).toISOString();
        writeJob(ws, makeRecord({ id: 'job-test-ancient', startedAt: ancient, updatedAt: ancient, finishedAt: ancient }));
        const running = makeRecord({ id: 'job-test-running', status: 'running', startedAt: ancient, updatedAt: ancient, finishedAt: undefined });
        writeJob(ws, running);

        pruneJobs(ws);
        const remaining = listJobs(ws).map(j => j.id);
        expect(remaining).toContain('job-test-running');
        expect(remaining).not.toContain('job-test-ancient');
        expect(remaining.filter(id => id !== 'job-test-running')).toHaveLength(50);
        expect(remaining).toContain(ids[0]);
        expect(remaining).toContain(ids[49]);
        expect(remaining).not.toContain(ids[50]);
    });

    it('marks running jobs from a dead pid as interrupted', () => {
        const deadPid = 2 ** 22 + 12345;
        const rec = makeRecord({ status: 'running', finishedAt: undefined, pid: deadPid, apiRunId: 'run-1' });
        writeJob(ws, rec);
        const interrupted = markInterruptedJobs(ws, { ownedByThisProcess: () => false });
        expect(interrupted.map(j => j.id)).toEqual([rec.id]);
        const back = readJob(ws, rec.id)!;
        expect(back.status).toBe('interrupted');
        expect(back.finishedAt).toBeDefined();
        expect(back.apiRunId).toBe('run-1');
        expect(back.error).toMatch(/stopped before it finished/);
    });

    it('marks running jobs of this pid that no runner owns as interrupted, but leaves owned ones', () => {
        const owned = makeRecord({ status: 'running', finishedAt: undefined });
        const orphan = makeRecord({ status: 'running', finishedAt: undefined });
        writeJob(ws, owned);
        writeJob(ws, orphan);
        markInterruptedJobs(ws, { ownedByThisProcess: (id) => id === owned.id });
        expect(readJob(ws, owned.id)!.status).toBe('running');
        expect(readJob(ws, orphan.id)!.status).toBe('interrupted');
    });

    it('leaves a live other process alone unless its heartbeat is stale', () => {
        const otherPid = process.ppid;
        const fresh = makeRecord({ status: 'running', finishedAt: undefined, pid: otherPid });
        const stale = makeRecord({
            status: 'running', finishedAt: undefined, pid: otherPid,
            updatedAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
        });
        writeJob(ws, fresh);
        writeJob(ws, stale);
        markInterruptedJobs(ws, { ownedByThisProcess: () => false });
        expect(readJob(ws, fresh.id)!.status).toBe('running');
        expect(readJob(ws, stale.id)!.status).toBe('interrupted');
    });

    it('never touches finished jobs', () => {
        const done = makeRecord({ status: 'completed', pid: 2 ** 22 + 999 });
        writeJob(ws, done);
        expect(markInterruptedJobs(ws, { ownedByThisProcess: () => false })).toEqual([]);
        expect(readJob(ws, done.id)!.status).toBe('completed');
    });
});
