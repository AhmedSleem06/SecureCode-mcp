import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const JOBS_DIR = '.securecode';
const JOBS_SUBDIR = 'jobs';
const JOB_ID_RE = /^job-[a-z0-9-]{4,64}$/;

export const MAX_JOBS = 50;
export const MAX_JOB_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const STALE_HEARTBEAT_MS = 10 * 60 * 1000;

export type JobKind = 'agent-scan' | 'agent-scan-batch';
export type JobStatus = 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted';

export interface JobProgress {
    current: number;
    total: number;
    message: string;
}

export interface JobRecord {
    id: string;
    kind: JobKind;
    args: Record<string, unknown>;
    targetKey: string;
    status: JobStatus;
    progress: JobProgress;
    apiRunId?: string;
    startedAt: string;
    updatedAt: string;
    finishedAt?: string;
    result?: unknown;
    error?: string;
    pid: number;
    cancelRequested?: boolean;
}

const SAFE_ARG_KEYS = [
    'filePath', 'language', 'baseRef', 'headRef', 'noCache',
    'topN', 'architectureDepth', 'fileSelection', 'stopOnIncomplete', 'stopOnFailure',
];

export function jobsDir(workspaceRoot: string): string {
    return path.join(workspaceRoot, JOBS_DIR, JOBS_SUBDIR);
}

export function isValidJobId(id: unknown): id is string {
    return typeof id === 'string' && JOB_ID_RE.test(id);
}

function jobPath(workspaceRoot: string, id: string): string {
    if (!isValidJobId(id)) throw new Error(`Invalid job id: ${String(id)}`);
    return path.join(jobsDir(workspaceRoot), `${id}.json`);
}

export function createJobId(): string {
    return `job-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
}

export function sanitizeJobArgs(args: Record<string, unknown> | undefined): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    if (!args) return out;
    for (const key of SAFE_ARG_KEYS) {
        const v = args[key];
        if (v === undefined || v === null) continue;
        if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[key] = v;
    }
    if (typeof args.code === 'string') {
        out.codeLength = args.code.length;
        out.codeHash = crypto.createHash('sha256').update(args.code).digest('hex').substring(0, 16);
    }
    return out;
}

export function jobTargetKey(kind: JobKind, args: Record<string, unknown> | undefined): string {
    if (kind === 'agent-scan-batch') {
        const topN = typeof args?.topN === 'number' ? args.topN : 3;
        const depth = typeof args?.architectureDepth === 'string' ? args.architectureDepth : 'standard';
        const selection = typeof args?.fileSelection === 'string' ? args.fileSelection : 'recommendedScanOrder';
        return `batch:${topN}:${depth}:${selection}`;
    }
    if (typeof args?.filePath === 'string' && args.filePath) {
        const normalized = path.normalize(args.filePath).replace(/\\/g, '/').replace(/^\.\//, '');
        return `file:${process.platform === 'win32' ? normalized.toLowerCase() : normalized}`;
    }
    if (typeof args?.code === 'string') {
        return `code:${crypto.createHash('sha256').update(args.code).digest('hex').substring(0, 16)}`;
    }
    return 'unknown';
}

function sleepSync(ms: number): void {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export function writeJob(workspaceRoot: string, record: JobRecord): void {
    const dir = jobsDir(workspaceRoot);
    fs.mkdirSync(dir, { recursive: true });
    const p = jobPath(workspaceRoot, record.id);
    const tmp = `${p}.${process.pid}.${crypto.randomBytes(3).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(record, null, 2), 'utf8');
    let lastErr: unknown;
    for (let attempt = 0; attempt < 5; attempt++) {
        try {
            fs.renameSync(tmp, p);
            return;
        } catch (err: any) {
            lastErr = err;
            if (err?.code !== 'EPERM' && err?.code !== 'EACCES' && err?.code !== 'EBUSY' && err?.code !== 'EEXIST') break;
            sleepSync(20 * (attempt + 1));
        }
    }
    try {
        fs.copyFileSync(tmp, p);
        fs.unlinkSync(tmp);
        return;
    } catch {
        try { fs.unlinkSync(tmp); } catch { /* best effort */ }
    }
    throw lastErr;
}

export function readJob(workspaceRoot: string, id: string): JobRecord | null {
    if (!isValidJobId(id)) return null;
    try {
        const raw = fs.readFileSync(jobPath(workspaceRoot, id), 'utf8');
        const data = JSON.parse(raw) as JobRecord;
        if (!data || data.id !== id) return null;
        return data;
    } catch {
        return null;
    }
}

export function listJobs(workspaceRoot: string): JobRecord[] {
    let entries: string[];
    try {
        entries = fs.readdirSync(jobsDir(workspaceRoot));
    } catch {
        return [];
    }
    const jobs: JobRecord[] = [];
    for (const name of entries) {
        if (!name.endsWith('.json')) continue;
        const rec = readJob(workspaceRoot, name.slice(0, -'.json'.length));
        if (rec) jobs.push(rec);
    }
    return jobs.sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt) || (b.id < a.id ? -1 : 1));
}

export function deleteJob(workspaceRoot: string, id: string): void {
    try { fs.unlinkSync(jobPath(workspaceRoot, id)); } catch { /* best effort */ }
}

export function pruneJobs(
    workspaceRoot: string,
    opts: { maxJobs?: number; maxAgeMs?: number; now?: number } = {},
): string[] {
    const maxJobs = opts.maxJobs ?? MAX_JOBS;
    const maxAgeMs = opts.maxAgeMs ?? MAX_JOB_AGE_MS;
    const now = opts.now ?? Date.now();
    const removed: string[] = [];
    const jobs = listJobs(workspaceRoot);
    let kept = 0;
    for (const job of jobs) {
        if (job.status === 'running') continue;
        const ts = Date.parse(job.finishedAt ?? job.updatedAt ?? job.startedAt);
        const tooOld = Number.isFinite(ts) && now - ts > maxAgeMs;
        if (tooOld || kept >= maxJobs) {
            deleteJob(workspaceRoot, job.id);
            removed.push(job.id);
            continue;
        }
        kept++;
    }
    try {
        for (const name of fs.readdirSync(jobsDir(workspaceRoot))) {
            if (!name.endsWith('.tmp')) continue;
            const full = path.join(jobsDir(workspaceRoot), name);
            try {
                if (now - fs.statSync(full).mtimeMs > 60 * 60 * 1000) fs.unlinkSync(full);
            } catch { /* best effort */ }
        }
    } catch { /* dir missing */ }
    return removed;
}

export function isPidAlive(pid: number): boolean {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
        process.kill(pid, 0);
        return true;
    } catch (err: any) {
        return err?.code === 'EPERM';
    }
}

export function isOrphanedRunningJob(
    job: JobRecord,
    opts: { ownedByThisProcess: (id: string) => boolean; now?: number; staleMs?: number },
): boolean {
    if (job.status !== 'running') return false;
    if (opts.ownedByThisProcess(job.id)) return false;
    if (job.pid === process.pid) return true;
    if (!isPidAlive(job.pid)) return true;
    const now = opts.now ?? Date.now();
    const updated = Date.parse(job.updatedAt);
    return Number.isFinite(updated) && now - updated > (opts.staleMs ?? STALE_HEARTBEAT_MS);
}

export function markInterruptedJobs(
    workspaceRoot: string,
    opts: { ownedByThisProcess: (id: string) => boolean; now?: number; staleMs?: number },
): JobRecord[] {
    const interrupted: JobRecord[] = [];
    for (const job of listJobs(workspaceRoot)) {
        if (!isOrphanedRunningJob(job, opts)) continue;
        const now = new Date(opts.now ?? Date.now()).toISOString();
        const updated: JobRecord = {
            ...job,
            status: 'interrupted',
            updatedAt: now,
            finishedAt: now,
            error: job.error ?? `The SecureCode MCP process running this job (pid ${job.pid}) stopped before it finished. Start the scan again.`,
        };
        try {
            writeJob(workspaceRoot, updated);
            interrupted.push(updated);
        } catch { /* best effort */ }
    }
    return interrupted;
}
