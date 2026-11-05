import type { ServerContext } from '../mcp/types';
import { getGlobalJobRunner, estimateJobMinutes, type JobStartResult } from '../jobs/jobRunner';
import { isValidJobId, type JobKind, type JobRecord } from '../jobs/jobStore';

const DEFAULT_TOOL_WAIT_MS = 50_000;
const CHECK_BACK = 'call securecode.job-status with this jobId in ~60 seconds';

export function toolWaitMs(): number {
    const raw = process.env.SECURECODE_TOOL_WAIT_MS;
    if (raw === undefined || raw === '') return DEFAULT_TOOL_WAIT_MS;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? n : DEFAULT_TOOL_WAIT_MS;
}

function elapsedSeconds(job: JobRecord): number {
    const start = Date.parse(job.startedAt);
    const end = job.finishedAt ? Date.parse(job.finishedAt) : Date.now();
    return Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, Math.round((end - start) / 1000)) : 0;
}

function describeTarget(job: JobRecord): string {
    if (job.kind === 'agent-scan-batch') return `agent-scan-batch (topN=${job.args.topN ?? 3})`;
    return `agent-scan of ${job.args.filePath ?? 'inline code'}`;
}

function busyResponse(started: Extract<JobStartResult, { status: 'busy' }>): Record<string, unknown> {
    const job = started.runningJob;
    return {
        status: 'busy',
        runningJobId: started.runningJobId,
        runningJob: {
            jobId: job.id,
            kind: job.kind,
            args: job.args,
            progress: job.progress,
            elapsedSeconds: elapsedSeconds(job),
        },
        message: `Another scan is already running in this workspace: ${describeTarget(job)} (job ${job.id}, running for ${elapsedSeconds(job)}s). Only one agent scan runs per workspace at a time. Check it with securecode.job-status { jobId: "${job.id}" }, wait for it to finish, or stop it with securecode.job-cancel { jobId: "${job.id}" } before starting a new scan.`,
    };
}

function jobSummary(job: JobRecord, includeResult: boolean): Record<string, unknown> {
    const out: Record<string, unknown> = {
        jobId: job.id,
        kind: job.kind,
        status: job.status,
        progress: job.progress,
        args: job.args,
        startedAt: job.startedAt,
        updatedAt: job.updatedAt,
        elapsedSeconds: elapsedSeconds(job),
    };
    if (job.finishedAt) out.finishedAt = job.finishedAt;
    if (job.cancelRequested) out.cancelRequested = true;
    if (job.error) out.error = job.error;
    if (job.status === 'running') out.next = CHECK_BACK;
    if (includeResult && job.result !== undefined) out.result = job.result;
    return out;
}

function startJob(ctx: ServerContext, kind: JobKind, args: any): Record<string, unknown> {
    const started = getGlobalJobRunner().start(ctx, kind, args || {});
    if (started.status === 'busy') return busyResponse(started);
    return {
        jobId: started.job.id,
        status: started.job.status,
        estimatedMinutes: started.estimatedMinutes,
        ...(started.status === 'existing' ? { alreadyRunning: true, progress: started.job.progress } : {}),
        next: CHECK_BACK,
    };
}

async function runViaJob(ctx: ServerContext, kind: JobKind, args: any): Promise<unknown> {
    const runner = getGlobalJobRunner();
    const progress = args?._progress as ((p: number, t: number, m: string) => void) | undefined;
    const signal = args?._signal as AbortSignal | undefined;
    const started = runner.start(ctx, kind, args || {});
    if (started.status === 'busy') return busyResponse(started);

    const jobId = started.job.id;
    const detach = progress ? runner.addProgressListener(jobId, progress) : () => undefined;
    const onAbort = () => { runner.cancel(ctx, jobId); };
    if (signal) {
        if (signal.aborted) onAbort();
        else signal.addEventListener('abort', onAbort, { once: true });
    }

    let job: JobRecord | null;
    try {
        job = await runner.wait(jobId, toolWaitMs());
    } finally {
        detach();
        if (signal) signal.removeEventListener('abort', onAbort);
    }
    job = job ?? runner.get(ctx, jobId) ?? started.job;

    if (job.status === 'completed') return job.result;
    if (job.status === 'failed') throw new Error(job.error || `${kind} failed.`);
    if (job.status === 'cancelled' || job.status === 'interrupted') {
        return job.result ?? { status: job.status, jobId, error: job.error, message: `Job ${jobId} ended with status '${job.status}'.` };
    }
    return {
        status: 'running',
        jobId,
        kind,
        progress: job.progress,
        elapsedSeconds: elapsedSeconds(job),
        estimatedMinutes: estimateJobMinutes(kind, job.args),
        ...(started.status === 'existing' ? { alreadyRunning: true } : {}),
        message: `The scan is still running in the background (job ${jobId}). Its result is kept when it finishes.`,
        next: CHECK_BACK,
    };
}

export function toolAgentScanStart(ctx: ServerContext, args: any): Promise<unknown> {
    return Promise.resolve(startJob(ctx, 'agent-scan', args));
}

export function toolAgentScanBatchStart(ctx: ServerContext, args: any): Promise<unknown> {
    return Promise.resolve(startJob(ctx, 'agent-scan-batch', args));
}

export function toolAgentScanViaJob(ctx: ServerContext, args: any): Promise<unknown> {
    return runViaJob(ctx, 'agent-scan', args);
}

export function toolAgentScanBatchViaJob(ctx: ServerContext, args: any): Promise<unknown> {
    return runViaJob(ctx, 'agent-scan-batch', args);
}

export async function toolJobStatus(ctx: ServerContext, args: any): Promise<unknown> {
    const jobId = args?.jobId as string | undefined;
    if (jobId !== undefined && !isValidJobId(jobId)) {
        throw new Error(`Invalid jobId '${jobId}'. Use an id returned by securecode.agent-scan-start or securecode.job-list.`);
    }
    const job = getGlobalJobRunner().get(ctx, jobId);
    if (!job) {
        return {
            status: 'not-found',
            message: jobId
                ? `No job with id ${jobId} in this workspace. Use securecode.job-list to see recent jobs.`
                : 'No scan jobs in this workspace yet. Start one with securecode.agent-scan-start.',
        };
    }
    return jobSummary(job, true);
}

export async function toolJobCancel(ctx: ServerContext, args: any): Promise<unknown> {
    const jobId = args?.jobId as string;
    if (!isValidJobId(jobId)) {
        throw new Error(`Invalid jobId '${String(jobId)}'.`);
    }
    const res = getGlobalJobRunner().cancel(ctx, jobId);
    return {
        jobId,
        cancelled: res.ok,
        status: res.job?.status ?? 'not-found',
        message: res.message,
    };
}

export async function toolJobList(ctx: ServerContext, _args: any): Promise<unknown> {
    const jobs = getGlobalJobRunner().list(ctx);
    return {
        jobs: jobs.map((j) => jobSummary(j, false)),
        count: jobs.length,
    };
}
