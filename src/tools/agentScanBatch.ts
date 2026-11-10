/**
 * securecode.agent-scan-batch MCP tool — sequential batch agent scanning.
 *
 * Maps the project, runs architecture scout, selects the top N
 * security-relevant files, and scans them ONE AT A TIME. Stops after
 * the first incomplete or failed scan and reports remaining files
 * as not-started.
 *
 * Rules:
 *   - Scans are strictly sequential (for...of + await, never Promise.all).
 *   - _skipFix is always true (no fix generation in batch mode).
 *   - Stops on incomplete, failed, cancelled, or thrown errors.
 *   - Does NOT stop merely because a completed scan has findings.
 *   - Does NOT include full transcripts in batch output.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { toolMap } from './map';
import { toolAgentScan } from './agentScan';
import { ApiClient } from '../api/client';
import { selectAgentScanBatchFiles } from '../attack/agentScanBatchSelection';
import { calculateBatchCredits, type CreditPlan } from '../attack/agentScanCreditPlan';
import { planFileSegmentsForPath } from '../attack/fileSegments';
import { globalScanCoordinator, batchOperationTimeoutMs } from '../attack/agentScanCoordinator';
import { AGENT_SCAN_DEFAULTS } from '../attack/agentScanProtocol';
import { scoutDefaultsForDepth } from '../attack/architectureScoutProtocol';
import {
    classifyAgentScanResult,
    buildBatchFileResult,
    buildNotStartedFileResult,
    aggregateBatchResult,
    type AgentScanBatchArgs,
    type AgentScanBatchResult,
    type AgentScanBatchFileResult,
    type AgentScanBatchFileSegment,
    type AgentScanBatchReplacement,
    type AgentScanBatchStopReason,
} from '../attack/agentScanBatchProtocol';
import type { CreditBalanceResponse } from '../api/types';
import type { ArchitectureContext } from '../project-map/architectureContext';
import { listCachedCompletedScans } from '../project-map/scanCache';

interface ArchitectureToolResult {
    architecture?: ArchitectureContext | null;
    status?: string;
    cached?: boolean;
    depth?: string;
}

interface AgentScanToolResult {
    status: string;
    agentFindings: any[];
    investigationNotes?: any[];
    coverageGaps?: any[];
    stepsUsed: number;
    costSpentUsd: number;
    creditsUsed?: number;
    terminationReason?: string;
    cached?: boolean;
    error?: string;
    segments?: AgentScanBatchFileSegment[];
}

export async function toolAgentScanBatch(
    ctx: ServerContext,
    args: AgentScanBatchArgs & Record<string, any>,
): Promise<AgentScanBatchResult> {
    return globalScanCoordinator.runExclusive(
        ctx.workspaceRoot,
        () => toolAgentScanBatchInner(ctx, args),
        {
            signal: args._signal as AbortSignal | undefined,
            operationTimeoutMs: batchOperationTimeoutMs(args.topN, args.architectureDepth),
        },
    );
}

async function toolAgentScanBatchInner(
    ctx: ServerContext,
    args: AgentScanBatchArgs & Record<string, any>,
): Promise<AgentScanBatchResult> {
    const progress = args._progress as ((current: number, total: number, message: string) => void) | undefined;
    const signal = args._signal as AbortSignal | undefined;
    const topN = args.topN ?? 3;
    const architectureDepth = args.architectureDepth ?? 'standard';
    const fileSelection = args.fileSelection ?? 'recommendedScanOrder';
    const noCache = !!args.noCache;
    const stopOnIncomplete = args.stopOnIncomplete !== false;
    const stopOnFailure = args.stopOnFailure !== false;

    if (progress) progress(0, 3, 'Mapping project + running architecture scout...');

    let architecture: ArchitectureContext | null = null;
    let archCached = false;

    try {
        const archResult = await toolMap(ctx, {
            action: 'architecture',
            depth: architectureDepth,
            _wait: true,
            _noCache: noCache,
            _signal: signal,
            _progress: progress ? (p: number, t: number, m: string) => {
                progress(Math.min(p, 1), 3, `Architecture: ${m}`);
            } : undefined,
        }) as ArchitectureToolResult;

        architecture = archResult.architecture ?? null;
        archCached = archResult.cached === true;

        if (!architecture) {
            return aggregateBatchResult(
                'architecture-failed' as AgentScanBatchStopReason,
                topN, [], [],
                {
                    stopDetail: 'Architecture scout returned no architecture context.',
                    cachedScans: listCachedCompletedScans(ctx.workspaceRoot),
                },
            );
        }

        if (architecture.completeness === 'failed') {
            return aggregateBatchResult(
                'architecture-incomplete' as AgentScanBatchStopReason,
                topN, [], [],
                {
                    stopDetail: 'Architecture scout completed with completeness=failed — the survey was cut short.',
                    cachedScans: listCachedCompletedScans(ctx.workspaceRoot),
                },
            );
        }
    } catch (err: any) {
        const apiCode = err?.apiCode || err?.code || '';
        const msg = String(err?.message || err);
        const cachedScans = listCachedCompletedScans(ctx.workspaceRoot);
        if (apiCode === 'AGENT_SCAN_ALREADY_RUNNING' || err?.statusCode === 409 || /already running/i.test(msg)) {
            return aggregateBatchResult(
                'architecture-in-progress' as AgentScanBatchStopReason,
                topN, [], [],
                {
                    stopDetail: `${msg} Completed files can be retrieved meanwhile — retry individual agent-scan calls without noCache (cache reads consume no runs).`,
                    cachedScans,
                },
            );
        }
        if (apiCode === 'AGENT_SCAN_DAILY_LIMIT' || (/daily limit/i.test(msg))) {
            return aggregateBatchResult(
                'daily-limit-reached' as AgentScanBatchStopReason,
                topN, [], [],
                {
                    stopDetail: `${msg} Architecture scouts share the agent-scan daily budget. Completed files are still retrievable from cache — retry individual agent-scan calls WITHOUT noCache (no run consumed).`,
                    cachedScans,
                },
            );
        }
        return aggregateBatchResult(
            'architecture-failed' as AgentScanBatchStopReason,
            topN, [], [],
            {
                stopDetail: msg,
                cachedScans,
            },
        );
    }

    if (signal?.aborted) {
        return aggregateBatchResult('cancelled', topN, [], []);
    }

    if (progress) progress(1, 3, 'Selecting files for sequential scanning...');

    const selection = await selectAgentScanBatchFiles(ctx.workspaceRoot, architecture, {
        topN,
        fileSelection,
    });

    const replacedOf = (file: object): AgentScanBatchReplacement | undefined =>
        (file as { replaced?: AgentScanBatchReplacement }).replaced;
    const replaced = selection.selected.map(replacedOf).filter((r): r is AgentScanBatchReplacement => !!r);
    const selectionExtras = { replaced, skipped: selection.skipped };

    if (selection.selected.length === 0) {
        return aggregateBatchResult('completed', topN, [], [], selectionExtras);
    }

    const selectedFiles = selection.selected.map(f => f.filePath);

    if (progress) progress(2, 3, `Preflight credit check for ${selectedFiles.length} file(s)...`);

    const fileParts = await Promise.all(selection.selected.map(async f => ({
        filePath: f.filePath,
        parts: await countFileParts(ctx.workspaceRoot, f.filePath),
    })));
    const partsByFile = new Map(fileParts.map(f => [f.filePath, f.parts]));

    const creditPlan = calculateBatchCredits({
        depth: architectureDepth,
        architectureCacheHit: archCached,
        uncachedFileCount: selection.selected.length,
        cachedFileCount: 0,
        fileParts,
    });
    if (progress && creditPlan.warning) progress(2, 3, creditPlan.warning);

    try {
        const client = new ApiClient({ baseUrl: ctx.apiUrl, token: ctx.apiToken });
        const balance = await client.getJson<CreditBalanceResponse>('/credits/balance', signal);

        if (balance.scanCredits < creditPlan.total) {
            const totalParts = creditPlan.breakdown.totalParts;
            const need = `Insufficient credits: have ${balance.scanCredits}, need ${creditPlan.total}`
                + (totalParts > selection.selected.length
                    ? ` (${totalParts} file parts × ${AGENT_SCAN_DEFAULTS.creditsPerRun}${creditPlan.architectureCredits > 0 ? ` + ${creditPlan.architectureCredits} architecture` : ''}).`
                    : '.');
            if (progress) progress(3, 3, need);
            return aggregateBatchResult(
                'insufficient-credits' as AgentScanBatchStopReason,
                topN, selectedFiles,
                selection.selected.map((f) => ({
                    ...buildNotStartedFileResult(f.filePath, f.rank, f.role, f.importance),
                    parts: partsByFile.get(f.filePath) ?? 1,
                    ...(replacedOf(f) ? { replaced: replacedOf(f) } : {}),
                })),
                {
                    stopDetail: `${need} Top up at https://usesecurecode.tech and retry.`,
                    creditNote: creditPlan.warning,
                    ...selectionExtras,
                },
            );
        }
    } catch (err: any) {
        if (signal?.aborted) {
            return aggregateBatchResult('cancelled', topN, [], []);
        }
    }

    const fileResults: AgentScanBatchFileResult[] = [];
    let stopReason: AgentScanBatchStopReason = 'completed';
    let shouldStop = false;

    for (const file of selection.selected) {
        const fileExtras = {
            parts: partsByFile.get(file.filePath) ?? 1,
            ...(replacedOf(file) ? { replaced: replacedOf(file) } : {}),
        };

        if (shouldStop) {
            fileResults.push({ ...buildNotStartedFileResult(
                file.filePath, file.rank, file.role, file.importance,
            ), ...fileExtras });
            continue;
        }

        if (signal?.aborted) {
            fileResults.push({ ...buildNotStartedFileResult(
                file.filePath, file.rank, file.role, file.importance,
            ), ...fileExtras });
            stopReason = 'cancelled';
            shouldStop = true;
            continue;
        }

        if (progress) {
            const partsNote = fileExtras.parts > 1 ? `, ${fileExtras.parts} parts` : '';
            progress(file.rank, selection.selected.length,
                `Scanning ${file.filePath} (${file.rank}/${selection.selected.length}${partsNote})...`);
        }

        try {
            const scanResult = await toolAgentScan(ctx, {
                filePath: file.filePath,
                _skipFix: true,
                _skipCoordinator: true,
                _noCache: noCache,
                _signal: signal,
                ...(file.role ? { _role: file.role } : {}),
                _progress: progress ? (p: number, t: number, m: string) => {
                    progress(file.rank, selection.selected.length,
                        `${file.filePath}: ${m}`);
                } : undefined,
            }) as AgentScanToolResult;

            const batchFile = buildBatchFileResult(
                file.filePath, file.rank, file.role, file.importance,
                {
                    status: scanResult.status as any,
                    findings: scanResult.agentFindings || [],
                    investigationNotes: scanResult.investigationNotes || [],
                    coverageGaps: scanResult.coverageGaps || [],
                    stepsUsed: scanResult.stepsUsed,
                    stepsGranted: 40,
                    extensionsGranted: 0,
                    costSpentUsd: scanResult.costSpentUsd,
                    creditsUsed: scanResult.creditsUsed,
                    transcript: [],
                    terminationReason: scanResult.terminationReason as any,
                    error: scanResult.error,
                } as any,
                scanResult.cached,
            );
            if (scanResult.segments && scanResult.segments.length > 0) {
                batchFile.segments = scanResult.segments;
                batchFile.parts = scanResult.segments.length;
            } else {
                batchFile.parts = fileExtras.parts;
            }
            if (fileExtras.replaced) batchFile.replaced = fileExtras.replaced;

            fileResults.push(batchFile);

            // Degraded-model window: stop the whole batch — retrying
            // against a bad model just burns credits.
            if (scanResult.terminationReason === 'llm_degraded') {
                stopReason = 'llm-degraded';
                shouldStop = true;
            } else if (batchFile.status === 'incomplete' && stopOnIncomplete) {
                stopReason = 'scan-incomplete';
                shouldStop = true;
            } else if (batchFile.status === 'failed' && stopOnFailure) {
                stopReason = 'scan-failed';
                shouldStop = true;
            }
        } catch (err: any) {
            const batchFile: AgentScanBatchFileResult = {
                filePath: file.filePath,
                rank: file.rank,
                role: file.role,
                importance: file.importance,
                status: 'failed',
                findings: [],
                investigationNotes: [],
                coverageGaps: [],
                stepsUsed: 0,
                costSpentUsd: 0,
                ...fileExtras,
                error: { message: err?.message || String(err) },
            };
            fileResults.push(batchFile);

            if (stopOnFailure) {
                stopReason = 'scan-failed';
                shouldStop = true;
            }
        }
    }

    if (progress && !shouldStop) {
        progress(selection.selected.length, selection.selected.length, 'Batch complete.');
    }

    return aggregateBatchResult(stopReason, topN, selectedFiles, fileResults, { creditNote: creditPlan.warning, ...selectionExtras });
}

async function countFileParts(workspaceRoot: string, filePath: string): Promise<number> {
    try {
        const abs = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
        const content = fs.readFileSync(abs, 'utf8');
        return (await planFileSegmentsForPath(content, filePath)).length;
    } catch {
        return 1;
    }
}
