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

import type { ServerContext } from '../mcp/types';
import { toolMap } from './map';
import { toolAgentScan } from './agentScan';
import { selectAgentScanBatchFiles } from '../attack/agentScanBatchSelection';
import {
    classifyAgentScanResult,
    buildBatchFileResult,
    buildNotStartedFileResult,
    aggregateBatchResult,
    type AgentScanBatchArgs,
    type AgentScanBatchResult,
    type AgentScanBatchFileResult,
    type AgentScanBatchStopReason,
} from '../attack/agentScanBatchProtocol';
import type { ArchitectureContext } from '../project-map/architectureContext';

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
    terminationReason?: string;
    cached?: boolean;
    error?: string;
}

export async function toolAgentScanBatch(
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

    try {
        const archResult = await toolMap(ctx, {
            action: 'architecture',
            depth: architectureDepth,
            _noCache: noCache,
            _signal: signal,
            _progress: progress ? (p: number, t: number, m: string) => {
                progress(Math.min(p, 1), 3, `Architecture: ${m}`);
            } : undefined,
        }) as ArchitectureToolResult;

        architecture = archResult.architecture ?? null;

        if (!architecture) {
            return aggregateBatchResult(
                'architecture-failed' as AgentScanBatchStopReason,
                topN, [], [],
            );
        }

        if (architecture.completeness === 'failed') {
            return aggregateBatchResult(
                'architecture-incomplete' as AgentScanBatchStopReason,
                topN, [], [],
            );
        }
    } catch (err: any) {
        return aggregateBatchResult(
            'architecture-failed' as AgentScanBatchStopReason,
            topN, [], [],
        );
    }

    if (signal?.aborted) {
        return aggregateBatchResult('cancelled', topN, [], []);
    }

    if (progress) progress(1, 3, 'Selecting files for sequential scanning...');

    const selection = selectAgentScanBatchFiles(ctx.workspaceRoot, architecture, {
        topN,
        fileSelection,
    });

    if (selection.selected.length === 0) {
        return aggregateBatchResult('completed', topN, [], []);
    }

    const selectedFiles = selection.selected.map(f => f.filePath);

    if (progress) progress(2, 3, `Preflight check for ${selectedFiles.length} file(s)...`);

    const fileResults: AgentScanBatchFileResult[] = [];
    let stopReason: AgentScanBatchStopReason = 'completed';
    let shouldStop = false;

    for (const file of selection.selected) {
        if (shouldStop) {
            fileResults.push(buildNotStartedFileResult(
                file.filePath, file.rank, file.role, file.importance,
            ));
            continue;
        }

        if (signal?.aborted) {
            fileResults.push(buildNotStartedFileResult(
                file.filePath, file.rank, file.role, file.importance,
            ));
            stopReason = 'cancelled';
            shouldStop = true;
            continue;
        }

        if (progress) {
            progress(file.rank, selection.selected.length,
                `Scanning ${file.filePath} (${file.rank}/${selection.selected.length})...`);
        }

        try {
            const scanResult = await toolAgentScan(ctx, {
                filePath: file.filePath,
                _skipFix: true,
                _noCache: noCache,
                _signal: signal,
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
                    transcript: [],
                    terminationReason: scanResult.terminationReason as any,
                    error: scanResult.error,
                } as any,
                scanResult.cached,
            );

            fileResults.push(batchFile);

            if (batchFile.status === 'incomplete' && stopOnIncomplete) {
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

    return aggregateBatchResult(stopReason, topN, selectedFiles, fileResults);
}
