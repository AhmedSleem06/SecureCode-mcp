/**
 * Agent scan batch protocol — types for the sequential batch scan tool.
 *
 * The batch tool maps the project, runs architecture scout, selects the top N
 * security-relevant files, and scans them one at a time. It stops on the first
 * incomplete or failed scan and reports remaining files as not-started.
 *
 * Status contract:
 *   completed     — scan finished cleanly (agent_finish)
 *   incomplete    — scan was cut short (budget, cost cap, blocked recovery)
 *   failed        — operational failure (API error, restart, spawn failure)
 *   not-started   — selected but never attempted (batch stopped before this file)
 */

import type { ArchitectureDepth } from '../project-map/architectureContext';
import type { AgentScanResult, AgentScanFinding, InvestigationNote, CoverageGap, TerminationReason } from './agentScanProtocol';

export interface AgentScanBatchArgs {
    /** Number of files to scan (default 3, clamped to 1..20). */
    topN?: number;
    /** Architecture scout depth (default 'standard'). */
    architectureDepth?: ArchitectureDepth;
    /** Which file list to prefer for selection (default 'recommendedScanOrder'). */
    fileSelection?: 'recommendedScanOrder' | 'importantFiles';
    /** Skip the scan cache for all files in the batch. */
    noCache?: boolean;
    /** Stop after the first incomplete scan (default true). */
    stopOnIncomplete?: boolean;
    /** Stop after the first failed scan (default true). */
    stopOnFailure?: boolean;
    /** Progress callback for batch-level events. */
    _progress?: (current: number, total: number, message: string) => void;
    /** Abort signal for cancellation. */
    _signal?: AbortSignal;
}

export type AgentScanBatchFileStatus =
    | 'completed'
    | 'incomplete'
    | 'failed'
    | 'not-started';

export interface AgentScanBatchFileError {
    code?: string;
    message: string;
    httpStatus?: number;
    retryable?: boolean;
}

export interface AgentScanBatchFileResult {
    filePath: string;
    rank: number;
    role?: string;
    importance?: number;
    status: AgentScanBatchFileStatus;
    scanStatus?: string;
    terminationReason?: TerminationReason;
    cached?: boolean;
    findings: AgentScanFinding[];
    investigationNotes: InvestigationNote[];
    coverageGaps: CoverageGap[];
    stepsUsed: number;
    costSpentUsd: number;
    error?: AgentScanBatchFileError;
}

export type AgentScanBatchStopReason =
    | 'completed'
    | 'architecture-failed'
    | 'architecture-incomplete'
    | 'insufficient-credits'
    | 'scan-incomplete'
    | 'scan-failed'
    | 'cancelled';

export interface AgentScanBatchResult {
    status: 'completed' | 'incomplete' | 'failed' | 'preflight-failed' | 'cancelled';
    stopReason: AgentScanBatchStopReason;
    requestedTopN: number;
    selectedFiles: string[];
    completed: AgentScanBatchFileResult[];
    incomplete: AgentScanBatchFileResult[];
    failed: AgentScanBatchFileResult[];
    notStarted: AgentScanBatchFileResult[];
    totals: {
        selected: number;
        completed: number;
        incomplete: number;
        failed: number;
        notStarted: number;
        findings: number;
        stepsUsed: number;
        costSpentUsd: number;
    };
}

/**
 * Classify a single agent scan result into a batch file status.
 *
 * - completed  → completed
 * - incomplete → incomplete
 * - failed     → failed
 * - cancelled  → incomplete (started but not finished)
 */
export function classifyAgentScanResult(result: AgentScanResult): AgentScanBatchFileStatus {
    switch (result.status) {
        case 'completed': return 'completed';
        case 'incomplete': return 'incomplete';
        case 'failed': return 'failed';
        case 'cancelled': return 'incomplete';
        default: return 'incomplete';
    }
}

/**
 * Build a per-file result from an AgentScanResult.
 */
export function buildBatchFileResult(
    filePath: string,
    rank: number,
    role: string | undefined,
    importance: number | undefined,
    result: AgentScanResult,
    cached?: boolean,
): AgentScanBatchFileResult {
    return {
        filePath,
        rank,
        role,
        importance,
        status: classifyAgentScanResult(result),
        scanStatus: result.status,
        terminationReason: result.terminationReason,
        cached,
        findings: result.findings || [],
        investigationNotes: result.investigationNotes || [],
        coverageGaps: result.coverageGaps || [],
        stepsUsed: result.stepsUsed,
        costSpentUsd: result.costSpentUsd,
        error: result.error ? { message: result.error } : undefined,
    };
}

/**
 * Build a not-started file result placeholder.
 */
export function buildNotStartedFileResult(
    filePath: string,
    rank: number,
    role: string | undefined,
    importance: number | undefined,
): AgentScanBatchFileResult {
    return {
        filePath,
        rank,
        role,
        importance,
        status: 'not-started',
        findings: [],
        investigationNotes: [],
        coverageGaps: [],
        stepsUsed: 0,
        costSpentUsd: 0,
    };
}

/**
 * Aggregate per-file results into a batch result with totals.
 */
export function aggregateBatchResult(
    stopReason: AgentScanBatchStopReason,
    requestedTopN: number,
    selectedFiles: string[],
    fileResults: AgentScanBatchFileResult[],
): AgentScanBatchResult {
    const completed = fileResults.filter(f => f.status === 'completed');
    const incomplete = fileResults.filter(f => f.status === 'incomplete');
    const failed = fileResults.filter(f => f.status === 'failed');
    const notStarted = fileResults.filter(f => f.status === 'not-started');

    const totalFindings = completed.length + incomplete.length > 0
        ? fileResults.reduce((sum, f) => sum + (f.findings?.length || 0), 0)
        : 0;
    const totalSteps = fileResults.reduce((sum, f) => sum + f.stepsUsed, 0);
    const totalCost = fileResults.reduce((sum, f) => sum + f.costSpentUsd, 0);

    let status: AgentScanBatchResult['status'];
    if (stopReason === 'completed') {
        status = incomplete.length > 0 || failed.length > 0 ? 'incomplete' : 'completed';
    } else if (stopReason === 'cancelled') {
        status = 'cancelled';
    } else if (stopReason === 'insufficient-credits' || stopReason === 'architecture-failed' || stopReason === 'architecture-incomplete') {
        status = failed.length > 0 ? 'failed' : 'preflight-failed';
    } else if (stopReason === 'scan-failed') {
        status = 'failed';
    } else {
        status = incomplete.length > 0 || failed.length > 0 ? 'incomplete' : 'completed';
    }

    return {
        status,
        stopReason,
        requestedTopN,
        selectedFiles,
        completed,
        incomplete,
        failed,
        notStarted,
        totals: {
            selected: selectedFiles.length,
            completed: completed.length,
            incomplete: incomplete.length,
            failed: failed.length,
            notStarted: notStarted.length,
            findings: totalFindings,
            stepsUsed: totalSteps,
            costSpentUsd: totalCost,
        },
    };
}
