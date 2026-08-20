/**
 * Architecture scout protocol — wire contract between the MCP loop and the
 * API brain for the architecture-scout subagent.
 *
 * Mirror: api/src/attacker/architectureScoutProtocol.ts — keep string values
 * in step. Types are duplicated (not shared) between the API and MCP repos,
 * same pattern as agentScanProtocol.
 */

import type { ArchitectureContext, ArchitectureDepth } from '../project-map/architectureContext';

// Re-export ArchitectureDepth so consumers can import it from this module
// without reaching into project-map/architectureContext directly.
export type { ArchitectureDepth };

/** Default budgets for one architecture scout run, by depth. */
export const ARCHITECTURE_SCOUT_DEFAULTS = {
    quick: {
        maxSteps: 12,
        costCapUsd: 0.50,
        wallClockMs: 120_000,
        perStepEstimateUsd: 0.08,
        creditsPerRun: 5,
        maxImportantFiles: 20,
    },
    standard: {
        maxSteps: 25,
        costCapUsd: 1.50,
        wallClockMs: 240_000,
        perStepEstimateUsd: 0.08,
        creditsPerRun: 10,
        maxImportantFiles: 50,
    },
    deep: {
        maxSteps: 50,
        costCapUsd: 3.00,
        wallClockMs: 480_000,
        perStepEstimateUsd: 0.08,
        creditsPerRun: 20,
        maxImportantFiles: 100,
    },
} as const;

export interface ArchitectureScoutBudget {
    stepsRemaining: number;
    costSpentUsd: number;
    costCapUsd: number;
}

export interface ArchitectureScoutReadFileAction {
    type: 'read_file';
    path: string;
    startLine?: number;
    endLine?: number;
    rationale: string;
}
export interface ArchitectureScoutSearchCodeAction {
    type: 'search_code';
    pattern: string;
    glob?: string;
    rationale: string;
}
export interface ArchitectureScoutListFilesAction {
    type: 'list_files';
    path?: string;
    glob?: string;
    rationale: string;
}
export interface ArchitectureScoutListImportsAction {
    type: 'list_imports';
    filePath: string;
    rationale: string;
}
export interface ArchitectureScoutGetEndpointsAction {
    type: 'get_endpoints';
    glob?: string;
    rationale: string;
}
export interface ArchitectureScoutCallGraphAction {
    type: 'call_graph';
    filePath: string;
    functionName?: string;
    rationale: string;
}
export interface ArchitectureScoutReadConfigAction {
    type: 'read_config';
    configKind: 'auth' | 'cors' | 'rate_limit' | 'headers' | 'env' | 'all';
    rationale: string;
}
export interface ArchitectureScoutCheckDependenciesAction {
    type: 'check_dependencies';
    rationale: string;
}
export interface ArchitectureScoutFindDefinitionAction {
    type: 'find_definition';
    filePath: string;
    symbol: string;
    line?: number;
    rationale: string;
}
export interface ArchitectureScoutFindReferencesAction {
    type: 'find_references';
    filePath: string;
    symbol: string;
    line?: number;
    rationale: string;
}
export interface ArchitectureScoutFinishAction {
    type: 'finish';
    architecture: ArchitectureContext;
    summary: string;
    selfCritique: string;
}

export type ArchitectureScoutAction =
    | ArchitectureScoutReadFileAction
    | ArchitectureScoutSearchCodeAction
    | ArchitectureScoutListFilesAction
    | ArchitectureScoutListImportsAction
    | ArchitectureScoutGetEndpointsAction
    | ArchitectureScoutCallGraphAction
    | ArchitectureScoutReadConfigAction
    | ArchitectureScoutCheckDependenciesAction
    | ArchitectureScoutFindDefinitionAction
    | ArchitectureScoutFindReferencesAction
    | ArchitectureScoutFinishAction;

export type ArchitectureScoutActionType =
    | 'read_file'
    | 'search_code'
    | 'list_files'
    | 'list_imports'
    | 'get_endpoints'
    | 'call_graph'
    | 'read_config'
    | 'check_dependencies'
    | 'find_definition'
    | 'find_references'
    | 'finish';

export interface ArchitectureScoutTranscriptStep {
    action: ArchitectureScoutAction;
    observation: string;
}

export interface ArchitectureInventory {
    files: Array<{
        file: string;
        language: string;
        lines: number;
        endpointCount: number;
        importCount: number;
    }>;
    endpoints: Array<{
        method: string;
        path: string;
        handler: string;
        sourceFile: string;
        line: number;
        authScheme: string;
        dataLayer: string;
    }>;
    runtimes: string[];
    packageManager: string | null;
    languages: string[];
    dependencyFindings?: Array<{
        name: string;
        installedVersion: string;
        fixedVersion: string | null;
        severity: string;
    }>;
    configSummary?: {
        auth?: string | null;
        cors?: string | null;
        rateLimit?: string | null;
        headers?: string | null;
        envKeys?: string[];
    };
}

export interface ArchitectureScoutTarget {
    depth: ArchitectureDepth;
    inventory: ArchitectureInventory;
    maxImportantFiles: number;
}

export interface ArchitectureScoutStartResponse {
    runId: string;
    budget: ArchitectureScoutBudget;
    scanCredits: number;
    refundId: string;
}

export interface ArchitectureScoutStepRequest {
    runId: string;
    target: ArchitectureScoutTarget;
    transcript: ArchitectureScoutTranscriptStep[];
    budget: ArchitectureScoutBudget;
}

export interface ArchitectureScoutStepResponse {
    next: ArchitectureScoutAction | null;
    costUsd: number;
    tokens: number;
    degraded: boolean;
    costCapped: boolean;
    stepsRemaining: number;
    callBreakdown?: {
        decision: number;
        retry: number;
        critique: number;
    };
}

export type ArchitectureScoutRunStatus =
    | 'completed'
    | 'capped'
    | 'degraded'
    | 'spawn_failed'
    | 'cancelled';

export interface ArchitectureScoutResult {
    status: ArchitectureScoutRunStatus;
    architecture: ArchitectureContext | null;
    summary?: string;
    transcript: ArchitectureScoutTranscriptStep[];
    stepsUsed: number;
    costSpentUsd: number;
    error?: string;
}

export function isScoutFinishAction(a: ArchitectureScoutAction): a is ArchitectureScoutFinishAction {
    return a.type === 'finish';
}

export function scoutDefaultsForDepth(depth: ArchitectureDepth) {
    return ARCHITECTURE_SCOUT_DEFAULTS[depth] ?? ARCHITECTURE_SCOUT_DEFAULTS.standard;
}
