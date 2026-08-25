export interface ScanRequest {
    code: string;
    language: string;
    filePath?: string;
    scanDepth?: 'auto' | 'deep' | 'agent';
    workspaceHints?: {
        frameworkHint?: string;
        relatedFiles?: Array<{ path: string; content: string; role: string }>;
        endpointContext?: unknown;
    };
    /** Phase B/C/E: AST-derived sink findings + taint flows + guard evals. */
    deterministicFacts?: {
        sinks?: Array<{
            line: number;
            endLine: number;
            sink: string;
            canonicalType: string;
            severity: string;
            callExpression: string;
            arguments: Array<{ kind: string; value?: string; interpolated?: boolean }>;
            enclosingFunction?: string | null;
            isInsideTryCatch: boolean;
        }>;
        taint?: Array<{
            source: string;
            sourceLine: number;
            sink: string;
            sinkLine: number;
            canonicalType: string;
            propagationPath: Array<{
                line: number;
                variable: string;
                operation: string;
                description: string;
            }>;
            isTainted: boolean;
        }>;
        guards?: Array<{
            guardName: string;
            guardType: string;
            attackType: string;
            effective: boolean;
            reason: string;
            bypassExample?: string;
        }>;
    };
}

export interface ScanFinding {
    check_id?: string;
    type?: string;
    path?: string;
    start?: { line: number; col?: number };
    end?: { line: number; col?: number };
    message?: string;
    severity?: string;
    extra?: { message?: string; severity?: string; lines?: string; fix?: string };
}

export interface FinalFinding {
    final_id: string;
    type: string;
    severity: string;
    confidence: number;
    location: { line_start: number; line_end: number };
    evidence_snippet: string;
    decision_basis: string;
    why_real?: string;
    fix_strategy?: string;
    fix_snippet?: string;
}

export interface ScanResponse {
    scanType: 'basic' | 'advanced' | 'fast';
    scanTypeMessage?: string | null;
    scanId?: string;
    findings?: ScanFinding[];
    finalFindings?: FinalFinding[];
    groupedFindings?: unknown;
    scanSummary?: string;
    remainingAIScans?: number;
    aiScanLimit?: number | null;
    plan?: string;
    degraded?: boolean;
    costs?: {
        totalCostUsd: number;
        stages: Array<{
            stage: string;
            provider: string;
            model: string;
            costUsd: number;
            degraded: boolean;
            fallbackFired: boolean;
        }>;
    };
    scanCredits?: number;
    attackerCredits?: number;
}

export interface FixRequest {
    code: string;
    language: string;
    vulnerability: {
        type: string;
        line_start: number;
        line_end: number;
        evidence_snippet: string;
    };
    framework?: string;
}

export interface FixResponse {
    fixed_code: string;
    diff?: string;
    fix_summary?: string;
    security_notes?: string[];
    why_secure?: string;
    imports_needed?: string[];
    confidence?: number;
}

export interface ApiError {
    status: number;
    code?: string;
    message: string;
    remaining?: number;
    scanType?: string;
    creditType?: 'scan' | 'attacker';
    requested?: number;
    balance?: number;
    required?: number;
    available?: number;
    shortfall?: number;
    retryable?: boolean;
}

export interface CreditBalanceResponse {
    scanCredits: number;
    attackerCredits: number;
    scanCreditsExpiringSoon?: number;
    reservedScanCredits?: number;
    availableScanCredits?: number;
}

export interface ApiErrorDetails {
    creditType?: 'scan' | 'attacker';
    requested?: number;
    balance?: number;
    required?: number;
    available?: number;
    shortfall?: number;
    stage?: string;
    retryable?: boolean;
}

export interface EndpointContext {
    method: string;
    path: string;
    mountedPath?: string;
    handlerName: string;
    sourceFile: string;
    line: number;
    middleware: unknown[];
    params: unknown[];
    authScheme: string;
    dataLayer: string;
    validatorLibrary: string;
    callGraph: unknown[];
    responseShape: string;
    confidence: number;
    runtimeConfirmed: boolean;
}

export interface ProjectMap {
    endpoints: EndpointContext[];
    files?: Record<string, { endpoints?: EndpointContext[] }>;
    builtAt?: string;
    version?: number;
}

export interface SandboxProveResponse {
    proven: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE' | 'NOT_REPRODUCIBLE';
    canReproduce: boolean;
    skipReason?: string;
    rationale?: string;
    degraded: boolean;
    sandbox?: {
        verdict: string;
        rule: string;
        reason: string;
        serverBooted: boolean;
        port: number;
        elapsedMs: number;
        baselineStatus?: number;
        exploitStatus?: number;
    };
    scanCredits?: number;
    proofEvidence?: import('../attack/proofTypes').ProofEvidence;
    proofGateResult?: import('../attack/proofTypes').ProofGateResult;
}

export interface VerifyGenerateResponse {
    canTest: boolean;
    testScript?: string;
    setupScript?: string | null;
    runner?: string;
    description?: string;
    skipReason?: string;
    scanCredits?: number;
    /** Dollar cost the API charged for this generate call (credits → USD). */
    costUsd?: number;
}

export interface VerifyAnalyzeResponse {
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    reason: string;
    shouldRetry: boolean;
    scanCredits?: number;
    /** Dollar cost the API charged for this analyze call (credits → USD). */
    costUsd?: number;
}
