/**
 * Scan quality metrics — tracks measurable quality indicators throughout
 * the agent scan so the final result includes a structured quality scorecard.
 *
 * Metrics are tracked locally in the MCP loop and included in the scan
 * result/audit. They are NOT sent to the API — they are for the MCP and
 * the caller to evaluate scan quality.
 */

export interface ScanQualityMetrics {
    reads: {
        total: number;
        successful: number;
        duplicate: number;
        highOverlap: number;
        partialNew: number;
        newCoverage: number;
        blocked: number;
        truncated: number;
        invalid: number;
    };
    coverage: {
        totalLines: number;
        coveredLines: number;
        coveragePercentage: number;
        uncoveredRangeCount: number;
        largestUncoveredRange: { start: number; end: number } | null;
    };
    tools: {
        totalActions: number;
        analysisToolCount: number;
        distinctToolsUsed: string[];
        readCount: number;
        searchCount: number;
        traceFlowCount: number;
        checkGuardCount: number;
        checkPolicyCount: number;
        getEndpointsCount: number;
        readConfigCount: number;
        findTestsCount: number;
        callGraphCount: number;
    };
    candidates: {
        total: number;
        discovered: number;
        investigating: number;
        supported: number;
        verified: number;
        unproven: number;
        inconclusive: number;
        rejected: number;
        merged: number;
        blocked: number;
    };
    finish: {
        attempts: number;
        rejections: number;
        forcedTermination: boolean;
        terminationReason: string;
        critiqueFired: number;
        finishGateFired: number;
    };
    output: {
        malformedOutputCount: number;
        sanitizedFindings: number;
        downgradedFindings: number;
    };
    budget: {
        stepsUsed: number;
        stepsGranted: number;
        extensionsGranted: number;
        costSpentUsd: number;
        costCapUsd: number;
        wallClockMs: number;
        elapsedMs: number;
    };
}

export function createQualityMetrics(): ScanQualityMetrics {
    return {
        reads: {
            total: 0,
            successful: 0,
            duplicate: 0,
            highOverlap: 0,
            partialNew: 0,
            newCoverage: 0,
            blocked: 0,
            truncated: 0,
            invalid: 0,
        },
        coverage: {
            totalLines: 0,
            coveredLines: 0,
            coveragePercentage: 0,
            uncoveredRangeCount: 0,
            largestUncoveredRange: null,
        },
        tools: {
            totalActions: 0,
            analysisToolCount: 0,
            distinctToolsUsed: [],
            readCount: 0,
            searchCount: 0,
            traceFlowCount: 0,
            checkGuardCount: 0,
            checkPolicyCount: 0,
            getEndpointsCount: 0,
            readConfigCount: 0,
            findTestsCount: 0,
            callGraphCount: 0,
        },
        candidates: {
            total: 0,
            discovered: 0,
            investigating: 0,
            supported: 0,
            verified: 0,
            unproven: 0,
            inconclusive: 0,
            rejected: 0,
            merged: 0,
            blocked: 0,
        },
        finish: {
            attempts: 0,
            rejections: 0,
            forcedTermination: false,
            terminationReason: '',
            critiqueFired: 0,
            finishGateFired: 0,
        },
        output: {
            malformedOutputCount: 0,
            sanitizedFindings: 0,
            downgradedFindings: 0,
        },
        budget: {
            stepsUsed: 0,
            stepsGranted: 0,
            extensionsGranted: 0,
            costSpentUsd: 0,
            costCapUsd: 0,
            wallClockMs: 0,
            elapsedMs: 0,
        },
    };
}

const ANALYSIS_TOOLS = new Set([
    'trace_flow', 'trace_flow_cross_file', 'check_guard', 'check_policy',
    'call_graph', 'find_definition', 'find_references', 'find_tests',
    'run_tests', 'search_code', 'read_config', 'get_endpoints',
]);

export class QualityMetricsTracker {
    private metrics: ScanQualityMetrics;

    constructor() {
        this.metrics = createQualityMetrics();
    }

    recordRead(classification: string, truncated: boolean): void {
        this.metrics.reads.total++;
        switch (classification) {
            case 'new-coverage': this.metrics.reads.newCoverage++; this.metrics.reads.successful++; break;
            case 'partial-new-coverage': this.metrics.reads.partialNew++; this.metrics.reads.successful++; break;
            case 'duplicate': this.metrics.reads.duplicate++; this.metrics.reads.blocked++; break;
            case 'high-overlap': this.metrics.reads.highOverlap++; this.metrics.reads.blocked++; break;
            case 'invalid': this.metrics.reads.invalid++; this.metrics.reads.blocked++; break;
            default: break;
        }
        if (truncated) this.metrics.reads.truncated++;
    }

    recordToolUse(toolType: string): void {
        this.metrics.tools.totalActions++;
        if (!this.metrics.tools.distinctToolsUsed.includes(toolType)) {
            this.metrics.tools.distinctToolsUsed.push(toolType);
        }
        if (ANALYSIS_TOOLS.has(toolType)) {
            this.metrics.tools.analysisToolCount++;
        }
        switch (toolType) {
            case 'read_file': this.metrics.tools.readCount++; break;
            case 'search_code': this.metrics.tools.searchCount++; break;
            case 'trace_flow':
            case 'trace_flow_cross_file': this.metrics.tools.traceFlowCount++; break;
            case 'check_guard': this.metrics.tools.checkGuardCount++; break;
            case 'check_policy': this.metrics.tools.checkPolicyCount++; break;
            case 'get_endpoints': this.metrics.tools.getEndpointsCount++; break;
            case 'read_config': this.metrics.tools.readConfigCount++; break;
            case 'find_tests': this.metrics.tools.findTestsCount++; break;
            case 'call_graph': this.metrics.tools.callGraphCount++; break;
        }
    }

    recordCoverage(totalLines: number, coveredLines: number, uncoveredRangeCount: number, largestUncovered: { start: number; end: number } | null): void {
        this.metrics.coverage.totalLines = totalLines;
        this.metrics.coverage.coveredLines = coveredLines;
        this.metrics.coverage.coveragePercentage = totalLines > 0 ? Math.round(100 * coveredLines / totalLines) : 0;
        this.metrics.coverage.uncoveredRangeCount = uncoveredRangeCount;
        this.metrics.coverage.largestUncoveredRange = largestUncovered;
    }

    recordCandidateSnapshot(snapshot: { total: number; discovered: number; investigating: number; supported: number; verified: number; unproven: number; inconclusive: number; rejected: number; merged: number; blocked: number }): void {
        this.metrics.candidates = { ...snapshot };
    }

    recordFinishAttempt(): void {
        this.metrics.finish.attempts++;
    }

    recordFinishRejection(): void {
        this.metrics.finish.rejections++;
    }

    recordCritique(): void {
        this.metrics.finish.critiqueFired++;
    }

    recordFinishGate(): void {
        this.metrics.finish.finishGateFired++;
    }

    recordForcedTermination(reason: string): void {
        this.metrics.finish.forcedTermination = true;
        this.metrics.finish.terminationReason = reason;
    }

    recordTermination(reason: string): void {
        this.metrics.finish.terminationReason = reason;
    }

    recordMalformedOutput(): void {
        this.metrics.output.malformedOutputCount++;
    }

    recordSanitizedFinding(): void {
        this.metrics.output.sanitizedFindings++;
    }

    recordDowngradedFinding(): void {
        this.metrics.output.downgradedFindings++;
    }

    recordBudget(stepsUsed: number, stepsGranted: number, extensionsGranted: number, costSpentUsd: number, costCapUsd: number, wallClockMs: number, elapsedMs: number): void {
        this.metrics.budget = { stepsUsed, stepsGranted, extensionsGranted, costSpentUsd, costCapUsd, wallClockMs, elapsedMs };
    }

    getMetrics(): ScanQualityMetrics {
        return { ...this.metrics };
    }
}
