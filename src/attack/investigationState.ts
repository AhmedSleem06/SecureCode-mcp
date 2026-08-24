/**
 * Structured investigation state — tracks what the agent has already
 * investigated so it doesn't waste steps re-reading the same code and
 * can see which required checks remain incomplete.
 *
 * The Synara scan exposed two problems this module addresses:
 *
 * 1. The agent read `http.ts` 12 times with different line ranges, many
 *    overlapping. The exact-range dedup blocked identical ranges but
 *    not overlapping ones. This module tracks merged coverage so a read
 *    that substantially overlaps an already-read range is caught.
 *
 * 2. The agent called `finish` without completing the required
 *    investigation protocol (configuration inspection, threat-model
 *    establishment, cross-file ownership tracing). The checklist makes
 *    the missing steps visible to the agent AND to the controller.
 */

export interface LineRange {
    start: number;
    end: number;
}

export type InvestigationTaskStatus = 'pending' | 'investigated' | 'verified' | 'unproven' | 'blocked';

export interface InvestigationTask {
    id: string;
    targetFiles: string[];
    claim: string;
    requiredTools: string[];
    requiredEvidence: string[];
    status: InvestigationTaskStatus;
    entryFiles?: string[];
    relatedFiles?: string[];
    sourceSymbols?: string[];
    sinkSymbols?: string[];
    requiredProofDimensions?: string[];
}

export interface FileCoverage {
    filePath: string;
    ranges: LineRange[];
    totalLines?: number;
    readCount: number;
    blockedReadCount: number;
}

export type FlowVerificationStatus = 'confirmed' | 'refuted' | 'inconclusive' | 'blocked';

export interface FlowVerification {
    filePath: string;
    tool: string;
    status: FlowVerificationStatus;
    flowCount: number;
    reason: string;
    timestamp: number;
    riskId?: string;
    candidateId?: string;
    source?: { filePath: string; symbol?: string; line?: number };
    sink?: { filePath: string; symbol?: string; line?: number };
    hops?: Array<{ filePath: string; symbol?: string; line?: number; description?: string }>;
    truncated?: boolean;
    error?: string;
}

export type ReadValueClassification =
    | 'new-coverage'
    | 'partial-new-coverage'
    | 'duplicate'
    | 'high-overlap'
    | 'invalid'
    | 'function-map';

export interface ReadValueResult {
    classification: ReadValueClassification;
    overlapFraction: number;
    newLines: number;
    coverageAfter: LineRange[];
    nextUnreadRange: LineRange | null;
}

export type InvestigationStep =
    | 'initial-read'
    | 'route-discovery'
    | 'policy-check'
    | 'auth-symbol-search'
    | 'cross-file-flow'
    | 'config-inspection'
    | 'ownership-analysis'
    | 'tests-found'
    | 'architecture-risks-addressed'
    | 'all-handlers-reviewed'
    | 'candidates-verified';

export interface InvestigationChecklist {
    completed: Set<InvestigationStep>;
    required: Set<InvestigationStep>;
    requiredForFindingType: Map<string, Set<InvestigationStep>>;
}

const SECURITY_KEYWORD_WEIGHTS: Array<[string, number]> = [
    ['authenticat', 30], ['authorize', 30], ['authorization', 30],
    ['permission', 25], ['ownership', 25], ['owner', 20],
    ['token', 25], ['session', 25], ['cookie', 20], ['credential', 25],
    ['password', 30], ['secret', 25], ['apikey', 25], ['api_key', 25],
    ['execfile', 35], ['exec(', 30], ['spawn(', 30], ['child_process', 35],
    ['writefile', 30], ['write(', 25], ['unlink', 25], ['mkdir', 20],
    ['path.', 20], ['resolve(', 15], ['join(', 15], ['traversal', 30],
    ['sql', 25], ['query(', 20], ['rawquery', 30], ['queryraw', 30],
    ['inject', 30], ['eval(', 30], ['function(', 10],
    ['router.', 20], ['route(', 20], ['handler', 15], ['middleware', 15],
    ['guard', 20], ['check(', 15], ['validate', 15], ['verify', 15],
    ['login', 25], ['logout', 20], ['register', 20], ['signup', 20],
    ['bootstrap', 25], ['pairing', 25], ['enroll', 20],
    ['rate', 15], ['limit', 15], ['throttle', 15],
    ['origin', 20], ['cors', 20], ['csrf', 25],
    ['csp', 20], ['header', 10], ['helmet', 15],
    ['websocket', 20], ['upgrade', 15], ['rpc', 20],
    ['file', 10], ['read(', 10], ['open(', 10],
    ['import', 5], ['export', 5], ['require(', 5],
    ['config', 10], ['env', 10], ['process.env', 15],
    ['crypto', 15], ['hash', 15], ['encrypt', 20], ['decrypt', 20],
    ['sanitiz', 15], ['escape', 15], ['encode', 10], ['decode', 10],
    ['error', 5], ['catch', 5], ['throw', 5], ['reject', 5],
];

export class InvestigationState {
    private fileCoverages = new Map<string, FileCoverage>();
    private checklist: InvestigationChecklist;
    private toolsUsed = new Set<string>();
    private filesRead = new Set<string>();
    private symbolsSearched = new Set<string>();
    private rootCauses = new Map<string, string>();
    private duplicateReadKeys = new Set<string>();
    private tasks = new Map<string, InvestigationTask>();
    private flowVerifications: FlowVerification[] = [];

    constructor() {
        this.checklist = {
            completed: new Set(),
            required: new Set([
                'initial-read',
                'route-discovery',
                'policy-check',
                'auth-symbol-search',
                'cross-file-flow',
                'config-inspection',
                'all-handlers-reviewed',
                'candidates-verified',
            ]),
            requiredForFindingType: new Map(),
        };
    }

    static normalizePath(p: string): string {
        return p.replace(/\\/g, '/').toLowerCase();
    }

    static parseRange(startLine?: number, endLine?: number, totalLines?: number): LineRange {
        const start = startLine ?? 1;
        const end = endLine ?? totalLines ?? start;
        return { start: Math.min(start, end), end: Math.max(start, end) };
    }

    static rangesOverlap(a: LineRange, b: LineRange): boolean {
        return a.start <= b.end && b.start <= a.end;
    }

    static mergeRanges(ranges: LineRange[]): LineRange[] {
        if (ranges.length <= 1) return [...ranges];
        const sorted = [...ranges].sort((a, b) => a.start - b.start);
        const merged: LineRange[] = [sorted[0]];
        for (let i = 1; i < sorted.length; i++) {
            const last = merged[merged.length - 1];
            if (sorted[i].start <= last.end + 1) {
                last.end = Math.max(last.end, sorted[i].end);
            } else {
                merged.push(sorted[i]);
            }
        }
        return merged;
    }

    static overlapFraction(a: LineRange, b: LineRange): number {
        if (!this.rangesOverlap(a, b)) return 0;
        const overlapStart = Math.max(a.start, b.start);
        const overlapEnd = Math.min(a.end, b.end);
        const overlapLines = overlapEnd - overlapStart + 1;
        const newLines = (b.end - b.start + 1) - overlapLines;
        if (newLines <= 0) return 1.0;
        return overlapLines / (b.end - b.start + 1);
    }

    /**
     * Check if a read would be blocked (duplicate or overlapping) WITHOUT
     * recording it. This lets the loop decide before committing coverage.
     */
    checkRead(filePath: string, startLine?: number, endLine?: number, totalLines?: number): {
        isExactDuplicate: boolean;
        overlapping: boolean;
        overlapFraction: number;
        coverageAfter: LineRange[];
    } {
        const normalized = InvestigationState.normalizePath(filePath);
        const range = InvestigationState.parseRange(startLine, endLine, totalLines);
        const rangeKey = `${normalized}:${startLine || 0}:${endLine || 0}`;
        const coverage = this.fileCoverages.get(normalized);

        const isExactDuplicate = this.duplicateReadKeys.has(rangeKey);
        let maxOverlap = 0;
        if (coverage) {
            for (const existing of coverage.ranges) {
                const frac = InvestigationState.overlapFraction(existing, range);
                if (frac > maxOverlap) maxOverlap = frac;
            }
        }

        return {
            isExactDuplicate,
            overlapping: maxOverlap > 0.5,
            overlapFraction: maxOverlap,
            coverageAfter: coverage ? [...coverage.ranges] : [],
        };
    }

    classifyRead(filePath: string, startLine?: number, endLine?: number, totalLines?: number): ReadValueResult {
        const normalized = InvestigationState.normalizePath(filePath);
        const range = InvestigationState.parseRange(startLine, endLine, totalLines);
        const rangeKey = `${normalized}:${startLine || 0}:${endLine || 0}`;
        const coverage = this.fileCoverages.get(normalized);

        if (startLine !== undefined && endLine !== undefined && startLine > endLine) {
            return {
                classification: 'invalid',
                overlapFraction: 0,
                newLines: 0,
                coverageAfter: coverage ? [...coverage.ranges] : [],
                nextUnreadRange: null,
            };
        }

        if (this.duplicateReadKeys.has(rangeKey)) {
            return {
                classification: 'duplicate',
                overlapFraction: 1,
                newLines: 0,
                coverageAfter: coverage ? [...coverage.ranges] : [],
                nextUnreadRange: this.getNextUnreadRange(filePath),
            };
        }

        let maxOverlap = 0;
        if (coverage) {
            for (const existing of coverage.ranges) {
                const frac = InvestigationState.overlapFraction(existing, range);
                if (frac > maxOverlap) maxOverlap = frac;
            }
        }

        const requestedLines = range.end - range.start + 1;
        const overlapLines = Math.round(maxOverlap * requestedLines);
        const newLines = requestedLines - overlapLines;

        let classification: ReadValueClassification;
        if (maxOverlap === 0) {
            classification = 'new-coverage';
        } else if (maxOverlap > 0.5) {
            classification = 'high-overlap';
        } else {
            classification = 'partial-new-coverage';
        }

        return {
            classification,
            overlapFraction: maxOverlap,
            newLines,
            coverageAfter: coverage ? [...coverage.ranges] : [],
            nextUnreadRange: this.getNextUnreadRange(filePath),
        };
    }

    /**
     * Record a blocked read attempt — increments the blocked counter
     * without merging ranges or counting it as a successful read.
     */
    recordBlockedRead(filePath: string): void {
        const normalized = InvestigationState.normalizePath(filePath);
        let coverage = this.fileCoverages.get(normalized);
        if (!coverage) {
            coverage = {
                filePath: normalized,
                ranges: [],
                totalLines: undefined,
                readCount: 0,
                blockedReadCount: 0,
            };
            this.fileCoverages.set(normalized, coverage);
        }
        coverage.blockedReadCount++;
    }

    recordRead(filePath: string, startLine?: number, endLine?: number, totalLines?: number): {
        overlapping: boolean;
        overlapFraction: number;
        coverageAfter: LineRange[];
    } {
        const normalized = InvestigationState.normalizePath(filePath);
        const range = InvestigationState.parseRange(startLine, endLine, totalLines);

        let coverage = this.fileCoverages.get(normalized);
        if (!coverage) {
            coverage = {
                filePath: normalized,
                ranges: [],
                totalLines,
                readCount: 0,
                blockedReadCount: 0,
            };
            this.fileCoverages.set(normalized, coverage);
        }

        coverage.readCount++;
        if (totalLines) coverage.totalLines = totalLines;

        const overlap = InvestigationState.overlapFraction(
            range,
            { start: 1, end: totalLines ?? range.end },
        );

        let maxOverlap = 0;
        for (const existing of coverage.ranges) {
            const frac = InvestigationState.overlapFraction(existing, range);
            if (frac > maxOverlap) maxOverlap = frac;
        }

        coverage.ranges = InvestigationState.mergeRanges([...coverage.ranges, range]);
        this.filesRead.add(normalized);
        const rangeKey = `${normalized}:${startLine || 0}:${endLine || 0}`;
        this.duplicateReadKeys.add(rangeKey);
        this.markStepComplete('initial-read');

        return {
            overlapping: maxOverlap > 0.5,
            overlapFraction: maxOverlap,
            coverageAfter: [...coverage.ranges],
        };
    }

    /**
     * Record a read using the ACTUAL delivered range (not the requested range).
     *
     * Use this when the executor returns structured metadata telling you
     * exactly which lines were delivered. A large-file read that returns a
     * function map (truncated=true, actualStart=0, actualEnd=0) does NOT
     * record any content coverage — the agent must still read specific
     * line ranges.
     */
    recordActualRead(
        filePath: string,
        actualStart: number,
        actualEnd: number,
        totalLines: number,
        truncated: boolean,
    ): {
        overlapping: boolean;
        overlapFraction: number;
        coverageAfter: LineRange[];
    } {
        const normalized = InvestigationState.normalizePath(filePath);

        let coverage = this.fileCoverages.get(normalized);
        if (!coverage) {
            coverage = {
                filePath: normalized,
                ranges: [],
                totalLines,
                readCount: 0,
                blockedReadCount: 0,
            };
            this.fileCoverages.set(normalized, coverage);
        }

        coverage.readCount++;
        if (totalLines) coverage.totalLines = totalLines;

        // Truncated reads (function map) deliver no content lines — don't
        // record any range coverage and don't complete initial-read. The
        // agent must still read specific sections with actual content.
        if (truncated || actualStart === 0 || actualEnd === 0) {
            this.filesRead.add(normalized);
            return {
                overlapping: false,
                overlapFraction: 0,
                coverageAfter: [...coverage.ranges],
            };
        }

        // Reject inverted ranges (actualStart > actualEnd) — these can
        // happen when startLine > totalLines. Don't record coverage.
        if (actualStart > actualEnd) {
            this.filesRead.add(normalized);
            return {
                overlapping: false,
                overlapFraction: 0,
                coverageAfter: [...coverage.ranges],
            };
        }

        const range: LineRange = { start: actualStart, end: actualEnd };

        let maxOverlap = 0;
        for (const existing of coverage.ranges) {
            const frac = InvestigationState.overlapFraction(existing, range);
            if (frac > maxOverlap) maxOverlap = frac;
        }

        coverage.ranges = InvestigationState.mergeRanges([...coverage.ranges, range]);
        this.filesRead.add(normalized);
        const rangeKey = `${normalized}:${actualStart || 0}:${actualEnd || 0}`;
        this.duplicateReadKeys.add(rangeKey);
        this.markStepComplete('initial-read');

        return {
            overlapping: maxOverlap > 0.5,
            overlapFraction: maxOverlap,
            coverageAfter: [...coverage.ranges],
        };
    }

    getCoverage(filePath: string): FileCoverage | undefined {
        return this.fileCoverages.get(InvestigationState.normalizePath(filePath));
    }

    isCovered(filePath: string, startLine?: number, endLine?: number): boolean {
        const coverage = this.getCoverage(filePath);
        if (!coverage) return false;
        if (startLine === undefined && endLine === undefined) return coverage.ranges.length > 0;
        const range = InvestigationState.parseRange(startLine, endLine, coverage.totalLines);
        return coverage.ranges.some(r =>
            r.start <= range.start && r.end >= range.end,
        );
    }

    /**
     * Return the gaps in coverage for a file — the line ranges that have NOT
     * been read yet. Returns [] if the file is fully covered or not tracked.
     */
    getUncoveredRanges(filePath: string): LineRange[] {
        const coverage = this.getCoverage(filePath);
        if (!coverage || !coverage.totalLines) return [];
        if (coverage.ranges.length === 0) {
            return [{ start: 1, end: coverage.totalLines }];
        }
        const gaps: LineRange[] = [];
        const sorted = [...coverage.ranges].sort((a, b) => a.start - b.start);

        // Gap before the first range
        if (sorted[0].start > 1) {
            gaps.push({ start: 1, end: sorted[0].start - 1 });
        }

        // Gaps between ranges
        for (let i = 0; i < sorted.length - 1; i++) {
            const gapStart = sorted[i].end + 1;
            const gapEnd = sorted[i + 1].start - 1;
            if (gapStart <= gapEnd) {
                gaps.push({ start: gapStart, end: gapEnd });
            }
        }

        // Gap after the last range
        const last = sorted[sorted.length - 1];
        if (last.end < coverage.totalLines) {
            gaps.push({ start: last.end + 1, end: coverage.totalLines });
        }

        return gaps;
    }

    /**
     * Return the next unread chunk for a file, using a chunk-size policy
     * based on file size:
     *   < 300 lines       full-file read (chunk = totalLines)
     *   300-1,000 lines   250-line chunks
     *   1,000-5,000       300-line chunks
     *   > 5,000 lines     400-line chunks
     *
     * Returns null if the file is fully covered or not tracked.
     */
    getNextUnreadRange(filePath: string, chunkSize?: number): LineRange | null {
        const coverage = this.getCoverage(filePath);
        if (!coverage || !coverage.totalLines) return null;

        const chunk = chunkSize ?? InvestigationState.chunkSizeForLines(coverage.totalLines);
        const gaps = this.getUncoveredRanges(filePath);
        if (gaps.length === 0) return null;

        const firstGap = gaps[0];
        const end = Math.min(firstGap.start + chunk - 1, firstGap.end);
        return { start: firstGap.start, end };
    }

    getPrioritizedUnreadRange(filePath: string, fileContent: string, chunkSize?: number, candidateLocations?: LineRange[], functionBoundaries?: { name: string; startLine: number; endLine: number }[]): LineRange | null {
        const coverage = this.getCoverage(filePath);
        if (!coverage || !coverage.totalLines) return null;

        const chunk = chunkSize ?? InvestigationState.chunkSizeForLines(coverage.totalLines);
        const gaps = this.getUncoveredRanges(filePath);
        if (gaps.length === 0) return null;

        if (gaps.length === 1) {
            const end = Math.min(gaps[0].start + chunk - 1, gaps[0].end);
            return this.snapToFunctionBoundary(gaps[0].start, end, functionBoundaries);
        }

        const lines = fileContent.split('\n');
        let bestGap = gaps[0];
        let bestScore = -1;

        for (const gap of gaps) {
            let score = 0;
            const gapLines = lines.slice(Math.max(0, gap.start - 1), Math.min(lines.length, gap.end));
            const gapText = gapLines.join('\n').toLowerCase();

            for (const [pattern, weight] of SECURITY_KEYWORD_WEIGHTS) {
                if (gapText.includes(pattern)) {
                    score += weight;
                }
            }

            if (candidateLocations) {
                for (const loc of candidateLocations) {
                    if (loc.start >= gap.start && loc.start <= gap.end) {
                        score += 100;
                    }
                    if (loc.end >= gap.start && loc.end <= gap.end) {
                        score += 50;
                    }
                }
            }

            if (functionBoundaries) {
                for (const fn of functionBoundaries) {
                    if (fn.startLine >= gap.start && fn.startLine <= gap.end) {
                        score += 15;
                    }
                    if (fn.endLine >= gap.start && fn.endLine <= gap.end) {
                        score += 10;
                    }
                }
            }

            score += Math.min(gap.end - gap.start, chunk) * 0.01;

            if (score > bestScore) {
                bestScore = score;
                bestGap = gap;
            }
        }

        const end = Math.min(bestGap.start + chunk - 1, bestGap.end);
        return this.snapToFunctionBoundary(bestGap.start, end, functionBoundaries);
    }

    private snapToFunctionBoundary(start: number, end: number, boundaries?: { name: string; startLine: number; endLine: number }[]): LineRange {
        if (!boundaries || boundaries.length === 0) return { start, end };
        let snappedStart = start;
        let snappedEnd = end;
        for (const fn of boundaries) {
            if (fn.startLine >= start && fn.startLine <= end && fn.endLine > end) {
                snappedEnd = Math.min(fn.endLine, end + 100);
            }
            if (fn.endLine >= start && fn.endLine <= end && fn.startLine < start) {
                snappedStart = Math.max(fn.startLine, start - 20);
            }
        }
        return { start: snappedStart, end: snappedEnd };
    }

    /**
     * Return coverage percentage for a file (0-100). Returns 0 if the file
     * is not tracked or has no totalLines.
     */
    getCoveragePercent(filePath: string): number {
        const coverage = this.getCoverage(filePath);
        if (!coverage || !coverage.totalLines) return 0;
        const coveredLines = coverage.ranges.reduce(
            (sum, r) => sum + (r.end - r.start + 1), 0,
        );
        return Math.round((coveredLines / coverage.totalLines) * 100);
    }

    static chunkSizeForLines(totalLines: number): number {
        if (totalLines < 300) return totalLines;
        if (totalLines < 1000) return 250;
        if (totalLines < 5000) return 300;
        return 400;
    }

    recordToolUse(toolType: string): void {
        this.toolsUsed.add(toolType);

        switch (toolType) {
            case 'check_policy':
                this.markStepComplete('policy-check');
                break;
            case 'search_code':
                if (this.checklist.completed.has('initial-read')) {
                    this.markStepComplete('auth-symbol-search');
                }
                break;
            case 'trace_flow':
            case 'trace_flow_cross_file':
                this.markStepComplete('ownership-analysis');
                break;
            case 'read_config':
                this.markStepComplete('config-inspection');
                break;
            case 'get_endpoints':
                this.markStepComplete('route-discovery');
                break;
            case 'find_tests':
                this.markStepComplete('tests-found');
                break;
        }
    }

    recordFlowVerification(
        filePath: string,
        tool: string,
        status: FlowVerificationStatus,
        flowCount: number,
        reason: string,
        structured?: {
            riskId?: string;
            candidateId?: string;
            source?: { filePath: string; symbol?: string; line?: number };
            sink?: { filePath: string; symbol?: string; line?: number };
            hops?: Array<{ filePath: string; symbol?: string; line?: number; description?: string }>;
            truncated?: boolean;
            error?: string;
        },
    ): void {
        this.flowVerifications.push({
            filePath,
            tool,
            status,
            flowCount,
            reason,
            timestamp: Date.now(),
            riskId: structured?.riskId,
            candidateId: structured?.candidateId,
            source: structured?.source,
            sink: structured?.sink,
            hops: structured?.hops,
            truncated: structured?.truncated,
            error: structured?.error,
        });
        if (status === 'confirmed' || status === 'refuted') {
            this.markStepComplete('cross-file-flow');
        }
    }

    getFlowVerifications(): FlowVerification[] {
        return [...this.flowVerifications];
    }

    hasClassifiedFlow(): boolean {
        return this.flowVerifications.some(v => v.status !== 'blocked');
    }

    hasResolvedFlow(riskId?: string): boolean {
        if (riskId) {
            return this.flowVerifications.some(v => v.riskId === riskId && (v.status === 'confirmed' || v.status === 'refuted'));
        }
        return this.flowVerifications.some(v => v.status === 'confirmed' || v.status === 'refuted');
    }

    recordSymbolSearch(symbol: string): void {
        this.symbolsSearched.add(symbol);
    }

    markStepComplete(step: InvestigationStep): void {
        this.checklist.completed.add(step);
    }

    markAllHandlersReviewed(): void {
        this.markStepComplete('all-handlers-reviewed');
    }

    markCandidatesVerified(): void {
        this.markStepComplete('candidates-verified');
    }

    markArchitectureRisksAddressed(): void {
        this.markStepComplete('architecture-risks-addressed');
    }

    /**
     * Replace the required checklist with a specific set of steps.
     * Used by target-specific investigation profiles.
     */
    setRequiredSteps(steps: InvestigationStep[]): void {
        this.checklist.required = new Set(steps);
    }

    // ── Investigation task tracking ──────────────────────────────────────────

    addInvestigationTasks(tasks: InvestigationTask[]): void {
        for (const task of tasks) {
            if (!this.tasks.has(task.id)) {
                this.tasks.set(task.id, { ...task });
            }
        }
    }

    updateTaskStatus(taskId: string, status: InvestigationTaskStatus): void {
        const task = this.tasks.get(taskId);
        if (task) {
            task.status = status;
            if (this.tasks.size > 0 && [...this.tasks.values()].every(t => t.status !== 'pending')) {
                this.markStepComplete('architecture-risks-addressed');
            }
        }
    }

    getPendingTasks(): InvestigationTask[] {
        return [...this.tasks.values()].filter(t => t.status === 'pending');
    }

    getUnresolvedTasks(): InvestigationTask[] {
        return [...this.tasks.values()].filter(t =>
            t.status === 'pending' || t.status === 'blocked',
        );
    }

    getAllTasks(): InvestigationTask[] {
        return [...this.tasks.values()];
    }

    getIncompleteSteps(): InvestigationStep[] {
        const incomplete: InvestigationStep[] = [];
        for (const required of this.checklist.required) {
            if (!this.checklist.completed.has(required)) {
                incomplete.push(required);
            }
        }
        return incomplete;
    }

    getCompletedSteps(): InvestigationStep[] {
        return [...this.checklist.completed];
    }

    getToolsUsed(): string[] {
        return [...this.toolsUsed];
    }

    getFilesRead(): string[] {
        return [...this.filesRead];
    }

    getReadCount(filePath: string): number {
        return this.getCoverage(filePath)?.readCount ?? 0;
    }

    getCoverageSummary(filePath: string): {
        totalLines: number;
        coveredLines: number;
        coveragePercentage: number;
        uncoveredRangeCount: number;
        largestUncoveredRange: LineRange | null;
        readCount: number;
        blockedReadCount: number;
    } {
        const coverage = this.getCoverage(filePath);
        const totalLines = coverage?.totalLines ?? 0;
        const coveredLines = (coverage?.ranges ?? []).reduce((sum, r) => sum + (r.end - r.start + 1), 0);
        const uncovered = this.getUncoveredRanges(filePath);
        const largestUncovered = uncovered.length > 0
            ? uncovered.reduce((max, r) => (r.end - r.start) > (max.end - max.start) ? r : max)
            : null;
        return {
            totalLines,
            coveredLines,
            coveragePercentage: totalLines > 0 ? Math.round(100 * coveredLines / totalLines) : 0,
            uncoveredRangeCount: uncovered.length,
            largestUncoveredRange: largestUncovered,
            readCount: coverage?.readCount ?? 0,
            blockedReadCount: coverage?.blockedReadCount ?? 0,
        };
    }

    registerRootCause(rootCauseId: string, description: string): void {
        if (!this.rootCauses.has(rootCauseId)) {
            this.rootCauses.set(rootCauseId, description);
        }
    }

    getRootCauses(): Map<string, string> {
        return new Map(this.rootCauses);
    }

    getRecommendedRecoveryAction(): string | null {
        const incomplete = this.getIncompleteSteps();
        if (incomplete.length === 0) return null;
        const step = incomplete[0];
        switch (step) {
            case 'route-discovery': return 'get_endpoints';
            case 'policy-check': return 'check_policy';
            case 'auth-symbol-search': return 'search_code';
            case 'cross-file-flow': return 'trace_flow_cross_file';
            case 'config-inspection': return 'read_config';
            case 'ownership-analysis': return 'trace_flow_cross_file';
            case 'tests-found': return 'find_tests';
            default: return null;
        }
    }

    formatChecklistForPrompt(): string {
        const incomplete = this.getIncompleteSteps();
        const completed = this.getCompletedSteps();

        if (incomplete.length === 0) {
            return `[Investigation checklist: ALL COMPLETE]`;
        }

        const lines: string[] = ['[Investigation checklist — incomplete steps block finish with 0 findings:]', ''];
        for (const step of incomplete) {
            const desc = this.stepDescription(step);
            lines.push(`  ✗ ${step}: ${desc}`);
        }
        if (completed.length > 0) {
            lines.push('');
            lines.push('  Completed:');
            for (const step of completed) {
                lines.push(`  ✓ ${step}`);
            }
        }
        return lines.join('\n');
    }

    private stepDescription(step: InvestigationStep): string {
        switch (step) {
            case 'initial-read': return 'Read the target file to understand the code';
            case 'route-discovery': return 'Call get_endpoints to discover sibling routes';
            case 'policy-check': return 'Call check_policy on route handler files';
            case 'auth-symbol-search': return 'Search for auth functions used in the target';
            case 'cross-file-flow': return 'Trace data flow with trace_flow or trace_flow_cross_file';
            case 'config-inspection': return 'Inspect security configuration with read_config';
            case 'ownership-analysis': return 'Trace ownership through repository/service layer';
            case 'tests-found': return 'Find tests for the target code';
            case 'architecture-risks-addressed': return 'Address architecture-scout risks for the target file';
            case 'all-handlers-reviewed': return 'Review ALL handlers in the target file';
            case 'candidates-verified': return 'Verify each candidate finding with tools';
            default: return step;
        }
    }
}
