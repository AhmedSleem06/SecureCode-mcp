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

export interface FileCoverage {
    /** Normalized file path (lowercase, forward slashes). */
    filePath: string;
    /** Merged, non-overlapping ranges that have been read. */
    ranges: LineRange[];
    /** Total line count of the file (if known). */
    totalLines?: number;
    /** Number of read_file calls on this file (including blocked ones). */
    readCount: number;
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

export class InvestigationState {
    private fileCoverages = new Map<string, FileCoverage>();
    private checklist: InvestigationChecklist;
    private toolsUsed = new Set<string>();
    private filesRead = new Set<string>();
    private symbolsSearched = new Set<string>();
    private rootCauses = new Map<string, string>();

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
                this.markStepComplete('cross-file-flow');
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

    registerRootCause(rootCauseId: string, description: string): void {
        if (!this.rootCauses.has(rootCauseId)) {
            this.rootCauses.set(rootCauseId, description);
        }
    }

    getRootCauses(): Map<string, string> {
        return new Map(this.rootCauses);
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
