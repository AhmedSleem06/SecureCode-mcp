import {
    AGENT_SCAN_DEFAULTS,
    SEGMENT_MIN_LINES,
    SEGMENT_TARGET_LINES,
    SEGMENT_THRESHOLD_LINES,
} from './agentScanProtocol';

export interface FileSegmentBoundary {
    name: string;
    startLine: number;
    endLine: number;
}

export interface PlannedFileSegment {
    index: number;
    total: number;
    startLine: number;
    endLine: number;
}

export function countFileLines(content: string): number {
    if (content.length === 0) return 0;
    const lines = content.split('\n');
    return lines[lines.length - 1] === '' ? lines.length - 1 : lines.length;
}

const CONTAINER_LINES = Math.round(SEGMENT_TARGET_LINES * 1.5);

function topLevelRanges(boundaries: FileSegmentBoundary[], lineCount: number): Array<{ startLine: number; endLine: number }> {
    const sorted = boundaries
        .filter(b => Number.isFinite(b.startLine) && Number.isFinite(b.endLine) && b.startLine >= 1 && b.endLine >= b.startLine)
        .filter(b => Math.min(b.endLine, lineCount) - b.startLine + 1 <= CONTAINER_LINES)
        .map(b => ({ startLine: b.startLine, endLine: Math.min(b.endLine, lineCount) }))
        .sort((a, b) => a.startLine - b.startLine || b.endLine - a.endLine);
    const out: Array<{ startLine: number; endLine: number }> = [];
    for (const r of sorted) {
        const last = out[out.length - 1];
        if (last && r.startLine <= last.endLine) {
            if (r.endLine > last.endLine) last.endLine = r.endLine;
            continue;
        }
        out.push({ ...r });
    }
    return out;
}

const LEADING_TRIVIA = /^\s*(\/\/|\/\*|\*|@|#)/;

function boundaryCutCandidates(lines: string[], ranges: Array<{ startLine: number; endLine: number }>): number[] {
    const set = new Set<number>();
    let prevEnd = 0;
    for (const r of ranges) {
        let k = r.startLine - 1;
        while (k > prevEnd && LEADING_TRIVIA.test(lines[k - 1] ?? '')) k--;
        if (k >= 1) set.add(k);
        set.add(r.endLine);
        prevEnd = r.endLine;
    }
    return [...set].sort((a, b) => a - b);
}

function blankLineCutCandidates(lines: string[]): { topLevel: number[]; anyBlank: number[] } {
    const topLevel: number[] = [];
    const anyBlank: number[] = [];
    for (let i = 0; i < lines.length - 1; i++) {
        if (lines[i].trim() !== '') continue;
        const line = i + 1;
        anyBlank.push(line);
        let j = i + 1;
        while (j < lines.length && lines[j].trim() === '') j++;
        if (j < lines.length && !/^\s/.test(lines[j]) && !/^[)\]}]/.test(lines[j])) topLevel.push(line);
    }
    return { topLevel, anyBlank };
}

const FALLBACK_WINDOW_LINES = 300;

function pickCut(candidates: number[], start: number, lineCount: number, mark: number, window = Infinity): number | undefined {
    let best: number | undefined;
    for (const c of candidates) {
        if (c < start + SEGMENT_MIN_LINES - 1 || c >= lineCount) continue;
        if (Math.abs(c - mark) > window) continue;
        if (best === undefined || Math.abs(c - mark) < Math.abs(best - mark)) best = c;
    }
    return best;
}

export function planFileSegments(content: string, functionBoundaries?: FileSegmentBoundary[] | null): PlannedFileSegment[] {
    const lineCount = countFileLines(content);
    if (lineCount <= SEGMENT_THRESHOLD_LINES) {
        return [{ index: 1, total: 1, startLine: 1, endLine: Math.max(1, lineCount) }];
    }

    const lines = content.split('\n').slice(0, lineCount);
    const ranges = functionBoundaries && functionBoundaries.length > 0 ? topLevelRanges(functionBoundaries, lineCount) : [];
    const boundaryCuts = ranges.length > 0 ? boundaryCutCandidates(lines, ranges) : [];
    const blanks = blankLineCutCandidates(lines);
    const outsideRanges = (line: number) => !ranges.some(r => line >= r.startLine && line < r.endLine);
    const freeTopLevel = blanks.topLevel.filter(outsideRanges);
    const freeAnyBlank = blanks.anyBlank.filter(outsideRanges);

    const chooseCut = (start: number, mark: number): number | undefined => {
        if (boundaryCuts.length > 0) {
            const near = pickCut(boundaryCuts, start, lineCount, mark, FALLBACK_WINDOW_LINES);
            if (near !== undefined) return near;
        }
        return pickCut(freeTopLevel, start, lineCount, mark, FALLBACK_WINDOW_LINES)
            ?? pickCut(freeAnyBlank, start, lineCount, mark, FALLBACK_WINDOW_LINES)
            ?? (boundaryCuts.length > 0 ? pickCut(boundaryCuts, start, lineCount, mark) : undefined)
            ?? pickCut([mark], start, lineCount, mark);
    };

    const parts: Array<{ startLine: number; endLine: number }> = [];
    const wanted = Math.ceil(lineCount / SEGMENT_TARGET_LINES);
    let start = 1;
    for (let k = 1; k < wanted; k++) {
        const mark = Math.round((k * lineCount) / wanted);
        if (mark < start) continue;
        const cut = chooseCut(start, mark);
        if (cut === undefined) continue;
        parts.push({ startLine: start, endLine: cut });
        start = cut + 1;
    }
    parts.push({ startLine: start, endLine: lineCount });

    const merged: Array<{ startLine: number; endLine: number }> = [];
    for (const p of parts) {
        const prev = merged[merged.length - 1];
        if (prev && p.endLine - p.startLine + 1 < SEGMENT_MIN_LINES) {
            prev.endLine = p.endLine;
        } else {
            merged.push({ ...p });
        }
    }

    return merged.map((p, i) => ({ index: i + 1, total: merged.length, startLine: p.startLine, endLine: p.endLine }));
}

export async function planFileSegmentsForPath(content: string, relPath: string): Promise<PlannedFileSegment[]> {
    if (countFileLines(content) <= SEGMENT_THRESHOLD_LINES) return planFileSegments(content);
    let boundaries: FileSegmentBoundary[] | null = null;
    try {
        const { extractFunctionBoundaries } = await import('./agentScanExecutor');
        boundaries = await extractFunctionBoundaries(content, relPath);
    } catch {
        boundaries = null;
    }
    return planFileSegments(content, boundaries);
}

export function segmentCreditRange(parts: number): { min: number; max: number } {
    return {
        min: parts * AGENT_SCAN_DEFAULTS.creditsPerRun,
        max: parts * AGENT_SCAN_DEFAULTS.maxCreditsPerRun,
    };
}

export function formatLineNumber(n: number): string {
    return n.toLocaleString('en-US');
}

export function formatSegmentEstimate(lineCount: number, parts: number): string {
    const { min, max } = segmentCreditRange(parts);
    return `${formatLineNumber(lineCount)} lines → ${parts} parts, ${min}–${max} credits`;
}

export function formatSegmentRange(segment: { startLine: number; endLine: number }): string {
    return `${formatLineNumber(segment.startLine)}–${formatLineNumber(segment.endLine)}`;
}
