import { describe, it, expect } from 'vitest';
import {
    planFileSegments,
    planFileSegmentsForPath,
    countFileLines,
    formatSegmentEstimate,
    segmentCreditRange,
} from '../src/attack/fileSegments';

function functionsFile(sizes: number[]): { content: string; boundaries: { name: string; startLine: number; endLine: number }[] } {
    const lines: string[] = [];
    const boundaries: { name: string; startLine: number; endLine: number }[] = [];
    sizes.forEach((size, i) => {
        const startLine = lines.length + 1;
        lines.push(`export function f${i}(req: any) {`);
        for (let j = 0; j < size - 2; j++) lines.push(`    const v${j} = req.body.a${j};`);
        lines.push('}');
        boundaries.push({ name: `f${i}`, startLine, endLine: lines.length });
        lines.push('');
    });
    return { content: lines.join('\n'), boundaries };
}

function insideAnyFunction(line: number, boundaries: { startLine: number; endLine: number }[]): boolean {
    return boundaries.some(b => line >= b.startLine && line < b.endLine);
}

describe('planFileSegments', () => {
    it('does not split files of 2,000 lines or less', () => {
        const content = Array.from({ length: 2000 }, (_, i) => `const a${i} = ${i};`).join('\n');
        expect(planFileSegments(content)).toEqual([{ index: 1, total: 1, startLine: 1, endLine: 2000 }]);
        expect(planFileSegments('const a = 1;\n')).toEqual([{ index: 1, total: 1, startLine: 1, endLine: 1 }]);
    });

    it('cuts only between top-level functions, near even marks', () => {
        const { content, boundaries } = functionsFile(Array(47).fill(100));
        const lineCount = countFileLines(content);
        expect(lineCount).toBeGreaterThan(4600);

        const parts = planFileSegments(content, boundaries);

        expect(parts).toHaveLength(4);
        expect(parts[0].startLine).toBe(1);
        expect(parts[parts.length - 1].endLine).toBe(lineCount);
        for (let i = 0; i < parts.length; i++) {
            expect(parts[i].index).toBe(i + 1);
            expect(parts[i].total).toBe(4);
            if (i > 0) expect(parts[i].startLine).toBe(parts[i - 1].endLine + 1);
            if (i < parts.length - 1) expect(insideAnyFunction(parts[i].endLine, boundaries)).toBe(false);
            const size = parts[i].endLine - parts[i].startLine + 1;
            expect(size).toBeGreaterThan(1000);
            expect(size).toBeLessThan(1400);
        }
    });

    it('ignores nested boundaries and never cuts inside an outer function', () => {
        const { content, boundaries } = functionsFile([1200, 1200, 1200]);
        const nested = [...boundaries, { name: 'inner', startLine: 1300, endLine: 1500 }];
        const parts = planFileSegments(content, nested);
        for (const p of parts.slice(0, -1)) {
            expect(insideAnyFunction(p.endLine, boundaries)).toBe(false);
        }
    });

    it('merges a part shorter than 400 lines into the previous one', () => {
        const { content, boundaries } = functionsFile([1500, 650, 50]);
        const lineCount = countFileLines(content);
        const parts = planFileSegments(content, boundaries);
        expect(parts).toHaveLength(2);
        expect(parts[1].endLine).toBe(lineCount);
        for (const p of parts) expect(p.endLine - p.startLine + 1).toBeGreaterThanOrEqual(400);
    });

    it('cuts between inner functions of a wrapper that spans most of the file', () => {
        const inner = functionsFile([700, 700, 700, 700, 700]);
        const wrapperLines = ['export const layer = make(function* () {', ...inner.content.split('\n').map(l => `  ${l}`), '});'];
        const content = wrapperLines.join('\n');
        const total = countFileLines(content);
        const innerBoundaries = inner.boundaries.map(b => ({ ...b, startLine: b.startLine + 1, endLine: b.endLine + 1 }));
        const boundaries = [{ name: 'layer', startLine: 1, endLine: total }, ...innerBoundaries];
        const parts = planFileSegments(content, boundaries);
        expect(parts.length).toBe(Math.ceil(total / 1500));
        for (const p of parts.slice(0, -1)) expect(insideAnyFunction(p.endLine, innerBoundaries)).toBe(false);
    });

    it('splits inside a single wrapper function that spans the whole file', () => {
        const { content, boundaries } = functionsFile([3000]);
        const parts = planFileSegments(content, boundaries);
        expect(parts).toHaveLength(2);
        expect(parts[1].endLine).toBe(countFileLines(content));
    });

    it('falls back to blank lines near each mark when no boundaries are known', () => {
        const lines: string[] = [];
        for (let block = 0; block < 60; block++) {
            lines.push(`const block${block} = {`);
            for (let j = 0; j < 48; j++) lines.push(`    k${j}: ${j},`);
            lines.push('};');
            lines.push('');
        }
        const content = lines.join('\n');
        const parts = planFileSegments(content);
        expect(parts.length).toBe(Math.ceil(countFileLines(content) / 1500));
        for (const p of parts.slice(0, -1)) {
            expect(lines[p.endLine - 1].trim()).toBe('');
        }
    });

    it('falls back to the mark itself when the file has no blank lines', () => {
        const content = Array.from({ length: 3200 }, (_, i) => `x${i}();`).join('\n');
        const parts = planFileSegments(content);
        expect(parts.map(p => [p.startLine, p.endLine])).toEqual([[1, 1067], [1068, 2133], [2134, 3200]]);
    });

    it('uses real function boundaries for a TypeScript path', async () => {
        const { content } = functionsFile(Array(47).fill(100));
        const parts = await planFileSegmentsForPath(content, 'src/big.ts');
        expect(parts).toHaveLength(4);
    });
});

describe('segment estimates', () => {
    it('formats the up-front estimate', () => {
        expect(formatSegmentEstimate(4707, 4)).toBe('4,707 lines → 4 parts, 20–60 credits');
        expect(segmentCreditRange(3)).toEqual({ min: 15, max: 45 });
    });
});
