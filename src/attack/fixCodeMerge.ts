/**
 * Fixed-code merge helper — reconstructs the full file by replacing the
 * declared line range with the proposed fixed code.
 *
 * The fixer API returns `fixed_code` + `replace_range` (start_line, end_line).
 * Before fix verification, we need the FULL file with the fix applied so the
 * verify subagent can test whether the original exploit still reproduces.
 *
 * Rules:
 *   - Lines are 1-indexed, end_line is inclusive.
 *   - Lines before start_line and after end_line are preserved.
 *   - Malformed ranges (start > end, start < 1, end > total lines) are rejected.
 *   - The merged code is kept in memory only — never written to the workspace.
 */

export interface ReplaceRange {
    start_line: number;
    end_line: number;
}

export interface MergeResult {
    ok: true;
    mergedCode: string;
}

export interface MergeError {
    ok: false;
    error: string;
}

export function mergeFixedCode(
    originalCode: string,
    fixedCode: string,
    replaceRange: ReplaceRange,
): MergeResult | MergeError {
    const { start_line, end_line } = replaceRange;

    if (!Number.isInteger(start_line) || !Number.isInteger(end_line)) {
        return { ok: false, error: `replace_range lines must be integers (got start=${start_line}, end=${end_line})` };
    }
    if (start_line < 1) {
        return { ok: false, error: `replace_range start_line must be >= 1 (got ${start_line})` };
    }
    if (end_line < start_line) {
        return { ok: false, error: `replace_range end_line (${end_line}) must be >= start_line (${start_line})` };
    }

    const originalLines = originalCode.split('\n');
    if (end_line > originalLines.length) {
        return { ok: false, error: `replace_range end_line (${end_line}) exceeds file length (${originalLines.length} lines)` };
    }

    // Lines before the replacement (1-indexed → 0-indexed slice).
    const before = originalLines.slice(0, start_line - 1);
    // Lines after the replacement (end_line is inclusive → slice from end_line).
    const after = originalLines.slice(end_line);

    // The fixed code may be multi-line — split it and join with the preserved lines.
    const fixedLines = fixedCode.length > 0 ? fixedCode.split('\n') : [];

    const mergedLines = [...before, ...fixedLines, ...after];
    return { ok: true, mergedCode: mergedLines.join('\n') };
}
