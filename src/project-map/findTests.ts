/**
 * Test discovery — finds test files that exercise a source file or symbol.
 *
 * Two strategies:
 *   1. Naming convention: derive candidate test file paths from the source
 *      file (src/foo.ts → tests/foo.test.ts, src/foo.test.ts, etc.)
 *   2. Symbol reference: if a symbol name is provided, search all test files
 *      in the workspace for references to that symbol.
 *
 * Returns ranked results with match type and confidence.
 *
 * Security:
 *   - All paths workspace-confined via resolveWorkspacePath
 *   - Output truncated to 16KB
 *   - No file contents returned — only paths and matched lines
 */

import * as fs from 'fs';
import * as path from 'path';
import { resolveWorkspacePath } from '../utils/files';
import { searchCode } from '../utils/searchCode';

export interface TestFinding {
    /** Workspace-relative test file path. */
    filePath: string;
    /** How this test was found. */
    matchType: 'naming' | 'symbol';
    /** Confidence 0-1. */
    confidence: number;
    /** Matched line numbers (for symbol matches). */
    matchedLines?: number[];
    /** Preview of matched lines (for symbol matches). */
    matchedPreviews?: string[];
}

const MAX_RESULTS = 30;
const MAX_PREVIEW_LENGTH = 120;

function getBaseName(filePath: string): string {
    const ext = path.extname(filePath);
    return path.basename(filePath, ext);
}

function getExt(filePath: string): string {
    return path.extname(filePath).toLowerCase();
}

function isTestFile(fileName: string): boolean {
    const lower = fileName.toLowerCase();
    return (
        lower.endsWith('.test.ts') ||
        lower.endsWith('.test.tsx') ||
        lower.endsWith('.test.js') ||
        lower.endsWith('.test.jsx') ||
        lower.endsWith('.test.mjs') ||
        lower.endsWith('.test.cjs') ||
        lower.endsWith('.spec.ts') ||
        lower.endsWith('.spec.tsx') ||
        lower.endsWith('.spec.js') ||
        lower.endsWith('.spec.jsx') ||
        lower.endsWith('.spec.mjs') ||
        lower.endsWith('.spec.cjs') ||
        lower.startsWith('test_') && lower.endsWith('.py') ||
        lower.endsWith('_test.py')
    );
}

function deriveTestCandidates(filePath: string): string[] {
    const ext = getExt(filePath);
    const baseName = getBaseName(filePath);
    const dir = path.dirname(filePath);
    const candidates: string[] = [];

    if (ext === '.py') {
        const pyTestName = `test_${baseName}.py`;
        const dirs = ['tests', 'test', dir, 'src', ''];
        for (const d of dirs) {
            candidates.push(d ? path.join(d, pyTestName) : pyTestName);
        }
        candidates.push(path.join(dir, `test_${baseName}.py`));
        return candidates;
    }

    const tsExts = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
    const testDirs = ['tests', 'test', '__tests__', '__test__', 'spec', ''];
    const sameDir = dir;

    for (const testExt of tsExts) {
        for (const suffix of ['.test', '.spec']) {
            for (const d of testDirs) {
                candidates.push(d ? path.join(d, baseName + suffix + testExt) : baseName + suffix + testExt);
            }
            candidates.push(path.join(sameDir, baseName + suffix + testExt));
        }
    }

    return candidates;
}

function findTestsByNaming(
    workspaceRoot: string,
    filePath: string,
): TestFinding[] {
    const candidates = deriveTestCandidates(filePath);
    const results: TestFinding[] = [];
    const seen = new Set<string>();

    for (const candidate of candidates) {
        try {
            const abs = resolveWorkspacePath(workspaceRoot, candidate);
            if (fs.existsSync(abs)) {
                const rel = path.relative(workspaceRoot, abs).replace(/\\/g, '/');
                if (seen.has(rel)) continue;
                seen.add(rel);
                results.push({
                    filePath: rel,
                    matchType: 'naming',
                    confidence: 0.9,
                });
            }
        } catch {
            // path outside workspace — skip
        }
    }

    return results;
}

async function findTestsBySymbol(
    workspaceRoot: string,
    symbol: string,
    existing: Set<string>,
): Promise<TestFinding[]> {
    const results: TestFinding[] = [];
    const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = `\\b${escaped}\\b`;

    const testGlobs = [
        '*.test.ts', '*.test.tsx', '*.test.js', '*.test.jsx',
        '*.test.mjs', '*.test.cjs',
        '*.spec.ts', '*.spec.tsx', '*.spec.js', '*.spec.jsx',
        '*.spec.mjs', '*.spec.cjs',
        'test_*.py', '*_test.py',
    ];

    const byFile = new Map<string, { lines: number[]; previews: string[] }>();

    for (const glob of testGlobs) {
        try {
            const result = await searchCode(workspaceRoot, pattern, glob);
            for (const hit of result.hits || []) {
                const fileName = path.basename(hit.path);
                if (!isTestFile(fileName)) continue;

                const existing_ = byFile.get(hit.path);
                if (existing_) {
                    if (existing_.lines.length < 5) {
                        existing_.lines.push(hit.line);
                        existing_.previews.push(hit.text.slice(0, MAX_PREVIEW_LENGTH));
                    }
                } else {
                    byFile.set(hit.path, {
                        lines: [hit.line],
                        previews: [hit.text.slice(0, MAX_PREVIEW_LENGTH)],
                    });
                }
            }
        } catch {
            // search failed for this glob — continue
        }
    }

    for (const [filePath, { lines, previews }] of byFile) {
        if (existing.has(filePath)) continue;
        results.push({
            filePath,
            matchType: 'symbol',
            confidence: 0.7,
            matchedLines: lines,
            matchedPreviews: previews,
        });
    }

    return results;
}

export async function findTests(
    workspaceRoot: string,
    filePath: string,
    symbol?: string,
): Promise<string> {
    try {
        resolveWorkspacePath(workspaceRoot, filePath);
    } catch (e: any) {
        return `Error: ${e.message}`;
    }

    const parts: string[] = [];

    if (!fs.existsSync(resolveWorkspacePath(workspaceRoot, filePath))) {
        return `Source file not found: ${filePath}`;
    }

    const namingResults = findTestsByNaming(workspaceRoot, filePath);
    const namingPaths = new Set(namingResults.map(r => r.filePath));

    let symbolResults: TestFinding[] = [];
    if (symbol) {
        symbolResults = await findTestsBySymbol(workspaceRoot, symbol, namingPaths);
    }

    const allResults = [...namingResults, ...symbolResults].slice(0, MAX_RESULTS);

    if (allResults.length === 0) {
        const symMsg = symbol ? ` referencing "${symbol}"` : '';
        return `No test files found for ${filePath}${symMsg}.`;
    }

    const symMsg = symbol ? ` referencing "${symbol}"` : '';
    parts.push(`Tests for ${filePath}${symMsg} (${allResults.length} found):`);
    parts.push('');

    const naming = allResults.filter(r => r.matchType === 'naming');
    const bySymbol = allResults.filter(r => r.matchType === 'symbol');

    if (naming.length > 0) {
        parts.push('By naming convention:');
        for (const r of naming) {
            parts.push(`  ${r.filePath} (confidence ${r.confidence})`);
        }
        parts.push('');
    }

    if (bySymbol.length > 0) {
        parts.push(`By symbol reference "${symbol}":`);
        for (const r of bySymbol) {
            const lines = r.matchedLines || [];
            const previews = r.matchedPreviews || [];
            const lineSummary = lines.length === 1
                ? `:${lines[0]}`
                : `:${lines[0]} (+${lines.length - 1} more)`;
            parts.push(`  ${r.filePath}${lineSummary} (confidence ${r.confidence})`);
            for (let i = 0; i < Math.min(lines.length, 3); i++) {
                parts.push(`    L${lines[i]}: ${previews[i]}`);
            }
        }
    }

    return parts.join('\n');
}
