/**
 * Code search utility — wraps ripgrep (rg) for fast workspace-wide search.
 * Falls back to recursive grep if rg is not available.
 *
 * Returns matching lines with file paths and line numbers, capped at maxHits.
 */

import { execFile } from 'child_process';
import * as path from 'path';
import { resolveWorkspacePath } from './files';

export interface SearchHit {
    path: string;
    line: number;
    text: string;
}

export interface SearchResult {
    hits: SearchHit[];
    total: number;
    truncated: boolean;
}

const MAX_HITS = 50;
const MAX_LINE_LENGTH = 500;

function promisifyExecFile(
    file: string,
    args: string[],
    opts: { cwd: string; maxBuffer: number },
): Promise<{ stdout: string; stderr: string; code: number | null }> {
    return new Promise((resolve, reject) => {
        execFile(file, args, opts, (err, stdout, stderr) => {
            if (err && (err as any).code === 'ENOENT') {
                reject(new Error(`Command not found: ${file}`));
                return;
            }
            resolve({ stdout, stderr, code: err ? (err as any).code : null });
        });
    });
}

function hasRipgrep(): Promise<boolean> {
    return new Promise((resolve) => {
        execFile('rg', ['--version'], (err) => {
            resolve(!err || (err as any).code !== 'ENOENT');
        });
    });
}

function trimLine(text: string): string {
    const trimmed = text.trim();
    return trimmed.length > MAX_LINE_LENGTH
        ? trimmed.slice(0, MAX_LINE_LENGTH) + '…'
        : trimmed;
}

async function searchWithRipgrep(
    workspaceRoot: string,
    pattern: string,
    glob?: string,
): Promise<SearchHit[]> {
    const args = [
        '--json',
        '--max-count', String(MAX_HITS),
        '--no-heading',
        '--line-number',
        '--ignore-case',
    ];
    if (glob) {
        args.push('--glob', glob);
    }
    args.push('--', pattern, workspaceRoot);

    let result;
    try {
        result = await promisifyExecFile('rg', args, {
            cwd: workspaceRoot,
            maxBuffer: 10 * 1024 * 1024,
        });
    } catch (e: any) {
        if (e.message === 'Command not found: rg') throw e;
        result = { stdout: '', stderr: e.message || '', code: e.code || 1 };
    }

    const hits: SearchHit[] = [];
    for (const line of result.stdout.split('\n')) {
        if (!line.trim()) continue;
        try {
            const obj = JSON.parse(line);
            if (obj.type === 'match' && obj.data) {
                const relativePath = path.relative(workspaceRoot, obj.data.path.text).replace(/\\/g, '/');
                hits.push({
                    path: relativePath,
                    line: obj.data.line_number,
                    text: trimLine(obj.data.lines.text),
                });
            }
        } catch {
            // skip non-JSON lines
        }
    }
    return hits;
}

async function searchWithGrep(
    workspaceRoot: string,
    pattern: string,
    glob?: string,
): Promise<SearchHit[]> {
    const args = ['-rn', '-i', '--max-count=50'];
    if (glob) {
        args.push('--include', glob.replace(/^\*\./, '*.'));
    }
    args.push('--', pattern, '.');

    let result;
    try {
        result = await promisifyExecFile('grep', args, {
            cwd: workspaceRoot,
            maxBuffer: 10 * 1024 * 1024,
        });
    } catch (e: any) {
        if (e.message === 'Command not found: grep') throw e;
        result = { stdout: '', stderr: '', code: e.code || 1 };
    }

    const hits: SearchHit[] = [];
    for (const line of result.stdout.split('\n').slice(0, MAX_HITS)) {
        const match = line.match(/^([^:]+):(\d+):(.*)$/);
        if (match) {
            hits.push({
                path: match[1].replace(/\\/g, '/'),
                line: parseInt(match[2], 10),
                text: trimLine(match[3]),
            });
        }
    }
    return hits;
}

export async function searchCode(
    workspaceRoot: string,
    pattern: string,
    glob?: string,
): Promise<SearchResult> {
    let hits: SearchHit[];

    if (await hasRipgrep()) {
        hits = await searchWithRipgrep(workspaceRoot, pattern, glob);
    } else {
        hits = await searchWithGrep(workspaceRoot, pattern, glob);
    }

    const total = hits.length;
    const truncated = total > MAX_HITS;
    if (truncated) hits = hits.slice(0, MAX_HITS);

    return { hits, total, truncated };
}

export function formatSearchResult(result: SearchResult): string {
    if (result.hits.length === 0) {
        return 'No matches found.';
    }
    const lines = result.hits.map(h =>
        `${h.path}:${h.line}: ${h.text}`,
    );
    let output = lines.join('\n');
    if (result.truncated) {
        output += `\n… (${result.total} total matches, showing first ${MAX_HITS})`;
    }
    return output;
}
