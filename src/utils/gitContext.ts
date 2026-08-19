/**
 * Git context — safe, read-only git blame and history extraction for the
 * agent scan's git_blame and git_history tools.
 *
 * Security rules (enforced here, not by the caller):
 *   - execFile only, no shell
 *   - argument arrays, never string concatenation
 *   - `--` before every file path (prevents option injection)
 *   - workspace confinement via resolveWorkspacePath
 *   - 20 commits maximum (hard cap)
 *   - output truncated to 8KB and redacted (emails, secrets)
 *   - non-git workspaces return a clear "not a git repo" message
 *
 * The agent is told that history is CONTEXT, never proof that code is safe.
 */

import * as path from 'path';
import { execFile } from 'child_process';
import { resolveWorkspacePath } from './files';

const MAX_COMMITS = 20;
const MAX_OUTPUT_BYTES = 8192;
const GIT_TIMEOUT_MS = 10_000;

interface GitResult {
    ok: boolean;
    output: string;
    error?: string;
}

function execGit(args: string[], workspaceRoot: string): Promise<GitResult> {
    return new Promise((resolve) => {
        execFile('git', args, {
            cwd: workspaceRoot,
            timeout: GIT_TIMEOUT_MS,
            maxBuffer: MAX_OUTPUT_BYTES,
            encoding: 'utf8',
            windowsHide: true,
        }, (err, stdout, stderr) => {
            if (err) {
                resolve({ ok: false, output: '', error: (err as any).message || String(err) });
                return;
            }
            resolve({ ok: true, output: stdout || stderr });
        });
    });
}

function isGitRepo(workspaceRoot: string): Promise<boolean> {
    return new Promise((resolve) => {
        execFile('git', ['rev-parse', '--is-inside-work-tree'], {
            cwd: workspaceRoot,
            timeout: 3000,
            windowsHide: true,
        }, (err, stdout) => {
            resolve(!err && stdout.trim() === 'true');
        });
    });
}

/** Redact email addresses and obvious secret patterns from git output. */
function redactGitOutput(text: string): string {
    return text
        .replace(/<[^>]+@[^>]+>/g, '<redacted>')       // author emails <foo@bar.com>
        .replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, 'redacted@email') // bare emails
        .replace(/(sk-[\w]{20,})/gi, 'sk-REDACTED')    // OpenAI keys
        .replace(/(AKIA[\w]{16})/g, 'AKIA-REDACTED')   // AWS keys
        .replace(/(ghp_[\w]{36})/g, 'ghp-REDACTED')    // GitHub PATs
        .replace(/(xox[baprs]-[\w-]+)/g, 'xox-REDACTED'); // Slack tokens
}

function truncate(text: string, max: number = MAX_OUTPUT_BYTES): string {
    if (text.length <= max) return text;
    return text.slice(0, max) + '\n… [truncated]';
}

export async function getGitBlame(
    workspaceRoot: string,
    filePath: string,
    startLine?: number,
    endLine?: number,
): Promise<string> {
    const isGit = await isGitRepo(workspaceRoot);
    if (!isGit) {
        return `Not a git repository — git_blame unavailable.`;
    }

    let absPath: string;
    try {
        absPath = resolveWorkspacePath(workspaceRoot, filePath);
    } catch (e: any) {
        return `Error: ${e.message}`;
    }

    const relPath = path.relative(workspaceRoot, absPath).replace(/\\/g, '/');
    const range = startLine && endLine ? `-L ${startLine},${endLine}` : null;
    const args = ['blame', '--porcelain', '--'];
    if (range) args.splice(1, 0, ...range.split(' '));
    args.push(relPath);

    const result = await execGit(args, workspaceRoot);
    if (!result.ok) {
        return `git blame failed: ${result.error || 'unknown error'}. The file may not be tracked by git.`;
    }

    const lines = result.output.split('\n');
    const blameEntries: { hash: string; author: string; date: string; summary: string; line: string }[] = [];
    let current: { hash: string; author: string; date: string; summary: string; line: string } | null = null;

    for (const line of lines) {
        if (line.startsWith('\t')) {
            if (current) {
                current.line = line.slice(1);
                blameEntries.push(current);
                current = null;
            }
            continue;
        }
        const match = line.match(/^([0-9a-f]{8,40}) (\d+)\s/);
        if (match && !current) {
            current = { hash: match[1].slice(0, 8), author: '', date: '', summary: '', line: '' };
        }
        if (line.startsWith('author ') && current) current.author = redactGitOutput(line.slice(7));
        if (line.startsWith('author-mail ') && current) current.author = `${current.author} ${redactGitOutput(line.slice(12))}`;
        if (line.startsWith('committer-time ') && current) {
            const ts = parseInt(line.slice(15), 10);
            if (!isNaN(ts)) current.date = new Date(ts * 1000).toISOString().slice(0, 10);
        }
        if (line.startsWith('summary ') && current) current.summary = redactGitOutput(line.slice(8));
    }

    if (blameEntries.length === 0) {
        return `No blame data for ${relPath}.`;
    }

    const out: string[] = [`Git blame for ${relPath} (${blameEntries.length} line(s)):`];
    for (const e of blameEntries.slice(0, 20)) {
        out.push(`  ${e.hash}  ${e.date}  ${e.author}`);
        out.push(`    ${e.summary}`);
        out.push(`    L: ${e.line}`);
    }
    return truncate(out.join('\n'));
}

export async function getGitHistory(
    workspaceRoot: string,
    filePath?: string,
    functionName?: string,
    limit: number = 10,
): Promise<string> {
    const isGit = await isGitRepo(workspaceRoot);
    if (!isGit) {
        return `Not a git repository — git_history unavailable.`;
    }

    const maxLimit = Math.min(limit, MAX_COMMITS);
    const args = ['log', `--max-count=${maxLimit}`, '--format=%h|%ad|%an|%s', '--date=short'];

    if (filePath) {
        let absPath: string;
        try {
            absPath = resolveWorkspacePath(workspaceRoot, filePath);
        } catch (e: any) {
            return `Error: ${e.message}`;
        }
        const relPath = path.relative(workspaceRoot, absPath).replace(/\\/g, '/');
        args.push('--', relPath);
    } else {
        args.push('--');
    }

    if (functionName) {
        args.splice(2, 0, `-S${functionName}`);
    }

    const result = await execGit(args, workspaceRoot);
    if (!result.ok) {
        return `git log failed: ${result.error || 'unknown error'}.`;
    }

    const lines = result.output.trim().split('\n').filter(Boolean);
    if (lines.length === 0) {
        return filePath
            ? `No commit history for ${filePath}.`
            : `No commit history found.`;
    }

    const out: string[] = [`Git history (${lines.length} commit(s))${filePath ? ` for ${filePath}` : ''}:`];
    for (const line of lines) {
        const parts = line.split('|');
        if (parts.length >= 4) {
            const [hash, date, author, summary] = parts;
            out.push(`  ${hash}  ${date}  ${redactGitOutput(author)}`);
            out.push(`    ${redactGitOutput(summary)}`);
        }
    }
    return truncate(out.join('\n'));
}
