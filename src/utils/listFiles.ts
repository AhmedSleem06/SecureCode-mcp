/**
 * File listing utility — walks a directory and returns source files,
 * respecting .securecodeignore and skip directories.
 */

import * as fs from 'fs';
import * as path from 'path';
import { readSecurecodeIgnore, isIgnored, isSecretFileName, SKIP_DIRS } from '../utils/ignore';

const SUPPORTED_EXTENSIONS = new Set([
    '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py',
]);

const MAX_FILES = 500;

export interface ListFilesOptions {
    /** Directory to list (relative to workspace root). Defaults to root. */
    dir?: string;
    /** Optional glob filter (e.g. "*.ts"). */
    glob?: string;
}

export interface FileEntry {
    path: string;       // workspace-relative
    size: number;       // bytes
    lines: number;      // line count
}

function matchGlob(filePath: string, glob?: string): boolean {
    if (!glob) return true;
    // Simple glob: *.ts, *.py, etc — match the extension
    if (glob.startsWith('*.')) {
        const ext = glob.slice(1); // '.ts'
        return filePath.endsWith(ext);
    }
    // Otherwise treat as substring match
    return filePath.includes(glob);
}

export function listFiles(
    workspaceRoot: string,
    options: ListFilesOptions = {},
): FileEntry[] {
    const ignorePatterns = readSecurecodeIgnore(workspaceRoot);
    const searchDir = options.dir
        ? path.resolve(workspaceRoot, options.dir)
        : workspaceRoot;

    const results: FileEntry[] = [];
    const stack: string[] = [searchDir];
    let count = 0;

    while (stack.length > 0 && count < MAX_FILES) {
        const dir = stack.pop()!;
        let entries: fs.Dirent[];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            continue;
        }

        for (const entry of entries) {
            if (count >= MAX_FILES) break;
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
                if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                    stack.push(fullPath);
                }
            } else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                if (!SUPPORTED_EXTENSIONS.has(ext)) continue;
                if (isSecretFileName(fullPath)) continue;

                const relPath = path.relative(workspaceRoot, fullPath).replace(/\\/g, '/');
                if (isIgnored(relPath, ignorePatterns)) continue;
                if (!matchGlob(relPath, options.glob)) continue;

                let size = 0;
                let lines = 0;
                try {
                    const content = fs.readFileSync(fullPath, 'utf8');
                    size = Buffer.byteLength(content);
                    lines = content.split('\n').length;
                } catch { /* best effort */ }

                results.push({ path: relPath, size, lines });
                count++;
            }
        }
    }

    results.sort((a, b) => a.path.localeCompare(b.path));
    return results;
}

export function formatFileList(files: FileEntry[]): string {
    if (files.length === 0) {
        return 'No source files found.';
    }
    const lines: string[] = [`Found ${files.length} source file(s):`];
    for (const f of files) {
        const sizeStr = f.size < 1024
            ? `${f.size}B`
            : `${(f.size / 1024).toFixed(1)}KB`;
        lines.push(`  ${f.path} (${f.lines}L, ${sizeStr})`);
    }
    return lines.join('\n');
}
