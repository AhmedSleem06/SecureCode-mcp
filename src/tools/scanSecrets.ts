/**
 * securecode.scan-secrets — standalone secret/PII scanner.
 *
 * Scans files for hardcoded secrets (API keys, JWTs, private keys, database
 * URLs, credentials) and PII (emails, credit cards). Runs entirely locally
 * — no AI calls, no API requests, no credits. Uses regex patterns ported
 * from the API's redact.ts.
 *
 * Input:
 *   - directory: workspace-relative folder to scan recursively
 *   - filePaths: explicit list of workspace-relative files
 *   - maxFiles: cap (default 200)
 *
 * Respects .securecodeignore, skips secret files (.env, private keys),
 * skips binary files, 1MB file size limit.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { readSecurecodeIgnore, isIgnored, isSecretFileName, SKIP_DIRS } from '../utils/ignore';
import { detectSecrets, type SecretFinding } from '../utils/secretDetector';

const MAX_FILE_SIZE = 1024 * 1024;
const DEFAULT_MAX_FILES = 200;

const SCANNABLE_EXTENSIONS = new Set([
    '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.php',
    '.json', '.yaml', '.yml', '.toml', '.env', '.xml', '.ini',
    '.cfg', '.conf', '.sh', '.bash', '.rb', '.go', '.rs', '.java',
    '.kt', '.swift', '.dart', '.vue', '.svelte',
]);

interface FileFinding {
    filePath: string;
    findings: Array<SecretFinding & { snippet: string }>;
}

function discoverFiles(root: string, ignorePatterns: Set<string>, maxFiles: number): string[] {
    const results: string[] = [];
    const stack: string[] = [root];
    let count = 0;

    while (stack.length > 0 && count < maxFiles) {
        const dir = stack.pop()!;
        let entries: fs.Dirent[];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch { continue; }

        for (const entry of entries) {
            if (count >= maxFiles) break;
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
                if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
                    stack.push(fullPath);
                }
            } else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                if (SCANNABLE_EXTENSIONS.has(ext) || entry.name === '.env' || entry.name.startsWith('.env.')) {
                    const relPath = path.relative(root, fullPath).replace(/\\/g, '/');
                    if (!isIgnored(relPath, ignorePatterns)) {
                        results.push(fullPath);
                        count++;
                    }
                }
            }
        }
    }
    return results.sort();
}

export async function toolScanSecrets(ctx: ServerContext, args: any): Promise<unknown> {
    const directory = args.directory as string | undefined;
    const filePaths = args.filePaths as string[] | undefined;
    const maxFiles = (args.maxFiles as number) || DEFAULT_MAX_FILES;
    const progressFn = args._progress as ((progress: number, total: number, message: string) => void) | undefined;

    if (!directory && !filePaths) {
        throw Object.assign(new Error('Provide directory or filePaths.'), { code: -32602 });
    }

    const root = ctx.workspaceRoot;
    const ignorePatterns = readSecurecodeIgnore(root);

    let filesToScan: string[] = [];

    if (directory) {
        const absDir = path.isAbsolute(directory)
            ? directory
            : path.join(root, directory);
        if (!fs.existsSync(absDir) || !fs.statSync(absDir).isDirectory()) {
            throw Object.assign(new Error(`Directory not found: ${directory}`), { code: -32602 });
        }
        filesToScan = discoverFiles(absDir, ignorePatterns, maxFiles);
    } else if (filePaths && filePaths.length > 0) {
        for (const fp of filePaths) {
            const abs = path.isAbsolute(fp) ? fp : path.join(root, fp);
            if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
                const relPath = path.relative(root, abs).replace(/\\/g, '/');
                if (!isIgnored(relPath, ignorePatterns)) {
                    filesToScan.push(abs);
                }
            }
        }
        filesToScan = filesToScan.slice(0, maxFiles);
    }

    const total = filesToScan.length;
    const results: FileFinding[] = [];
    const skipped: Array<{ path: string; reason: string }> = [];
    let lastProgress = 0;

    const allFindingsByType: Record<string, number> = {};
    const allFindingsBySeverity: Record<string, number> = {};

    for (let i = 0; i < total; i++) {
        const absPath = filesToScan[i];
        const relPath = path.relative(root, absPath).replace(/\\/g, '/');

        const pct = Math.floor(((i + 1) / total) * 100);
        if (pct >= lastProgress + 5 || (i + 1) % 10 === 0 || i === 0 || i === total - 1) {
            lastProgress = pct;
            progressFn?.(i + 1, total, `Scanning ${path.basename(relPath)} (${i + 1}/${total})`);
        }

        if (isSecretFileName(absPath)) {
            skipped.push({ path: relPath, reason: 'secret_file' });
            continue;
        }

        try {
            const stat = fs.statSync(absPath);
            if (stat.size > MAX_FILE_SIZE) {
                skipped.push({ path: relPath, reason: 'too_large' });
                continue;
            }

            const code = fs.readFileSync(absPath, 'utf8');
            const findings = detectSecrets(code);

            if (findings.length > 0) {
                const lines = code.split('\n');
                const enriched = findings.map(f => ({
                    ...f,
                    snippet: lines[f.line - 1]?.trim().substring(0, 120) ?? '',
                }));
                results.push({ filePath: relPath, findings: enriched });

                for (const f of findings) {
                    allFindingsByType[f.type] = (allFindingsByType[f.type] ?? 0) + 1;
                    allFindingsBySeverity[f.severity] = (allFindingsBySeverity[f.severity] ?? 0) + 1;
                }
            }
        } catch {
            skipped.push({ path: relPath, reason: 'read_error' });
        }
    }

    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);

    return {
        filesScanned: total - skipped.length,
        filesSkipped: skipped.length,
        totalFindings,
        findingsByType: allFindingsByType,
        findingsBySeverity: allFindingsBySeverity,
        results,
        skipped,
    };
}
