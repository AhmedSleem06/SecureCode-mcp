import * as fs from 'fs';
import * as path from 'path';
import { parseSource, grammarForFile } from './parserLoader';
import { extractLayer1 } from './layer1';
import { detectDynamicPatterns } from './layer2';
import { aggregateConfidence } from './confidence';
import type { ProjectMap, FileExtraction, EndpointRecord, WebSocketHandler } from './types';
import { PROJECT_MAP_SCHEMA_VERSION } from './types';
import { readSecurecodeIgnore, isIgnored, SKIP_DIRS } from '../utils/ignore';

const SUPPORTED_EXTENSIONS = new Set([
    '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py',
]);

const MAX_FILES = 500;
const MAX_FILE_SIZE = 1024 * 1024;

export interface BuildOptions {
    workspaceRoot: string;
    maxFiles?: number;
    onProgress?: (processed: number, total: number, file: string) => void;
}

export interface BuildResult {
    map: ProjectMap;
    filesProcessed: number;
    filesSkipped: number;
    errors: Array<{ file: string; error: string }>;
    durationMs: number;
}

function discoverFiles(root: string, ignorePatterns: Set<string>): string[] {
    const results: string[] = [];
    const stack: string[] = [root];
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
                if (SUPPORTED_EXTENSIONS.has(ext)) {
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

function toRelative(root: string, absPath: string): string {
    return path.relative(root, absPath).replace(/\\/g, '/');
}

export async function buildProjectMap(opts: BuildOptions): Promise<BuildResult> {
    const startTime = Date.now();
    const root = path.resolve(opts.workspaceRoot);
    const maxFiles = opts.maxFiles ?? MAX_FILES;

    const ignorePatterns = readSecurecodeIgnore(root);
    const files = discoverFiles(root, ignorePatterns);
    const total = Math.min(files.length, maxFiles);

    const fileExtractions: FileExtraction[] = [];
    const allEndpoints: EndpointRecord[] = [];
    const allWebsockets: WebSocketHandler[] = [];
    const errors: Array<{ file: string; error: string }> = [];
    let processed = 0;
    let skipped = 0;

    for (const absPath of files.slice(0, maxFiles)) {
        const relPath = toRelative(root, absPath);
        opts.onProgress?.(processed, total, relPath);

        try {
            const stat = fs.statSync(absPath);
            if (stat.size > MAX_FILE_SIZE) {
                skipped++;
                continue;
            }

            const source = fs.readFileSync(absPath, 'utf8');
            if (source.length === 0) {
                skipped++;
                continue;
            }

            const grammar = grammarForFile(absPath);
            if (grammar === 'unknown') {
                skipped++;
                continue;
            }

            const parsed = await parseSource(source, grammar);
            if (!parsed || !parsed.root) {
                skipped++;
                continue;
            }

            const { root: astRoot } = parsed;
            const layer1 = extractLayer1(relPath, source, astRoot);
            const dynamicPatterns = detectDynamicPatterns(relPath, source, astRoot);

            for (const ep of layer1.endpoints) {
                const confidence = aggregateConfidence(ep);
                ep.confidence = confidence;
                allEndpoints.push(ep);
            }
            for (const ws of layer1.websockets) {
                allWebsockets.push(ws);
            }

            fileExtractions.push({
                file: relPath,
                language: grammar,
                endpoints: layer1.endpoints,
                websockets: layer1.websockets,
                dynamicPatterns,
                imports: layer1.imports,
                mtime: stat.mtimeMs,
                hash: '',
            });

            processed++;
        } catch (err: any) {
            errors.push({ file: relPath, error: err.message || String(err) });
            skipped++;
        }
    }

    const map: ProjectMap = {
        files: Object.fromEntries(fileExtractions.map((f) => [f.file, f])),
        endpoints: allEndpoints,
        websockets: allWebsockets,
        dynamicPatterns: fileExtractions.flatMap((f) => f.dynamicPatterns),
        version: PROJECT_MAP_SCHEMA_VERSION,
        builtAt: Date.now(),
    };

    return {
        map,
        filesProcessed: processed,
        filesSkipped: skipped,
        errors,
        durationMs: Date.now() - startTime,
    };
}
