/**
 * Scan agent executor — dispatches each agent action to the right tool
 * and returns a redacted, truncated observation string.
 *
 * MCP-side tools (read_file, search_code, trace_flow, check_guard) run
 * locally using tree-sitter + filesystem. API-side tools (check_policy)
 * call POST /agent/scan/tool over the wire.
 */

import * as fs from 'fs';
import * as path from 'path';
import { ApiClient } from '../api/client';
import type { ServerContext } from '../mcp/types';
import { readFileFromWorkspace, resolveWorkspacePath } from '../utils/files';
import { searchCode, formatSearchResult } from '../utils/searchCode';
import { trackTaint } from '../project-map/taintTracker';
import { trackTaintCrossFile } from '../project-map/crossFileTaintTracker';
import { evaluateGuard } from '../project-map/guardEvaluator';
import type { SinkLanguage } from '../project-map/sinkRegistry';
import { redactText } from './report';
import { discoverEndpoints, formatEndpoints } from '../project-map/endpointDiscovery';
import { listImports, formatImports } from '../utils/listImports';
import { listFiles, formatFileList } from '../utils/listFiles';
import { getCallGraph } from '../project-map/callGraphExtractor';
import { getGitBlame, getGitHistory } from '../utils/gitContext';
import { scanDependencies } from '../dependency/dependencyChecker';
import { FileCacheStore } from '../dependency/depCache';
import { readSecurityConfig } from '../utils/securityConfig';
import { findDefinition, findReferences } from '../project-map/symbolIndex';
import { findTests } from '../project-map/findTests';
import { runTests, type RunTestsRequest } from '../utils/testRunner';
import { validateToolResponse } from './protocolValidator';
import type {
    AgentScanAction,
    AgentScanToolRequest,
    AgentScanToolResponse,
    AgentScanTarget,
} from './agentScanProtocol';

const MAX_OBSERVATION_CHARS = 16000;
const LARGE_FILE_THRESHOLD = 300;

function truncate(text: string): string {
    if (text.length <= MAX_OBSERVATION_CHARS) return text;
    return text.slice(0, MAX_OBSERVATION_CHARS) + '\n… [truncated]';
}

function redact(text: string): string {
    return truncate(redactText(text));
}

function toSinkLanguage(language: string): SinkLanguage | null {
    const map: Record<string, SinkLanguage> = {
        javascript: 'javascript',
        javascriptreact: 'javascript',
        typescript: 'typescript',
        typescriptreact: 'tsx',
        python: 'python',
    };
    return map[language] || null;
}

function findFunctionInFile(source: string, functionName: string): string | null {
    // Simple heuristic: find a function/method declaration by name and
    // extract its body by brace matching. Works for most JS/TS/Python.
    const patterns = [
        new RegExp(`(?:export\\s+)?(?:async\\s+)?function\\s+${escapeRegex(functionName)}\\s*\\(`),
        new RegExp(`(?:const|let|var)\\s+${escapeRegex(functionName)}\\s*=\\s*(?:async\\s*)?\\(`),
        new RegExp(`\\b${escapeRegex(functionName)}\\s*(?::\\s*[^=]+)?\\s*=\\s*(?:async\\s*)?\\(`),
    ];

    for (const pattern of patterns) {
        const match = source.match(pattern);
        if (!match) continue;
        const startIdx = match.index!;

        // Find opening brace
        let braceStart = source.indexOf('{', startIdx);
        if (braceStart === -1) continue;

        // Find matching close brace
        let depth = 0;
        let endIdx = -1;
        for (let i = braceStart; i < source.length; i++) {
            if (source[i] === '{') depth++;
            else if (source[i] === '}') {
                depth--;
                if (depth === 0) { endIdx = i; break; }
            }
        }
        if (endIdx !== -1) {
            return source.slice(startIdx, endIdx + 1);
        }
    }
    return null;
}

function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Extract a function map from source code using tree-sitter.
 * Returns a string like:
 *   Function map:
 *     L1-20   requireAuth (function_declaration)
 *     L22-50  requireMembership (function_declaration)
 *     ...
 * Returns null if tree-sitter parsing fails.
 */
async function extractFunctionMap(content: string, relPath: string): Promise<string | null> {
    try {
        const { parseSource } = await import('../project-map/parserLoader');
        const { walk } = await import('../project-map/astHelpers');

        // Infer language from path
        const ext = path.extname(relPath).toLowerCase();
        const langMap: Record<string, string> = {
            '.ts': 'typescript', '.tsx': 'tsx', '.js': 'javascript',
            '.jsx': 'javascript', '.py': 'python',
        };
        const lang = langMap[ext];
        if (!lang) return null;

        const parsed = await parseSource(content, lang as any);
        if (!parsed) return null;

        const { root } = parsed;
        const entries: string[] = [];
        const FUNCTION_TYPES = new Set([
            'function_declaration', 'async_function_declaration',
            'method_definition', 'async_method_definition',
            'arrow_function', 'function_expression',
            'class_declaration', 'export_statement',
        ]);

        for (const node of walk(root)) {
            if (!FUNCTION_TYPES.has(node.type)) continue;

            // Get the name (first identifier child or property_identifier)
            let name = '';
            for (const child of node.children) {
                if (child.type === 'identifier' || child.type === 'property_identifier' || child.type === 'type_identifier') {
                    name = content.slice(child.startIndex, child.endIndex);
                    break;
                }
            }
            if (!name) continue;

            const startLine = node.startPosition.row + 1;
            const endLine = node.endPosition.row + 1;
            const lineCount = endLine - startLine + 1;
            const kind = node.type.replace(/_/g, ' ');
            entries.push(`  L${startLine}-${endLine} (${lineCount}L) ${name} [${kind}]`);
        }

        if (entries.length === 0) return null;

        // Also include export-level structure for TS/JS
        const exportLines: string[] = [];
        for (const node of walk(root)) {
            if (node.type === 'export_statement') {
                const text = content.slice(node.startIndex, node.endIndex);
                const firstLine = text.split('\n')[0];
                if (firstLine.length > 100) {
                    exportLines.push(`  L${node.startPosition.row + 1} ${firstLine.slice(0, 100)}...`);
                } else {
                    exportLines.push(`  L${node.startPosition.row + 1} ${firstLine}`);
                }
            }
        }

        const parts = ['Function map (use read_file with startLine/endLine to read specific sections):'];
        parts.push(...entries);
        if (exportLines.length > 0 && exportLines.length <= 20) {
            parts.push('', 'Exports:');
            parts.push(...exportLines);
        }
        return parts.join('\n');
    } catch {
        return null;
    }
}

export async function executeAction(
    action: AgentScanAction,
    ctx: ServerContext,
    runId: string,
    client: ApiClient,
    target: AgentScanTarget,
): Promise<string> {
    switch (action.type) {
        case 'read_file': {
            try {
                const absPath = resolveWorkspacePath(ctx.workspaceRoot, action.path);
                const content = fs.readFileSync(absPath, 'utf8');
                const rel = path.relative(ctx.workspaceRoot, absPath).replace(/\\/g, '/');
                const allLines = content.split('\n');
                const totalLines = allLines.length;

                // If startLine/endLine provided, return only that range
                if (action.startLine || action.endLine) {
                    const start = Math.max(1, action.startLine || 1);
                    const end = Math.min(totalLines, action.endLine || totalLines);
                    const section = allLines.slice(start - 1, end)
                        .map((line, i) => `${start + i}: ${line}`)
                        .join('\n');
                    return redact(`File: ${rel} (lines ${start}-${end} of ${totalLines})\n\n${section}`);
                }

                // For large files, return a function map instead of raw content
                if (totalLines > LARGE_FILE_THRESHOLD) {
                    const funcMap = await extractFunctionMap(content, rel);
                    if (funcMap) {
                        return redact(`File: ${rel} (${totalLines} lines — LARGE FILE)\n\nThis file is too large to show in full. Here is a function map. Use read_file with startLine/endLine to read specific sections.\n\n${funcMap}`);
                    }
                }

                // Small file: return full content with line numbers
                const numbered = allLines
                    .map((line, i) => `${i + 1}: ${line}`)
                    .join('\n');
                return redact(`File: ${rel} (${totalLines} lines)\n\n${numbered}`);
            } catch (e: any) {
                return `Error reading file "${action.path}": ${e.message || e}`;
            }
        }

        case 'search_code': {
            try {
                const result = await searchCode(ctx.workspaceRoot, action.pattern, action.glob);
                return redact(formatSearchResult(result));
            } catch (e: any) {
                return `Error searching for "${action.pattern}": ${e.message || e}`;
            }
        }

        case 'trace_flow': {
            try {
                const absPath = resolveWorkspacePath(ctx.workspaceRoot, action.filePath);
                const content = fs.readFileSync(absPath, 'utf8');
                const { language } = readFileFromWorkspace(ctx.workspaceRoot, action.filePath);
                const sinkLang = toSinkLanguage(language);
                if (!sinkLang) {
                    return `Unsupported language for taint tracking: ${language}`;
                }
                const results = await trackTaint(content, sinkLang);
                if (results.length === 0) {
                    return `No taint flows found in ${action.filePath}.`;
                }
                const formatted = results.map(r => {
                    const path = r.propagationPath
                        .map(p => `  L${p.line} ${p.operation}: ${p.description}`)
                        .join('\n');
                    return `${r.source} (L${r.sourceLine}) → ${r.sink} (L${r.sinkLine}) [${r.canonicalType}]${r.isTainted ? ' TAINTED' : ' (sanitized)'}\n${path}`;
                }).join('\n\n');
                return redact(formatted);
            } catch (e: any) {
                return `Error tracing flow in "${action.filePath}": ${e.message || e}`;
            }
        }

        case 'trace_flow_cross_file': {
            try {
                const results = await trackTaintCrossFile({
                    workspaceRoot: ctx.workspaceRoot,
                    filePath: action.filePath,
                    maxDepth: (action as any).maxDepth ?? 3,
                });
                if (results.length === 0) {
                    return `No cross-file taint flows found starting from ${action.filePath}.`;
                }
                const formatted = results.map(r => {
                    const path = r.crossFileSteps
                        .map(s => `  ${s.file}:${s.line} ${s.operation}: ${s.description}`)
                        .join('\n');
                    return `${r.source} (${r.sourceFile}:${r.sourceLine}) → ${r.sink} (${r.sinkFile}:${r.sinkLine}) [${r.canonicalType}]\n${path}`;
                }).join('\n\n');
                return redact(formatted);
            } catch (e: any) {
                return `Error tracing cross-file flow from "${action.filePath}": ${e.message || e}`;
            }
        }

        case 'check_guard': {
            try {
                const absPath = resolveWorkspacePath(ctx.workspaceRoot, action.filePath);
                const content = fs.readFileSync(absPath, 'utf8');
                const guardSource = findFunctionInFile(content, action.guardName);
                if (!guardSource) {
                    return `Guard function "${action.guardName}" not found in ${action.filePath}. Use search_code to find where it's defined.`;
                }
                const { language } = readFileFromWorkspace(ctx.workspaceRoot, action.filePath);
                const sinkLang = toSinkLanguage(language);
                if (!sinkLang) {
                    return `Unsupported language for guard evaluation: ${language}`;
                }
                const result = await evaluateGuard(guardSource, action.guardName, action.attackType, sinkLang);
                const effectiveStr = result.effective ? 'EFFECTIVE' : 'NOT EFFECTIVE';
                let output = `Guard "${action.guardName}" vs ${action.attackType}: ${effectiveStr}\nReason: ${result.reason}`;
                if (result.bypassExample) {
                    output += `\nBypass: ${result.bypassExample}`;
                }
                return output;
            } catch (e: any) {
                return `Error evaluating guard "${action.guardName}": ${e.message || e}`;
            }
        }

        case 'check_policy': {
            try {
                const toolReq: AgentScanToolRequest = {
                    runId,
                    action,
                    target,
                };
                const respRaw = await client.postJson<AgentScanToolResponse>('/agent/scan/tool', toolReq);
                const validation = validateToolResponse(respRaw);
                if (!validation.ok) {
                    return `Error running check_policy: API returned a malformed tool response: ${validation.error}`;
                }
                return truncate(validation.value.observation);
            } catch (e: any) {
                return `Error running check_policy: ${e.message || e}`;
            }
        }

        case 'get_endpoints': {
            try {
                const endpoints = await discoverEndpoints(ctx.workspaceRoot, (action as any).glob);
                return truncate(formatEndpoints(endpoints));
            } catch (e: any) {
                return `Error discovering endpoints: ${e.message || e}`;
            }
        }

        case 'list_imports': {
            try {
                const imports = await listImports(ctx.workspaceRoot, action.filePath);
                return truncate(formatImports(imports, action.filePath));
            } catch (e: any) {
                return `Error listing imports for "${action.filePath}": ${e.message || e}`;
            }
        }

        case 'list_files': {
            try {
                const files = listFiles(ctx.workspaceRoot, {
                    dir: (action as any).path,
                    glob: (action as any).glob,
                });
                return truncate(formatFileList(files));
            } catch (e: any) {
                return `Error listing files: ${e.message || e}`;
            }
        }

        case 'call_graph': {
            try {
                const result = await getCallGraph(
                    ctx.workspaceRoot,
                    (action as any).filePath,
                    (action as any).functionName,
                );
                return redact(result);
            } catch (e: any) {
                return `Error extracting call graph for "${(action as any).filePath}": ${e.message || e}`;
            }
        }

        case 'git_blame': {
            try {
                const result = await getGitBlame(
                    ctx.workspaceRoot,
                    (action as any).filePath,
                    (action as any).startLine,
                    (action as any).endLine,
                );
                return truncate(result);
            } catch (e: any) {
                return `Error running git blame on "${(action as any).filePath}": ${e.message || e}`;
            }
        }

        case 'git_history': {
            try {
                const result = await getGitHistory(
                    ctx.workspaceRoot,
                    (action as any).filePath,
                    (action as any).functionName,
                    (action as any).limit,
                );
                return truncate(result);
            } catch (e: any) {
                return `Error running git history: ${e.message || e}`;
            }
        }

        case 'check_dependencies': {
            try {
                const cache = new FileCacheStore(ctx.workspaceRoot);
                const result = await scanDependencies({
                    workspaceRoot: ctx.workspaceRoot,
                    state: cache,
                    licensePolicy: 'warn',
                    useGhsa: true,
                });
                if (result.findings.length === 0) {
                    return `No vulnerable dependencies found. Scanned ${result.packageCount} package(s) across ${result.lockfiles.length} lockfile(s).`;
                }
                const lines: string[] = [
                    `Dependency scan: ${result.findings.length} finding(s) across ${result.packageCount} package(s) (${result.lockfiles.length} lockfile(s)):`,
                    '',
                ];
                const vulnFindings = result.findings.filter(f => !f.check_id.startsWith('dep.license.') && !f.check_id.startsWith('dep.unresolved.'));
                const sortedBySeverity = vulnFindings.sort((a, b) => {
                    const rank = (s: string) => s === 'ERROR' ? 0 : 1;
                    return rank(a.severity) - rank(b.severity);
                });
                for (const f of sortedBySeverity.slice(0, 20)) {
                    const dep = (f as any).dependency;
                    const sev = f.severity === 'ERROR' ? 'CRITICAL' : 'HIGH';
                    lines.push(`  [${sev}] ${dep?.name || 'unknown'}@${dep?.installedVersion || '?'} — ${f.message}`);
                    if (dep?.fixedVersion) lines.push(`    Fix: upgrade to ${dep.fixedVersion}`);
                }
                if (vulnFindings.length > 20) {
                    lines.push(`  ... and ${vulnFindings.length - 20} more (run securecode.scan-dependencies for the full list)`);
                }
                lines.push('');
                lines.push('NOTE: These are known-vulnerable library versions (SCA), NOT code-level vulnerabilities. Report them separately from code-path findings. These do not need exploit verification.');
                return truncate(lines.join('\n'));
            } catch (e: any) {
                return `Error scanning dependencies: ${e.message || e}`;
            }
        }

        case 'read_config': {
            try {
                const kind = (action as any).configKind || 'all';
                const result = await readSecurityConfig(ctx.workspaceRoot, kind);
                return truncate(result);
            } catch (e: any) {
                return `Error reading security config: ${e.message || e}`;
            }
        }

        case 'find_definition': {
            try {
                const result = await findDefinition(
                    ctx.workspaceRoot,
                    (action as any).filePath,
                    (action as any).symbol,
                    (action as any).line,
                );
                return redact(result);
            } catch (e: any) {
                return `Error finding definition for "${(action as any).symbol}": ${e.message || e}`;
            }
        }

        case 'find_references': {
            try {
                const result = await findReferences(
                    ctx.workspaceRoot,
                    (action as any).filePath,
                    (action as any).symbol,
                    (action as any).line,
                );
                return redact(result);
            } catch (e: any) {
                return `Error finding references for "${(action as any).symbol}": ${e.message || e}`;
            }
        }

        case 'find_tests': {
            try {
                const result = await findTests(
                    ctx.workspaceRoot,
                    (action as any).filePath,
                    (action as any).symbol,
                );
                return redact(result);
            } catch (e: any) {
                return `Error finding tests for "${(action as any).filePath}": ${e.message || e}`;
            }
        }

        case 'run_tests': {
            try {
                const a = action as any;
                const req: RunTestsRequest = {
                    mode: a.mode,
                    testFiles: a.testFiles,
                    testPattern: a.testPattern,
                    packageManager: a.packageManager,
                    script: a.script,
                    runner: a.runner,
                    setupScript: a.setupScript,
                    timeoutMs: a.timeoutMs,
                };
                const result = await runTests(req, ctx.workspaceRoot);
                const lines: string[] = [
                    `run_tests ${a.mode}: ${result.status}`,
                ];
                if (result.backend) lines.push(`Backend: ${result.backend}`);
                if (result.command) lines.push(`Command: ${result.command.executable} ${result.command.args.join(' ')}`);
                lines.push(`Exit code: ${result.exitCode}`);
                lines.push(`Duration: ${result.durationMs}ms`);
                if (!result.approved) {
                    lines.push(`Note: ${result.output}`);
                }
                if (result.output) {
                    lines.push('', 'Output:', result.output);
                }
                return redact(lines.join('\n'));
            } catch (e: any) {
                return `Error running tests: ${e.message || e}`;
            }
        }

        case 'finish': {
            // finish is handled by the loop, not the executor
            return '';
        }

        case 'system_event': {
            // system_event is appended to the transcript by the loop, never
            // executed. Return empty if somehow reached.
            return '';
        }
    }
}
