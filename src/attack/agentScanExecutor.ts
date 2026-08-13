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
import { evaluateGuard } from '../project-map/guardEvaluator';
import type { SinkLanguage } from '../project-map/sinkRegistry';
import { redactText } from './report';
import type {
    AgentScanAction,
    AgentScanToolRequest,
    AgentScanToolResponse,
    AgentScanTarget,
} from './agentScanProtocol';

const MAX_OBSERVATION_CHARS = 8000;

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
                const lines = content.split('\n').length;
                const numbered = content
                    .split('\n')
                    .map((line, i) => `${i + 1}: ${line}`)
                    .join('\n');
                return redact(`File: ${rel} (${lines} lines)\n\n${numbered}`);
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
                const resp = await client.postJson<AgentScanToolResponse>('/agent/scan/tool', toolReq);
                return truncate(resp.observation);
            } catch (e: any) {
                return `Error running check_policy: ${e.message || e}`;
            }
        }

        case 'finish': {
            // finish is handled by the loop, not the executor
            return '';
        }
    }
}
