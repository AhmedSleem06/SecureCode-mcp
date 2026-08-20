/**
 * Architecture scout executor — dispatches each scout action to the right
 * tool and returns a redacted, truncated observation string.
 *
 * This is a SUBSET of the agent-scan executor: only the
 * architecture-relevant tools (read_file, search_code, list_files,
 * list_imports, get_endpoints, call_graph, read_config, check_dependencies,
 * find_definition, find_references). Vulnerability-confirmation tools
 * (trace_flow, check_guard, check_policy, git_*, find_tests, run_tests)
 * are NOT available — the scout surveys architecture, it does not confirm
 * vulnerabilities.
 *
 * All tools run locally (no API round-trip — the scout has no equivalent
 * of the agent-scan check_policy that calls back to the API).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ServerContext } from '../mcp/types';
import { resolveWorkspacePath } from '../utils/files';
import { searchCode, formatSearchResult } from '../utils/searchCode';
import { listImports, formatImports } from '../utils/listImports';
import { listFiles, formatFileList } from '../utils/listFiles';
import { discoverEndpoints, formatEndpoints } from '../project-map/endpointDiscovery';
import { getCallGraph } from '../project-map/callGraphExtractor';
import { scanDependencies } from '../dependency/dependencyChecker';
import { FileCacheStore } from '../dependency/depCache';
import { readSecurityConfig } from '../utils/securityConfig';
import { findDefinition, findReferences } from '../project-map/symbolIndex';
import {
    extractFunctionMap,
    truncate,
    redact,
    LARGE_FILE_THRESHOLD,
} from './agentScanExecutor';
import type { ArchitectureScoutAction } from './architectureScoutProtocol';

export async function executeScoutAction(
    action: ArchitectureScoutAction,
    ctx: ServerContext,
): Promise<string> {
    switch (action.type) {
        case 'read_file': {
            try {
                const absPath = resolveWorkspacePath(ctx.workspaceRoot, action.path);
                const content = fs.readFileSync(absPath, 'utf8');
                const rel = path.relative(ctx.workspaceRoot, absPath).replace(/\\/g, '/');
                const allLines = content.split('\n');
                const totalLines = allLines.length;

                if (action.startLine || action.endLine) {
                    const start = Math.max(1, action.startLine || 1);
                    const end = Math.min(totalLines, action.endLine || totalLines);
                    const section = allLines.slice(start - 1, end)
                        .map((line, i) => `${start + i}: ${line}`)
                        .join('\n');
                    return redact(`File: ${rel} (lines ${start}-${end} of ${totalLines})\n\n${section}`);
                }

                if (totalLines > LARGE_FILE_THRESHOLD) {
                    const funcMap = await extractFunctionMap(content, rel);
                    if (funcMap) {
                        return redact(`File: ${rel} (${totalLines} lines — LARGE FILE)\n\nThis file is too large to show in full. Here is a function map. Use read_file with startLine/endLine to read specific sections.\n\n${funcMap}`);
                    }
                }

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

        case 'list_imports': {
            try {
                const imports = await listImports(ctx.workspaceRoot, action.filePath);
                return truncate(formatImports(imports, action.filePath));
            } catch (e: any) {
                return `Error listing imports for "${action.filePath}": ${e.message || e}`;
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

        case 'call_graph': {
            try {
                const result = await getCallGraph(
                    ctx.workspaceRoot,
                    action.filePath,
                    action.functionName,
                );
                return redact(result);
            } catch (e: any) {
                return `Error extracting call graph for "${action.filePath}": ${e.message || e}`;
            }
        }

        case 'read_config': {
            try {
                const result = await readSecurityConfig(ctx.workspaceRoot, action.configKind);
                return truncate(redact(result));
            } catch (e: any) {
                return `Error reading ${action.configKind} config: ${e.message || e}`;
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
                const vulnFindings = result.findings.filter(f => !f.check_id.startsWith('dep.license.') && !f.check_id.startsWith('dep.unresolved.'));
                const lines: string[] = [
                    `Dependency scan: ${vulnFindings.length} vulnerable package(s) across ${result.packageCount} package(s) (${result.lockfiles.length} lockfile(s)):`,
                    '',
                ];
                for (const f of vulnFindings.slice(0, 30)) {
                    const dep = (f as any).dependency;
                    const sev = f.severity === 'ERROR' ? 'CRITICAL' : 'HIGH';
                    lines.push(`  [${sev}] ${dep?.name || 'unknown'}@${dep?.installedVersion || '?'} — ${f.message}`);
                    if (dep?.fixedVersion) lines.push(`    Fix: upgrade to ${dep.fixedVersion}`);
                }
                if (vulnFindings.length > 30) {
                    lines.push(`  ... and ${vulnFindings.length - 30} more`);
                }
                return truncate(lines.join('\n'));
            } catch (e: any) {
                return `Error checking dependencies: ${e.message || e}`;
            }
        }

        case 'find_definition': {
            try {
                const result = await findDefinition(ctx.workspaceRoot, action.filePath, action.symbol, action.line);
                return truncate(result);
            } catch (e: any) {
                return `Error finding definition of "${action.symbol}": ${e.message || e}`;
            }
        }

        case 'find_references': {
            try {
                const result = await findReferences(ctx.workspaceRoot, action.filePath, action.symbol, action.line);
                return truncate(result);
            } catch (e: any) {
                return `Error finding references to "${action.symbol}": ${e.message || e}`;
            }
        }

        case 'finish': {
            return '';
        }
    }
    return '';
}
