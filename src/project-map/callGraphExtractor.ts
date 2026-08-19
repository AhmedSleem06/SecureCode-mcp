/**
 * Call graph extractor — builds a forward + reverse call graph for a file
 * or a specific function, using tree-sitter AST.
 *
 * Used by the agent scan's call_graph tool. Unlike layer1.ts's extractCallGraph
 * (which is endpoint-handler-specific), this is a general-purpose extractor
 * that works on any function in any parseable file.
 *
 * Forward graph:  what does function X call? (callees)
 * Reverse graph:  who calls function X?      (callers)
 * File-level:      what functions exist, and what do they call?
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseSource, grammarForFile, TreeSitterNode } from './parserLoader';
import { walk, callParts, isIdentifier, collectImports, resolveModulePath } from './astHelpers';
import { resolveWorkspacePath } from '../utils/files';

interface FunctionInfo {
    name: string;
    startLine: number;
    endLine: number;
    node: TreeSitterNode;
}

interface CallEdge {
    /** The called function/method name. */
    name: string;
    /** Resolved file if the callee is imported, else null. */
    calleeFile: string | null;
    /** Call site line (1-indexed). */
    line: number;
}

const FUNCTION_TYPES = new Set([
    'function_declaration', 'function_definition', 'method_definition',
    'async_function_declaration', 'async_function_definition',
    'generator_function_declaration', 'generator_declaration',
]);

function extractFunctionList(root: TreeSitterNode, source: string): FunctionInfo[] {
    const out: FunctionInfo[] = [];
    const seen = new Set<number>();

    for (const n of walk(root)) {
        if (!FUNCTION_TYPES.has(n.type)) continue;
        let name = '';
        for (const child of n.namedChildren) {
            if (isIdentifier(child)) {
                name = source.slice(child.startIndex, child.endIndex);
                break;
            }
        }
        if (!name && n.parent) {
            const parent = n.parent;
            if (parent.type === 'lexical_declaration' || parent.type === 'variable_declaration') {
                const decl = parent.namedChildren.find(c => c.type === 'variable_declarator');
                if (decl) {
                    const id = decl.child(0);
                    if (id && isIdentifier(id)) name = source.slice(id.startIndex, id.endIndex);
                }
            }
        }
        if (!name) continue;
        if (seen.has(n.startIndex)) continue;
        seen.add(n.startIndex);
        out.push({
            name,
            startLine: n.startPosition.row + 1,
            endLine: n.endPosition.row + 1,
            node: n,
        });
    }
    return out;
}

function extractCallees(
    funcNode: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
    fromFile: string,
    workspaceRoot: string,
): CallEdge[] {
    const out: CallEdge[] = [];
    const seen = new Set<string>();

    for (const n of walk(funcNode)) {
        if (n.type !== 'call_expression' && n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p) continue;
        const name = p.receiver ? `${p.receiver}.${p.method}` : p.method;
        if (seen.has(name)) continue;
        seen.add(name);
        const calleeSpec = imports.get(p.receiver || '') || imports.get(p.method) || null;
        const resolved = calleeSpec ? resolveModulePath(calleeSpec, fromFile, workspaceRoot) : null;
        out.push({ name, calleeFile: resolved, line: p.line + 1 });
    }
    return out;
}

function findCallers(
    root: TreeSitterNode,
    source: string,
    targetName: string,
): { caller: string; line: number; callerStart: number }[] {
    const out: { caller: string; line: number; callerStart: number }[] = [];
    const seen = new Set<string>();

    for (const n of walk(root)) {
        if (n.type !== 'call_expression' && n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p) continue;
        if (p.method !== targetName) continue;

        let callerName = '<anonymous>';
        let callerStart = 0;
        let cur: TreeSitterNode | null | undefined = n.parent;
        while (cur) {
            if (FUNCTION_TYPES.has(cur.type)) {
                const id = cur.namedChildren.find(c => isIdentifier(c));
                if (id) callerName = source.slice(id.startIndex, id.endIndex);
                callerStart = cur.startPosition.row + 1;
                break;
            }
            cur = cur.parent;
        }
        const key = `${callerName}:${p.line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ caller: callerName, line: p.line + 1, callerStart });
    }
    return out;
}

export async function getCallGraph(
    workspaceRoot: string,
    filePath: string,
    functionName?: string,
): Promise<string> {
    const grammar = grammarForFile(filePath);
    if (grammar === 'unknown') {
        return `Cannot extract call graph: unsupported file type (${filePath}). Only JS/TS/TSX/Python can be parsed.`;
    }

    let content: string;
    let relPath: string;
    let absPath: string;
    try {
        absPath = resolveWorkspacePath(workspaceRoot, filePath);
        content = fs.readFileSync(absPath, 'utf8');
        relPath = path.relative(workspaceRoot, absPath).replace(/\\/g, '/');
    } catch (e: any) {
        return `Error reading file "${filePath}": ${e.message || e}`;
    }

    const parsed = await parseSource(content, grammar as any);
    if (!parsed) {
        return `Cannot parse ${relPath}: tree-sitter parsing failed.`;
    }

    const { root } = parsed;
    const imports = collectImports(root, content);
    const functions = extractFunctionList(root, content);

    if (functions.length === 0) {
        return `No functions found in ${relPath}.`;
    }

    const lines: string[] = [`Call graph for ${relPath} (${functions.length} function(s)):`];

    if (functionName) {
        const target = functions.find(f => f.name === functionName);
        if (!target) {
            lines.push(`\nFunction "${functionName}" not found in this file.`);
            lines.push(`\nAvailable functions:`);
            for (const f of functions) {
                lines.push(`  L${f.startLine}-${f.endLine}  ${f.name}`);
            }
            return lines.join('\n');
        }

        lines.push(`\nFunction: ${target.name} (L${target.startLine}-${target.endLine})`);

        const callees = extractCallees(target.node, content, imports, absPath, workspaceRoot);
        lines.push(`\n  Callees (${callees.length} — what ${target.name} calls):`);
        if (callees.length === 0) {
            lines.push('    (none)');
        } else {
            for (const c of callees) {
                const file = c.calleeFile ? ` → ${c.calleeFile}` : '';
                lines.push(`    L${c.line}  ${c.name}${file}`);
            }
        }

        const callers = findCallers(root, content, target.name);
        lines.push(`\n  Callers (${callers.length} — who calls ${target.name}):`);
        if (callers.length === 0) {
            lines.push('    (none — this may be an entry point)');
        } else {
            for (const c of callers) {
                lines.push(`    L${c.line}  ${c.caller}`);
            }
        }
    } else {
        lines.push('');
        for (const f of functions) {
            const callees = extractCallees(f.node, content, imports, absPath, workspaceRoot);
            const calleeNames = callees.length > 0
                ? callees.map(c => c.name).join(', ')
                : '(no calls)';
            lines.push(`  L${f.startLine}-${f.endLine}  ${f.name}  →  ${calleeNames}`);
        }
        lines.push('');
        lines.push('Use call_graph with functionName to get forward + reverse edges for a specific function.');
    }

    return lines.join('\n');
}
