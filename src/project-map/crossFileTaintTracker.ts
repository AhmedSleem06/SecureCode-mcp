/**
 * Cross-file taint tracker — follows taint across file boundaries.
 *
 * The single-file `trackTaint` engine finds source→sink flows within one
 * file. This module extends that to multi-file flows by:
 *
 *   1. Parsing the entry file's imports (collectImports)
 *   2. Resolving each import to a file on disk (resolveModulePath)
 *   3. Indexing each imported function: does it return tainted data?
 *      Does it propagate taint through a specific parameter?
 *   4. Running taint tracking on the entry file with the cross-file
 *      function index, so calls to imported functions that propagate
 *      taint are recognised.
 *
 * Limits prevent runaway analysis on large codebases:
 *   maxDepth (3)  — how many import hops to follow
 *   maxFiles (10) — total files parsed per trace
 *   maxFunctionBodySize (5000 chars) — skip oversized functions
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseSource, TreeSitterNode } from './parserLoader';
import { walk, collectImports, resolveModulePath, isIdentifier, isStringLiteral, stringLiteralValue } from './astHelpers';
import { trackTaint, TaintResult, PropagationStep } from './taintTracker';
import type { SinkLanguage } from './sinkRegistry';

// ── Types ───────────────────────────────────────────────────────────────────

export interface CrossFileStep {
    file: string;           // workspace-relative
    line: number;           // 1-indexed
    variable: string;
    operation: 'source' | 'call-cross-file' | 'return-tainted' | 'sink-arg';
    description: string;
}

export interface CrossFileTaintResult {
    source: string;
    sourceLine: number;
    sourceFile: string;
    sink: string;
    sinkLine: number;
    sinkFile: string;
    canonicalType: string;
    crossFileSteps: CrossFileStep[];
}

export interface CrossFileTaintOptions {
    workspaceRoot: string;
    filePath: string;          // entry file to trace from
    maxDepth?: number;         // default 3
    maxFiles?: number;         // default 10
}

// ── Constants ───────────────────────────────────────────────────────────────

const DEFAULT_MAX_DEPTH = 3;
const DEFAULT_MAX_FILES = 10;
const MAX_FUNCTION_BODY_SIZE = 5000;

const FUNCTION_NODE_TYPES = new Set([
    'function_declaration', 'function_definition', 'method_definition',
    'async_function_declaration', 'async_function_definition',
    'arrow_function', 'function_expression',
    'generator_function_declaration', 'generator_declaration',
]);

// ── Function index ─────────────────────────────────────────────────────────

interface FunctionAnalysis {
    name: string;
    file: string;
    line: number;
    /** Parameter names in order. */
    params: string[];
    /** True if the function returns data derived from a taint source. */
    returnsTainted: boolean;
    /** Set of parameter indices that propagate taint to the return value. */
    taintThroughParams: Set<number>;
}

/**
 * Build a map of `functionName → FunctionAnalysis` for all exported
 * functions in the file. Each function is analyzed to determine whether
 * it returns tainted data and which parameters propagate taint.
 */
async function indexFileFunctions(
    source: string,
    language: SinkLanguage,
    file: string,
): Promise<Map<string, FunctionAnalysis>> {
    const out = new Map<string, FunctionAnalysis>();
    const parsed = await parseSource(source, language);
    if (!parsed) return out;
    const { root } = parsed;

    for (const node of walk(root)) {
        if (!FUNCTION_NODE_TYPES.has(node.type)) continue;

        const name = functionName(node, source);
        if (!name) continue;

        // Skip functions that are too large
        const bodyText = source.slice(node.startIndex, node.endIndex);
        if (bodyText.length > MAX_FUNCTION_BODY_SIZE) continue;

        const params = extractParams(node, source);
        const line = node.startPosition.row + 1;

        // Analyze: seed each parameter as tainted, check if the function
        // returns tainted data from any param
        const taintThroughParams = new Set<number>();
        let returnsTainted = false;

        for (let i = 0; i < params.length; i++) {
            const seedName = params[i];
            if (!seedName) continue;

            // Run taint tracking on just this function body with the param
            // seeded as a source. If any result mentions this param as the
            // source, the function propagates taint through it.
            const flows = await trackTaintWithSeed(source, language, seedName, node);
            if (flows.length > 0) {
                taintThroughParams.add(i);
                returnsTainted = true; // if it reaches a sink it could also be returned
            }
        }

        // Also check if the function returns tainted data directly
        // (e.g. `return req.body` without going through a sink)
        if (!returnsTainted) {
            returnsTainted = checkReturnsTainted(node, source, language);
        }

        out.set(name, { name, file, line, params, returnsTainted, taintThroughParams });
    }

    return out;
}

/**
 * Check if a function returns tainted data by examining return statements.
 * Looks for returns of taint sources (req.body, etc.) or tainted variables.
 */
function checkReturnsTainted(
    fnNode: TreeSitterNode,
    source: string,
    language: SinkLanguage,
): boolean {
    let found = false;
    for (const child of walk(fnNode)) {
        if (child.type !== 'return_statement' && child.type !== 'return') continue;
        // Skip the function's own return type annotation
        if (child.parent && FUNCTION_NODE_TYPES.has(child.parent.type) && child === child.parent.namedChildren[0]) continue;

        const expr = child.namedChildren.find(c => c.type !== 'return' && c.type !== 'return_statement');
        if (!expr) continue;

        const text = source.slice(expr.startIndex, expr.endIndex);
        // Simple heuristic: if the return expression contains a known source pattern
        // like req.body, request.GET, etc.
        if (isTaintSourceText(text, language)) {
            found = true;
            break;
        }
    }
    return found;
}

/**
 * Check if text looks like a taint source (req.body, request.GET, etc.)
 * without needing a full AST parse.
 */
function isTaintSourceText(text: string, language: SinkLanguage): boolean {
    const patterns: string[] = [];
    if (language === 'python') {
        patterns.push('request.GET', 'request.POST', 'request.args', 'request.form',
            'request.json', 'request.body', 'request.headers', 'request.cookies',
            'request.values', 'request.data', 'request.META', 'request.FILES',
            'sys.argv', 'os.environ', 'os.getenv');
    } else {
        patterns.push('req.body', 'req.query', 'req.params', 'req.headers',
            'req.cookies', 'req.files', 'request.body', 'request.query',
            'request.params', 'request.headers', 'request.cookies',
            'ctx.body', 'ctx.query', 'ctx.params', 'ctx.headers',
            'event.body', 'req.json', 'request.json');
    }
    return patterns.some(p => text.includes(p));
}

/**
 * Run taint tracking on a file with a parameter seeded as a taint source.
 * Uses the seedParams option of trackTaint to pre-taint the parameter
 * at module scope, so it propagates into the function's scope.
 */
async function trackTaintWithSeed(
    source: string,
    language: SinkLanguage,
    seedParam: string,
    fnNode: TreeSitterNode,
): Promise<TaintResult[]> {
    const results = await trackTaint(source, language, [seedParam]);
    // Filter: only keep results where the source involves our seed
    return results.filter(r =>
        r.source === `<param:${seedParam}>` ||
        r.propagationPath.some(p => p.variable === seedParam && p.operation === 'source')
    );
}

/** Extract parameter names from a function node. */
function extractParams(fnNode: TreeSitterNode, source: string): string[] {
    const params: string[] = [];
    for (const child of fnNode.namedChildren) {
        if (child.type === 'parameters' || child.type === 'formal_parameters' || child.type === 'parameter_list') {
            for (const param of child.namedChildren) {
                if (isIdentifier(param)) {
                    // Plain identifier: `name` (JS/Python)
                    params.push(source.slice(param.startIndex, param.endIndex));
                } else if (param.type === 'required_parameter') {
                    // TypeScript required parameter: `name: string` — take the identifier
                    const id = param.namedChildren.find(c => isIdentifier(c));
                    if (id) params.push(source.slice(id.startIndex, id.endIndex));
                } else if (param.type === 'shorthand_property_identifier_pattern' || param.type === 'shorthand_property_identifier') {
                    params.push(source.slice(param.startIndex, param.endIndex));
                } else if (param.type === 'assignment_pattern') {
                    // default param: `x = 'default'` — take the left side
                    const left = param.namedChildren[0];
                    if (left && isIdentifier(left)) {
                        params.push(source.slice(left.startIndex, left.endIndex));
                    }
                } else if (param.type === 'identifier' || param.type === 'typed_parameter') {
                    params.push(source.slice(param.startIndex, param.endIndex));
                } else if (param.type === 'typed_parameter') {
                    // Python typed param: `name: str`
                    const id = param.namedChildren.find(c => isIdentifier(c));
                    if (id) params.push(source.slice(id.startIndex, id.endIndex));
                }
                // Skip rest params, destructuring patterns — too complex for now
            }
            break;
        }
    }
    return params;
}

/** Get the name of a function node (mirrors taintTracker's functionName). */
function functionName(fn: TreeSitterNode, source: string): string | null {
    const id = fn.namedChildren.find(c => isIdentifier(c));
    if (id) return source.slice(id.startIndex, id.endIndex);
    const parent = fn.parent;
    if (parent && (parent.type === 'lexical_declaration' || parent.type === 'variable_declaration' || parent.type === 'assignment')) {
        const name = parent.child(0);
        if (name && isIdentifier(name)) return source.slice(name.startIndex, name.endIndex);
    }
    return null;
}

// ── Language detection ──────────────────────────────────────────────────────

function toSinkLanguage(filePath: string): SinkLanguage | null {
    const ext = path.extname(filePath).toLowerCase();
    const map: Record<string, SinkLanguage> = {
        '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
        '.ts': 'typescript', '.tsx': 'tsx',
        '.py': 'python',
    };
    return map[ext] || null;
}

// ── Main entry point ───────────────────────────────────────────────────────

/**
 * Track taint propagation across file boundaries.
 *
 * Parses the entry file, resolves its imports, indexes imported functions
 * for taint behavior, then runs taint tracking with cross-file knowledge.
 *
 * Returns CrossFileTaintResult[] with full file:line paths.
 */
export async function trackTaintCrossFile(
    opts: CrossFileTaintOptions,
): Promise<CrossFileTaintResult[]> {
    const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
    const maxFiles = opts.maxFiles ?? DEFAULT_MAX_FILES;

    const entryAbs = path.resolve(opts.workspaceRoot, opts.filePath);
    const language = toSinkLanguage(opts.filePath);
    if (!language) return [];

    const entrySource = fs.readFileSync(entryAbs, 'utf8');
    const entryParsed = await parseSource(entrySource, language);
    if (!entryParsed) return [];

    // 1. Collect imports from the entry file
    const imports = collectImports(entryParsed.root, entrySource);
    // imports = Map { localName -> moduleSpec }

    // 2. Build a function index from imported files
    const functionIndex = new Map<string, FunctionAnalysis>();
    const visitedFiles = new Set<string>([opts.filePath]);
    const filesToIndex: Array<{ spec: string; fromFile: string; depth: number }> = [];

    for (const [localName, moduleSpec] of imports) {
        filesToIndex.push({ spec: moduleSpec, fromFile: opts.filePath, depth: 0 });
    }

    let filesParsed = 1;
    while (filesToIndex.length > 0 && filesParsed < maxFiles) {
        const { spec, fromFile, depth } = filesToIndex.shift()!;
        if (depth >= maxDepth) continue;

        const resolvedFile = resolveModulePath(
            spec,
            path.resolve(opts.workspaceRoot, fromFile),
            opts.workspaceRoot,
        );
        if (!resolvedFile) continue; // node_modules or unresolvable
        if (visitedFiles.has(resolvedFile)) continue; // cycle guard
        visitedFiles.add(resolvedFile);

        const resolvedAbs = path.resolve(opts.workspaceRoot, resolvedFile);
        let source: string;
        try {
            source = fs.readFileSync(resolvedAbs, 'utf8');
        } catch { continue; }

        const fileLang = toSinkLanguage(resolvedFile);
        if (!fileLang) continue;

        const index = await indexFileFunctions(source, fileLang, resolvedFile);
        for (const [name, analysis] of index) {
            functionIndex.set(name, analysis);
        }
        filesParsed++;

        // Queue deeper imports (depth+1) if we haven't hit the limit
        if (depth + 1 < maxDepth) {
            const parsed = await parseSource(source, fileLang);
            if (parsed) {
                const deeperImports = collectImports(parsed.root, source);
                for (const [_, deeperSpec] of deeperImports) {
                    filesToIndex.push({ spec: deeperSpec, fromFile: resolvedFile, depth: depth + 1 });
                }
            }
        }
    }

    // 3. Run single-file taint tracking on the entry file
    const entryFlows = await trackTaint(entrySource, language);
    if (entryFlows.length === 0) {
        // No flows in the entry file — check if any imported functions
        // have sinks that could be reached through tainted parameters
        return checkImportedFunctionSinks(functionIndex, imports, opts.workspaceRoot, language);
    }

    // 4. Convert single-file results to cross-file results
    //    For now: if the entry file has flows, report them with the entry file
    //    as both source and sink file. If the flow involves a call to an
    //    indexed function, add the cross-file step.
    const results: CrossFileTaintResult[] = [];

    for (const flow of entryFlows) {
        const steps: CrossFileStep[] = [];
        let sourceFile = opts.filePath;
        let sinkFile = opts.filePath;

        for (const step of flow.propagationPath) {
            // Check if this step involves a call to an indexed function
            const callMatch = step.description.match(/^([\w$]+)\(\)/);
            if (callMatch && (step.operation === 'call-pass' || step.operation === 'sink-arg')) {
                const fnName = callMatch[1];
                const analysis = functionIndex.get(fnName);
                if (analysis && analysis.file !== opts.filePath) {
                    // This step crosses a file boundary
                    steps.push({
                        file: opts.filePath,
                        line: step.line,
                        variable: step.variable,
                        operation: 'call-cross-file',
                        description: `${fnName}() in ${analysis.file}:${analysis.line} ${analysis.returnsTainted ? 'returns tainted data' : 'propagates taint'}`,
                    });
                    sourceFile = analysis.file;
                    continue;
                }
            }

            steps.push({
                file: opts.filePath,
                line: step.line,
                variable: step.variable,
                operation: step.operation === 'source' ? 'source' : 'sink-arg',
                description: step.description,
            });
        }

        results.push({
            source: flow.source,
            sourceLine: flow.sourceLine,
            sourceFile,
            sink: flow.sink,
            sinkLine: flow.sinkLine,
            sinkFile,
            canonicalType: flow.canonicalType,
            crossFileSteps: steps,
        });
    }

    // 5. Also check imported functions for sinks reachable through params
    const importedSinks = await checkImportedFunctionSinks(functionIndex, imports, opts.workspaceRoot, language);
    results.push(...importedSinks);

    // Dedup by (source, sink, sinkFile, sinkLine)
    const seen = new Set<string>();
    const deduped: CrossFileTaintResult[] = [];
    for (const r of results) {
        const key = `${r.source}:${r.sink}:${r.sinkFile}:${r.sinkLine}`;
        if (!seen.has(key)) {
            seen.add(key);
            deduped.push(r);
        }
    }

    return deduped;
}

/**
 * Check imported functions for sinks reachable through tainted parameters.
 * If an imported function has a sink in its body and the caller passes
 * tainted data to the relevant parameter, that's a cross-file flow.
 */
async function checkImportedFunctionSinks(
    functionIndex: Map<string, FunctionAnalysis>,
    imports: Map<string, string>,
    workspaceRoot: string,
    language: SinkLanguage,
): Promise<CrossFileTaintResult[]> {
    const results: CrossFileTaintResult[] = [];

    for (const [name, analysis] of functionIndex) {
        if (analysis.taintThroughParams.size === 0) continue;

        // This function has sinks reachable through params.
        // Read its source and run trackTaint with all params seeded to find sinks.
        const fileAbs = path.resolve(workspaceRoot, analysis.file);
        let source: string;
        try {
            source = fs.readFileSync(fileAbs, 'utf8');
        } catch { continue; }

        // Seed all params of this function as taint sources
        const flows = await trackTaint(source, language, analysis.params);
        for (const flow of flows) {
            // Only include flows where the source is a seeded parameter
            const isParamSource = analysis.params.includes(flow.source.replace('<param:', '').replace('>', '')) ||
                flow.propagationPath.some(p => p.operation === 'source' && analysis.params.includes(p.variable));

            if (!isParamSource) continue;

            results.push({
                source: `${name}() param: ${flow.source}`,
                sourceLine: analysis.line,
                sourceFile: analysis.file,
                sink: flow.sink,
                sinkLine: flow.sinkLine,
                sinkFile: analysis.file,
                canonicalType: flow.canonicalType,
                crossFileSteps: [
                    {
                        file: analysis.file,
                        line: analysis.line,
                        variable: name,
                        operation: 'call-cross-file',
                        description: `${name}() called with tainted data — param "${flow.source}" reaches sink`,
                    },
                    {
                        file: analysis.file,
                        line: flow.sinkLine,
                        variable: flow.sink,
                        operation: 'sink-arg',
                        description: `${flow.sink}(${flow.propagationPath[flow.propagationPath.length - 1]?.variable || ''})`,
                    },
                ],
            });
        }
    }

    return results;
}
