/**
 * Phase C — taint propagation tracker.
 *
 * Walks a parsed file forward, maintaining a per-scope set of tainted
 * variables. When a source access is found (req.body, request.GET, etc.),
 * the variable is marked tainted. Taint propagates through assignments,
 * concatenations, and template interpolations. Sanitizer calls strip
 * taint. When a sink (from the sink registry) is encountered, the
 * arguments are checked for taint — if tainted, a TaintResult is recorded
 * with the full propagation path from source to sink.
 *
 * Intra-function: source and sink in the same function (the common case).
 * Inter-function: a simple first pass identifies functions that return
 * tainted data; calls to those functions propagate taint to the result.
 */

import { parseSource, TreeSitterNode } from './parserLoader';
import {
    walk, callParts, isIdentifier, isStringLiteral,
} from './astHelpers';
import { SINK_REGISTRY, SinkLanguage, SinkDefinition, SinkMatcher } from './sinkRegistry';
import { matchTaintSource } from './taintSources';
import { matchSanitizer } from './sanitizers';

// ── Types ───────────────────────────────────────────────────────────────────

export interface PropagationStep {
    line: number;       // 1-indexed
    variable: string;
    operation: 'source' | 'assign' | 'concat' | 'template' | 'call-pass' | 'sink-arg';
    description: string;
}

export interface TaintResult {
    source: string;
    sourceLine: number;      // 1-indexed
    sink: string;
    sinkLine: number;        // 1-indexed
    canonicalType: string;
    propagationPath: PropagationStep[];
    isTainted: boolean;
}

interface TaintInfo {
    source: string;
    sourceLine: number;
    path: PropagationStep[];
    sanitizersApplied: string[];
}

// ── Scope ───────────────────────────────────────────────────────────────────

interface Scope {
    tainted: Map<string, TaintInfo>;
    parent: Scope | null;
}

function scopeGet(scope: Scope, name: string): TaintInfo | undefined {
    let s: Scope | null = scope;
    while (s) {
        if (s.tainted.has(name)) return s.tainted.get(name);
        s = s.parent;
    }
    return undefined;
}

// ── Node type sets ──────────────────────────────────────────────────────────

const FUNCTION_NODE_TYPES = new Set([
    'function_declaration', 'function_definition', 'method_definition',
    'async_function_declaration', 'async_function_definition',
    'arrow_function', 'function_expression',
    'generator_function_declaration', 'generator_declaration',
]);

const CALL_NODE_TYPES = new Set(['call_expression', 'call', 'new_expression']);

const STATEMENT_TYPES = new Set([
    'expression_statement', 'lexical_declaration', 'variable_declaration',
    'if_statement', 'for_statement', 'for_in_statement', 'for_each_statement',
    'while_statement', 'do_statement', 'try_statement', 'try',
    'return_statement', 'return',
    'function_declaration', 'function_definition', 'method_definition',
    'block', 'statement_block',
    'export_statement', 'throw_statement', 'raise_statement',
    'with_statement', 'augmented_assignment', 'assignment',
    'decorated_definition',
]);

// ── Source detection ────────────────────────────────────────────────────────

/**
 * Check if an expression node is a source access. Returns the source text
 * if it is, null otherwise. Checks the text of the node against source
 * patterns (req.body, request.GET, etc.).
 */
function detectSource(node: TreeSitterNode, sourceText: string, language: SinkLanguage): string | null {
    const text = sourceText.slice(node.startIndex, node.endIndex);
    const match = matchTaintSource(text, language);
    return match ? text : null;
}

// ── Expression taint checking ───────────────────────────────────────────────

/**
 * Recursively check if an expression is tainted. Returns TaintInfo if
 * tainted, null otherwise.
 */
function checkExpressionTaint(
    node: TreeSitterNode,
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
): TaintInfo | null {
    // 1. Check if the node text is a source
    const srcText = detectSource(node, sourceText, language);
    if (srcText) {
        return {
            source: srcText,
            sourceLine: node.startPosition.row + 1,
            path: [{
                line: node.startPosition.row + 1,
                variable: srcText,
                operation: 'source',
                description: `Source: ${srcText}`,
            }],
            sanitizersApplied: [],
        };
    }

    // 2. Identifier — check if it's in the tainted set
    if (isIdentifier(node) || node.type === 'identifier') {
        const name = sourceText.slice(node.startIndex, node.endIndex);
        return scopeGet(scope, name) ?? null;
    }

    // 3. Call expression — check sanitizer, source method, taint-returning
    if (CALL_NODE_TYPES.has(node.type)) {
        const p = callParts(node, sourceText);
        if (p) {
            // Sanitizer → taint stripped
            const sanitizer = matchSanitizer(p.method, p.receiver, language);
            if (sanitizer) return null;

            // Function text starts with a source (e.g. req.body.get('q'))
            const funcText = p.receiverText
                ? `${p.receiverText}.${p.method}`
                : p.method;
            const srcMatch = matchTaintSource(funcText, language);
            if (srcMatch) {
                return {
                    source: funcText,
                    sourceLine: node.startPosition.row + 1,
                    path: [{
                        line: node.startPosition.row + 1,
                        variable: funcText,
                        operation: 'source',
                        description: `Source: ${funcText}`,
                    }],
                    sanitizersApplied: [],
                };
            }

            // Taint-returning function
            const fnName = p.receiver ?? p.method;
            if (taintReturningFns.has(fnName)) {
                // Find the tainted argument to carry the source info
                for (const arg of p.args) {
                    const argTaint = checkExpressionTaint(arg, scope, sourceText, language, taintReturningFns);
                    if (argTaint) {
                        return {
                            ...argTaint,
                            path: [...argTaint.path, {
                                line: node.startPosition.row + 1,
                                variable: fnName,
                                operation: 'call-pass',
                                description: `${fnName}() returns tainted data`,
                            }],
                        };
                    }
                }
                // Function is taint-returning but we can't trace the source
                return {
                    source: `<${fnName}>`,
                    sourceLine: node.startPosition.row + 1,
                    path: [{
                        line: node.startPosition.row + 1,
                        variable: fnName,
                        operation: 'call-pass',
                        description: `${fnName}() returns tainted data`,
                    }],
                    sanitizersApplied: [],
                };
            }
        }
        // Also check if the receiver of a method call is tainted
        // e.g. const x = req.body; x.toString() — x is tainted, so x.toString() is tainted
        if (node.type === 'call_expression' || node.type === 'call') {
            const func = node.child(0);
            if (func && (func.type === 'member_expression' || func.type === 'attribute')) {
                const obj = func.child(0);
                if (obj) {
                    const objTaint = checkExpressionTaint(obj, scope, sourceText, language, taintReturningFns);
                    if (objTaint) {
                        return {
                            ...objTaint,
                            path: [...objTaint.path, {
                                line: node.startPosition.row + 1,
                                variable: sourceText.slice(func.startIndex, func.endIndex),
                                operation: 'call-pass',
                                description: `Method call on tainted receiver`,
                            }],
                        };
                    }
                }
            }
        }
        return null;
    }

    // 4. Binary expression (concatenation) — check both operands
    if (node.type === 'binary_expression' || node.type === 'binary_operator_expression') {
        const left = node.child(0);
        const right = node.child(node.childCount - 1);
        const leftTaint = left ? checkExpressionTaint(left, scope, sourceText, language, taintReturningFns) : null;
        if (leftTaint) {
            return {
                ...leftTaint,
                path: [...leftTaint.path, {
                    line: node.startPosition.row + 1,
                    variable: sourceText.slice(node.startIndex, node.endIndex),
                    operation: 'concat',
                    description: `Concatenation with tainted data`,
                }],
            };
        }
        const rightTaint = right ? checkExpressionTaint(right, scope, sourceText, language, taintReturningFns) : null;
        if (rightTaint) {
            return {
                ...rightTaint,
                path: [...rightTaint.path, {
                    line: node.startPosition.row + 1,
                    variable: sourceText.slice(node.startIndex, node.endIndex),
                    operation: 'concat',
                    description: `Concatenation with tainted data`,
                }],
            };
        }
        return null;
    }

    // 5. Template literal — check interpolations
    if (node.type === 'template_literal' || node.type === 'template_string') {
        for (const child of node.namedChildren) {
            if (child.type === 'template_substitution' || child.type === 'template_expr') {
                const expr = child.namedChildren[0];
                if (expr) {
                    const taint = checkExpressionTaint(expr, scope, sourceText, language, taintReturningFns);
                    if (taint) {
                        return {
                            ...taint,
                            path: [...taint.path, {
                                line: node.startPosition.row + 1,
                                variable: sourceText.slice(node.startIndex, node.endIndex),
                                operation: 'template',
                                description: `Template interpolation with tainted data`,
                            }],
                        };
                    }
                }
            }
        }
        return null;
    }

    // 6. Member expression — check if the object is tainted
    if (node.type === 'member_expression' || node.type === 'attribute') {
        const obj = node.child(0);
        if (obj) {
            return checkExpressionTaint(obj, scope, sourceText, language, taintReturningFns);
        }
    }

    // 7. Subscript expression — check if the object is tainted (req.body['q'])
    if (node.type === 'subscript_expression' || node.type === 'subscript') {
        const obj = node.child(0);
        if (obj) {
            return checkExpressionTaint(obj, scope, sourceText, language, taintReturningFns);
        }
    }

    // 8. Await / parenthesized / as — unwrap
    if (node.type === 'await_expression' || node.type === 'await'
        || node.type === 'parenthesized_expression' || node.type === 'non_null_expression'
        || node.type === 'as_expression') {
        const inner = node.namedChildren[0];
        if (inner) {
            return checkExpressionTaint(inner, scope, sourceText, language, taintReturningFns);
        }
    }

    // 9. Python augmented assignment (x += tainted)
    if (node.type === 'augmented_assignment') {
        const right = node.child(node.childCount - 1);
        if (right) {
            return checkExpressionTaint(right, scope, sourceText, language, taintReturningFns);
        }
    }

    return null;
}

// ── Sink matching ──────────────────────────────────────────────────────────

/** Match a call's (receiver, method) against a single `call` matcher. */
function matchCallMatcher(
    matcher: Extract<SinkMatcher, { kind: 'call' }>,
    receiver: string | null,
    method: string,
): boolean {
    if (method !== matcher.method) return false;
    if (matcher.receiver === undefined) return receiver === null;
    if (matcher.receiver === '*') return true;
    return receiver === matcher.receiver;
}

/** Check if a call node matches any sink definition. Returns the def + args. */
function matchSink(
    node: TreeSitterNode,
    sourceText: string,
    language: SinkLanguage,
): { def: SinkDefinition; args: TreeSitterNode[]; line: number } | null {
    if (!CALL_NODE_TYPES.has(node.type)) return null;
    const p = callParts(node, sourceText);
    if (!p) return null;

    // Handle tagged template literals (queryRaw`...${x}...`)
    let args = p.args;
    const lastChild = node.child(node.childCount - 1);
    if (lastChild && (lastChild.type === 'template_literal' || lastChild.type === 'template_string')) {
        args = [lastChild];
    }

    for (const def of SINK_REGISTRY) {
        if (!def.languages.includes(language)) continue;
        for (const matcher of def.matchers) {
            if (matcher.kind !== 'call') continue;
            if (matchCallMatcher(matcher, p.receiver, p.method)) {
                return { def, args, line: p.line };
            }
        }
    }
    return null;
}

// ── Statement processing ───────────────────────────────────────────────────

/** Extract variable names from a destructuring pattern (object/array). */
function patternNames(pattern: TreeSitterNode, sourceText: string): string[] {
    const names: string[] = [];
    for (const n of walk(pattern)) {
        if (n.type === 'shorthand_property_identifier_pattern'
            || n.type === 'shorthand_property_identifier') {
            names.push(sourceText.slice(n.startIndex, n.endIndex));
            continue;
        }
        if (n.type === 'pair_pattern' || n.type === 'pair') {
            const value = n.namedChildren[n.namedChildren.length - 1];
            if (value && isIdentifier(value)) {
                names.push(sourceText.slice(value.startIndex, value.endIndex));
            }
        }
    }
    return names;
}

/**
 * Process a single variable declarator: `const x = expr` or `const { a, b } = expr`.
 * If the RHS is tainted, the LHS variable(s) are marked tainted in the scope.
 */
function processDeclarator(
    decl: TreeSitterNode,
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
): void {
    const lhs = decl.child(0);
    const rhs = decl.child(decl.childCount - 1);
    if (!lhs || !rhs || lhs === rhs) return;

    const taint = checkExpressionTaint(rhs, scope, sourceText, language, taintReturningFns);
    if (!taint) return;

    if (isIdentifier(lhs) || lhs.type === 'identifier') {
        const name = sourceText.slice(lhs.startIndex, lhs.endIndex);
        scope.tainted.set(name, {
            ...taint,
            path: [...taint.path, {
                line: decl.startPosition.row + 1,
                variable: name,
                operation: 'assign',
                description: `${name} = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
            }],
        });
    } else if (lhs.type === 'object_pattern' || lhs.type === 'array_pattern'
        || lhs.type === 'object' || lhs.type === 'list_pattern') {
        for (const name of patternNames(lhs, sourceText)) {
            scope.tainted.set(name, {
                ...taint,
                path: [...taint.path, {
                    line: decl.startPosition.row + 1,
                    variable: name,
                    operation: 'assign',
                    description: `const { ${name} } = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
                }],
            });
        }
    }
}

/**
 * Process an expression statement. Handles:
 * - Assignments: `x = tainted` → update scope
 * - Sink calls: `exec(tainted)` → record result
 */
function processExpression(
    node: TreeSitterNode,
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
    onSink: (result: TaintResult) => void,
): void {
    // Assignment: x = expr or x += expr
    if (node.type === 'assignment_expression' || node.type === 'assignment'
        || node.type === 'augmented_assignment') {
        const lhs = node.child(0);
        const rhs = node.child(node.childCount - 1);
        if (!lhs || !rhs || lhs === rhs) return;
        const taint = checkExpressionTaint(rhs, scope, sourceText, language, taintReturningFns);
        if (taint && isIdentifier(lhs)) {
            const name = sourceText.slice(lhs.startIndex, lhs.endIndex);
            scope.tainted.set(name, {
                ...taint,
                path: [...taint.path, {
                    line: node.startPosition.row + 1,
                    variable: name,
                    operation: 'assign',
                    description: `${name} = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
                }],
            });
        }
        return;
    }

    // Sink call
    const sinkMatch = matchSink(node, sourceText, language);
    if (sinkMatch) {
        for (const arg of sinkMatch.args) {
            const taint = checkExpressionTaint(arg, scope, sourceText, language, taintReturningFns);
            if (taint) {
                onSink({
                    source: taint.source,
                    sourceLine: taint.sourceLine,
                    sink: sinkMatch.def.id,
                    sinkLine: sinkMatch.line + 1,
                    canonicalType: sinkMatch.def.canonicalType,
                    propagationPath: [...taint.path, {
                        line: sinkMatch.line + 1,
                        variable: sourceText.slice(arg.startIndex, arg.endIndex),
                        operation: 'sink-arg',
                        description: `${sinkMatch.def.id}(${sourceText.slice(arg.startIndex, arg.endIndex)})`,
                    }],
                    isTainted: true,
                });
            }
        }
    }
}

/** Find the body node of a function. Returns null for expression-body arrows. */
function functionBody(fn: TreeSitterNode): TreeSitterNode | null {
    for (const c of fn.namedChildren) {
        if (c.type === 'statement_block' || c.type === 'block') return c;
    }
    return null;
}

/** Get the name of a function node. */
function functionName(fn: TreeSitterNode, sourceText: string): string | null {
    const id = fn.namedChildren.find(c => isIdentifier(c));
    if (id) return sourceText.slice(id.startIndex, id.endIndex);
    const parent = fn.parent;
    if (parent && (parent.type === 'lexical_declaration' || parent.type === 'variable_declaration' || parent.type === 'assignment')) {
        const name = parent.child(0);
        if (name && isIdentifier(name)) return sourceText.slice(name.startIndex, name.endIndex);
    }
    return null;
}

/**
 * Process a scope (function body or module level). Walks named children in
 * order, tracking taint and calling onSink when a tainted sink is found.
 */
function processScope(
    bodyNode: TreeSitterNode,
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
    onSink: (result: TaintResult) => void,
    onReturn: (taint: TaintInfo | null) => void,
): void {
    for (const stmt of bodyNode.namedChildren) {
        // Variable declaration
        if (stmt.type === 'lexical_declaration' || stmt.type === 'variable_declaration') {
            for (const decl of stmt.namedChildren) {
                if (decl.type === 'variable_declarator') {
                    // Check if the RHS is an arrow/function — recurse into it
                    const rhs = decl.child(decl.childCount - 1);
                    if (rhs && FUNCTION_NODE_TYPES.has(rhs.type)) {
                        const fnName = sourceText.slice(
                            (decl.child(0) ?? decl).startIndex,
                            (decl.child(0) ?? decl).endIndex,
                        );
                        const body = functionBody(rhs);
                        if (body) {
                            const childScope: Scope = { tainted: new Map(), parent: scope };
                            processScope(body, childScope, sourceText, language, taintReturningFns, onSink, onReturn);
                        }
                        continue;
                    }
                    processDeclarator(decl, scope, sourceText, language, taintReturningFns);
                }
            }
            continue;
        }

        // Expression statement
        if (stmt.type === 'expression_statement') {
            const expr = stmt.namedChildren[0];
            if (expr) processExpression(expr, scope, sourceText, language, taintReturningFns, onSink);
            continue;
        }

        // Python assignment (not inside expression_statement)
        if (stmt.type === 'assignment' || stmt.type === 'augmented_assignment') {
            processExpression(stmt, scope, sourceText, language, taintReturningFns, onSink);
            continue;
        }

        // Return statement
        if (stmt.type === 'return_statement' || stmt.type === 'return') {
            const expr = stmt.namedChildren[0];
            if (expr) {
                const taint = checkExpressionTaint(expr, scope, sourceText, language, taintReturningFns);
                onReturn(taint);
            } else {
                onReturn(null);
            }
            continue;
        }

        // Function declaration — recurse with new scope
        if (FUNCTION_NODE_TYPES.has(stmt.type)) {
            const body = functionBody(stmt);
            if (body) {
                const childScope: Scope = { tainted: new Map(), parent: scope };
                processScope(body, childScope, sourceText, language, taintReturningFns, onSink, onReturn);
            }
            continue;
        }

        // Export statement — recurse into the declaration
        if (stmt.type === 'export_statement') {
            for (const child of stmt.namedChildren) {
                if (STATEMENT_TYPES.has(child.type)) {
                    // Recursively process the exported declaration
                    processScope({ namedChildren: [child] } as any, scope, sourceText, language, taintReturningFns, onSink, onReturn);
                }
            }
            continue;
        }

        // Control flow — recurse into body
        if (stmt.type === 'if_statement' || stmt.type === 'for_statement'
            || stmt.type === 'for_in_statement' || stmt.type === 'for_each_statement'
            || stmt.type === 'while_statement' || stmt.type === 'do_statement'
            || stmt.type === 'try_statement' || stmt.type === 'try'
            || stmt.type === 'with_statement' || stmt.type === 'block'
            || stmt.type === 'statement_block'
            || stmt.type === 'decorated_definition') {
            for (const child of stmt.namedChildren) {
                if (child.type === 'statement_block' || child.type === 'block'
                    || STATEMENT_TYPES.has(child.type)) {
                    processScope(
                        child.type === 'statement_block' || child.type === 'block' ? child : { namedChildren: [child] } as any,
                        scope, sourceText, language, taintReturningFns, onSink, onReturn,
                    );
                }
            }
            continue;
        }
    }
}

// ── First pass: identify taint-returning functions ─────────────────────────

/**
 * Walk the AST and identify functions that return tainted data. A function
 * is taint-returning if any return statement in its body returns a source
 * access or a tainted variable.
 */
function findTaintReturningFunctions(
    root: TreeSitterNode,
    sourceText: string,
    language: SinkLanguage,
): Set<string> {
    const result = new Set<string>();
    for (const node of walk(root)) {
        if (!FUNCTION_NODE_TYPES.has(node.type)) continue;
        const name = functionName(node, sourceText);
        if (!name) continue;
        const body = functionBody(node);
        if (!body) continue;

        const scope: Scope = { tainted: new Map(), parent: null };
        let returnsTainted = false;
        processScope(body, scope, sourceText, language, new Set(), () => {}, (taint) => {
            if (taint) returnsTainted = true;
        });
        if (returnsTainted) result.add(name);
    }
    return result;
}

// ── Main entry point ───────────────────────────────────────────────────────

/**
 * Track taint propagation through source code. Returns a TaintResult for
 * every sink where tainted data reaches an argument.
 *
 * @param source   the file's source text
 * @param language  the grammar to parse with
 * @returns taint results, one per tainted sink argument. Empty when the
 *          grammar is missing, the file fails to parse, or no tainted data
 *          reaches any sink (best-effort: never throws).
 */
export async function trackTaint(
    source: string,
    language: SinkLanguage,
): Promise<TaintResult[]> {
    const parsed = await parseSource(source, language);
    if (!parsed) return [];
    const { root } = parsed;

    // First pass: identify taint-returning functions
    const taintReturningFns = findTaintReturningFunctions(root, source, language);

    // Second pass: track taint and record results at sinks
    const results: TaintResult[] = [];
    const onSink = (result: TaintResult) => {
        // Dedup by (source, sink, sinkLine)
        const key = `${result.source}:${result.sink}:${result.sinkLine}`;
        if (!results.some(r => `${r.source}:${r.sink}:${r.sinkLine}` === key)) {
            results.push(result);
        }
    };

    // Process module level
    const moduleScope: Scope = { tainted: new Map(), parent: null };
    processScope(root, moduleScope, source, language, taintReturningFns, onSink, () => {});

    return results;
}
