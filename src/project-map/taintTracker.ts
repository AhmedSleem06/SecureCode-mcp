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
    operation: 'source' | 'assign' | 'concat' | 'template' | 'call-pass' | 'sink-arg' | 'store-write' | 'store-read';
    description: string;
}

export type TaintSourceKind = 'request input' | 'stored input' | 'identity claim';

export interface TaintResult {
    source: string;
    sourceLine: number;      // 1-indexed
    sink: string;
    sinkLine: number;        // 1-indexed
    canonicalType: string;
    propagationPath: PropagationStep[];
    isTainted: boolean;
    sourceKind: TaintSourceKind;
    sourceDescription?: string;
}

interface TaintInfo {
    source: string;
    sourceLine: number;
    path: PropagationStep[];
    sanitizersApplied: string[];
    sourceKind: TaintSourceKind;
}

// ── Scope ───────────────────────────────────────────────────────────────────

interface Scope {
    tainted: Map<string, TaintInfo>;
    allTaints: Map<string, TaintInfo[]>;
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

function scopeGetAll(scope: Scope, name: string): TaintInfo[] {
    let s: Scope | null = scope;
    while (s) {
        const all = s.allTaints.get(name);
        if (all && all.length > 0) return all;
        if (s.tainted.has(name)) return [s.tainted.get(name)!];
        s = s.parent;
    }
    return [];
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

// ── Identity claim detection ────────────────────────────────────────────

const IDENTITY_PREFIXES = [
    'req.user.', 'req.auth.', 'request.user.', 'request.auth.',
    'ctx.state.user.', 'req.user[', 'req.auth[', 'request.user[', 'request.auth[',
];

function isIdentityClaim(text: string): boolean {
    return IDENTITY_PREFIXES.some(p => text.startsWith(p));
}

// ── Source detection ────────────────────────────────────────────────────────

/**
 * Check if an expression node is a source access. Returns the source text
 * if it is, null otherwise. Checks the text of the node against source
 * patterns (req.body, request.GET, etc.).
 */
function detectSource(node: TreeSitterNode, sourceText: string, language: SinkLanguage): { text: string; kind: TaintSourceKind } | null {
    const text = sourceText.slice(node.startIndex, node.endIndex);
    if (isIdentityClaim(text)) {
        return { text, kind: 'identity claim' };
    }
    const match = matchTaintSource(text, language);
    return match ? { text, kind: 'request input' } : null;
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
    stores?: ModuleStores,
): TaintInfo | null {
    // 1. Check if the node text is a source
    const srcMatch = detectSource(node, sourceText, language);
    if (srcMatch) {
        return {
            source: srcMatch.text,
            sourceLine: node.startPosition.row + 1,
            path: [{
                line: node.startPosition.row + 1,
                variable: srcMatch.text,
                operation: 'source',
                description: `Source: ${srcMatch.text}`,
            }],
            sanitizersApplied: [],
            sourceKind: srcMatch.kind,
        };
    }

    // 1b. Check store reads
    if (stores) {
        const storeRead = checkStoreReadTaint(node, sourceText, stores);
        if (storeRead) return storeRead;
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
            const funcSrcMatch = matchTaintSource(funcText, language);
            const funcIdentity = isIdentityClaim(funcText);
            if (funcSrcMatch || funcIdentity) {
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
                    sourceKind: funcIdentity ? 'identity claim' : 'request input',
                };
            }

            // Taint-returning function
            const fnName = p.receiver ?? p.method;
            if (taintReturningFns.has(fnName)) {
                // Find the tainted argument to carry the source info
                for (const arg of p.args) {
                    const argTaint = checkExpressionTaint(arg, scope, sourceText, language, taintReturningFns, stores);
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
                    sourceKind: 'request input',
                };
            }

            // General argument propagation — for non-sanitizer, non-source,
            // non-taint-returning calls, check if any argument is tainted.
            // Catches passthrough wrappers like SQLAlchemy text(),
            // base64.b64decode(), str(), etc.
            for (const arg of p.args) {
                const argTaint = checkExpressionTaint(arg, scope, sourceText, language, taintReturningFns, stores);
                if (argTaint) {
                    return {
                        ...argTaint,
                        path: [...argTaint.path, {
                            line: node.startPosition.row + 1,
                            variable: sourceText.slice(node.startIndex, node.endIndex),
                            operation: 'call-pass',
                            description: `Tainted data passed through ${p.method}()`,
                        }],
                    };
                }
            }
        }
        // Also check if the receiver of a method call is tainted
        // e.g. const x = req.body; x.toString() — x is tainted, so x.toString() is tainted
        if (node.type === 'call_expression' || node.type === 'call') {
            const func = node.child(0);
            if (func && (func.type === 'member_expression' || func.type === 'attribute')) {
                const obj = func.child(0);
                if (obj) {
                    const objTaint = checkExpressionTaint(obj, scope, sourceText, language, taintReturningFns, stores);
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
    if (node.type === 'binary_expression' || node.type === 'binary_operator_expression'
        || node.type === 'binary_operator') {
        const left = node.child(0);
        const right = node.child(node.childCount - 1);
        const leftTaint = left ? checkExpressionTaint(left, scope, sourceText, language, taintReturningFns, stores) : null;
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
        const rightTaint = right ? checkExpressionTaint(right, scope, sourceText, language, taintReturningFns, stores) : null;
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
                    const taint = checkExpressionTaint(expr, scope, sourceText, language, taintReturningFns, stores);
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
            return checkExpressionTaint(obj, scope, sourceText, language, taintReturningFns, stores);
        }
    }

    // 7. Subscript expression — check if the object is tainted (req.body['q'])
    if (node.type === 'subscript_expression' || node.type === 'subscript') {
        const obj = node.child(0);
        if (obj) {
            return checkExpressionTaint(obj, scope, sourceText, language, taintReturningFns, stores);
        }
    }

    // 8. Await / parenthesized / as — unwrap
    if (node.type === 'await_expression' || node.type === 'await'
        || node.type === 'parenthesized_expression' || node.type === 'non_null_expression'
        || node.type === 'as_expression') {
        const inner = node.namedChildren[0];
        if (inner) {
            return checkExpressionTaint(inner, scope, sourceText, language, taintReturningFns, stores);
        }
    }

    // 9. Python augmented assignment (x += tainted)
    if (node.type === 'augmented_assignment') {
        const right = node.child(node.childCount - 1);
        if (right) {
            return checkExpressionTaint(right, scope, sourceText, language, taintReturningFns, stores);
        }
    }

    // 10. Object literal — if any property value is tainted, the object is tainted
    if (node.type === 'object' || node.type === 'object_expression') {
        for (const child of node.namedChildren) {
            if (child.type === 'pair' || child.type === 'property') {
                const val = child.namedChildren[child.namedChildren.length - 1];
                if (val) {
                    const taint = checkExpressionTaint(val, scope, sourceText, language, taintReturningFns, stores);
                    if (taint) return taint;
                }
            }
            if (child.type === 'shorthand_property_identifier' || child.type === 'shorthand_property_identifier_pattern') {
                const name = sourceText.slice(child.startIndex, child.endIndex);
                const taint = scopeGet(scope, name);
                if (taint) return taint;
            }
            if (child.type === 'spread_element') {
                const inner = child.namedChildren[0];
                if (inner) {
                    const taint = checkExpressionTaint(inner, scope, sourceText, language, taintReturningFns, stores);
                    if (taint) return taint;
                }
            }
        }
    }

    // 11. Array literal — if any element is tainted, the array is tainted
    if (node.type === 'array' || node.type === 'array_expression') {
        for (const child of node.namedChildren) {
            const taint = checkExpressionTaint(child, scope, sourceText, language, taintReturningFns, stores);
            if (taint) return taint;
        }
    }

    // 12. Conditional (ternary) expression — if either branch is tainted, result is tainted
    if (node.type === 'ternary_expression' || node.type === 'conditional_expression') {
        const children = node.namedChildren;
        if (children.length >= 3) {
            const thenTaint = checkExpressionTaint(children[1], scope, sourceText, language, taintReturningFns, stores);
            if (thenTaint) return thenTaint;
            const elseTaint = checkExpressionTaint(children[2], scope, sourceText, language, taintReturningFns, stores);
            if (elseTaint) return elseTaint;
        }
    }

    return null;
}

// ── Multi-taint collection ─────────────────────────────────────────────

function collectAllTaints(
    node: TreeSitterNode,
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
    stores?: ModuleStores,
): TaintInfo[] {
    const results: TaintInfo[] = [];
    const seen = new Set<string>();

    const collect = (n: TreeSitterNode): void => {
        if (n.type === 'binary_expression' || n.type === 'binary_operator_expression'
            || n.type === 'binary_operator') {
            const left = n.child(0);
            const right = n.child(n.childCount - 1);
            if (left) collect(left);
            if (right) collect(right);
            return;
        }
        if (n.type === 'template_literal' || n.type === 'template_string') {
            for (const child of n.namedChildren) {
                if (child.type === 'template_substitution' || child.type === 'template_expr') {
                    const expr = child.namedChildren[0];
                    if (expr) collect(expr);
                }
            }
            return;
        }
        const taint = checkExpressionTaint(n, scope, sourceText, language, taintReturningFns, stores);
        if (taint) {
            const key = `${taint.source}:${taint.sourceLine}:${taint.sourceKind}`;
            if (!seen.has(key)) {
                seen.add(key);
                results.push(taint);
            }
        }
    };

    collect(node);
    if (results.length === 0) {
        const single = checkExpressionTaint(node, scope, sourceText, language, taintReturningFns, stores);
        if (single) results.push(single);
    }
    return results;
}


function emitSinkResults(
    sinkMatch: { def: SinkDefinition; args: TreeSitterNode[]; line: number },
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
    onSink: (result: TaintResult) => void,
    stores?: ModuleStores,
): void {
    for (const arg of sinkMatch.args) {
        const taints = collectAllTaints(arg, scope, sourceText, language, taintReturningFns, stores);
        if (taints.length <= 1 && isIdentifier(arg)) {
            const name = sourceText.slice(arg.startIndex, arg.endIndex);
            const all = scopeGetAll(scope, name);
            if (all.length > taints.length) {
                for (const t of all) {
                    const key = `${t.source}:${t.sourceLine}:${t.sourceKind}`;
                    if (!taints.some(x => `${x.source}:${x.sourceLine}:${x.sourceKind}` === key)) {
                        taints.push(t);
                    }
                }
            }
        }
        for (const taint of taints) {
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
                sourceKind: taint.sourceKind || 'request input',
            });
        }
    }
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

// ── Stored-data tracking ────────────────────────────────────────────────

interface StoreTaintEntry {
    storeName: string;
    writeLine: number;
    writeContext: string;
    sourceTaint: TaintInfo;
}

interface ModuleStores {
    taintedStores: Map<string, StoreTaintEntry>;
}

function makeStoreReadTaint(entry: StoreTaintEntry, readLine: number, readExpr: string): TaintInfo {
    return {
        source: entry.sourceTaint.source,
        sourceLine: entry.sourceTaint.sourceLine,
        path: [
            ...entry.sourceTaint.path,
            {
                line: entry.writeLine,
                variable: entry.storeName,
                operation: 'store-write' as const,
                description: `Stored into ${entry.storeName} (${entry.writeContext})`,
            },
            {
                line: readLine,
                variable: readExpr,
                operation: 'store-read' as const,
                description: `Read from ${entry.storeName}`,
            },
        ],
        sanitizersApplied: [],
        sourceKind: 'stored input',
    };
}

const STORE_WRITE_METHODS = new Set(['set', 'push', 'unshift', 'add']);
const STORE_READ_METHODS = new Set(['get', 'values', 'entries', 'keys', 'forEach', 'map', 'filter', 'find', 'some', 'every', 'reduce', 'flatMap']);

function detectStoreWrite(
    node: TreeSitterNode,
    scope: Scope,
    sourceText: string,
    language: SinkLanguage,
    taintReturningFns: Set<string>,
    stores: ModuleStores,
    fnContext: string,
): void {
    if (node.type === 'assignment_expression' || node.type === 'assignment'
        || node.type === 'augmented_assignment') {
        const lhs = node.child(0);
        const rhs = node.child(node.childCount - 1);
        if (!lhs || !rhs || lhs === rhs) return;

        if (lhs.type === 'subscript_expression' || lhs.type === 'subscript') {
            const obj = lhs.child(0);
            if (obj && isIdentifier(obj)) {
                const storeName = sourceText.slice(obj.startIndex, obj.endIndex);
                const taint = checkExpressionTaint(rhs, scope, sourceText, language, taintReturningFns, stores);
                if (taint) {
                    stores.taintedStores.set(storeName, {
                        storeName,
                        writeLine: node.startPosition.row + 1,
                        writeContext: fnContext,
                        sourceTaint: taint,
                    });
                }
            }
        }

        if (lhs.type === 'member_expression' || lhs.type === 'attribute') {
            const obj = lhs.child(0);
            if (obj && isIdentifier(obj)) {
                const storeName = sourceText.slice(obj.startIndex, obj.endIndex);
                const taint = checkExpressionTaint(rhs, scope, sourceText, language, taintReturningFns, stores);
                if (taint) {
                    stores.taintedStores.set(storeName, {
                        storeName,
                        writeLine: node.startPosition.row + 1,
                        writeContext: fnContext,
                        sourceTaint: taint,
                    });
                }
            }
        }
    }

    if (CALL_NODE_TYPES.has(node.type)) {
        const p = callParts(node, sourceText);
        if (!p || !p.receiver) return;
        if (STORE_WRITE_METHODS.has(p.method)) {
            for (const arg of p.args) {
                const taint = checkExpressionTaint(arg, scope, sourceText, language, taintReturningFns, stores);
                if (taint) {
                    stores.taintedStores.set(p.receiver, {
                        storeName: p.receiver,
                        writeLine: node.startPosition.row + 1,
                        writeContext: fnContext,
                        sourceTaint: taint,
                    });
                    return;
                }
            }
            if (p.method === 'set' && p.args.length >= 2) {
                const valArg = p.args[p.args.length - 1];
                const valText = sourceText.slice(valArg.startIndex, valArg.endIndex);
                const valTaint = scopeGet(scope, valText);
                if (valTaint) {
                    stores.taintedStores.set(p.receiver, {
                        storeName: p.receiver,
                        writeLine: node.startPosition.row + 1,
                        writeContext: fnContext,
                        sourceTaint: valTaint,
                    });
                    return;
                }
                for (const child of walk(valArg)) {
                    if (isIdentifier(child)) {
                        const name = sourceText.slice(child.startIndex, child.endIndex);
                        const childTaint = scopeGet(scope, name);
                        if (childTaint) {
                            stores.taintedStores.set(p.receiver, {
                                storeName: p.receiver,
                                writeLine: node.startPosition.row + 1,
                                writeContext: fnContext,
                                sourceTaint: childTaint,
                            });
                            return;
                        }
                    }
                }
            }
        }
    }
}

function checkStoreReadTaint(
    node: TreeSitterNode,
    sourceText: string,
    stores: ModuleStores,
): TaintInfo | null {
    if (CALL_NODE_TYPES.has(node.type)) {
        const p = callParts(node, sourceText);
        if (p && p.receiver && STORE_READ_METHODS.has(p.method)) {
            const entry = stores.taintedStores.get(p.receiver);
            if (entry) {
                return makeStoreReadTaint(entry, node.startPosition.row + 1, sourceText.slice(node.startIndex, node.endIndex));
            }
        }
    }

    if (node.type === 'member_expression' || node.type === 'attribute') {
        const obj = node.child(0);
        if (obj) {
            if (isIdentifier(obj)) {
                const name = sourceText.slice(obj.startIndex, obj.endIndex);
                const entry = stores.taintedStores.get(name);
                if (entry) {
                    const prop = node.child(node.childCount - 1);
                    const propText = prop ? sourceText.slice(prop.startIndex, prop.endIndex) : '';
                    if (!STORE_READ_METHODS.has(propText) && !STORE_WRITE_METHODS.has(propText) && propText !== 'length' && propText !== 'size') {
                        return makeStoreReadTaint(entry, node.startPosition.row + 1, sourceText.slice(node.startIndex, node.endIndex));
                    }
                }
            }
            if (CALL_NODE_TYPES.has(obj.type)) {
                const p = callParts(obj, sourceText);
                if (p && p.receiver && STORE_READ_METHODS.has(p.method)) {
                    const entry = stores.taintedStores.get(p.receiver);
                    if (entry) {
                        return makeStoreReadTaint(entry, node.startPosition.row + 1, sourceText.slice(node.startIndex, node.endIndex));
                    }
                }
            }
        }
    }

    if (node.type === 'subscript_expression' || node.type === 'subscript') {
        const obj = node.child(0);
        if (obj && isIdentifier(obj)) {
            const name = sourceText.slice(obj.startIndex, obj.endIndex);
            const entry = stores.taintedStores.get(name);
            if (entry) {
                return makeStoreReadTaint(entry, node.startPosition.row + 1, sourceText.slice(node.startIndex, node.endIndex));
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
    onSink?: (result: TaintResult) => void,
    stores?: ModuleStores,
): void {
    const lhs = decl.child(0);
    const rhs = decl.child(decl.childCount - 1);
    if (!lhs || !rhs || lhs === rhs) return;

    // Check if the RHS is a sink call with tainted arguments BEFORE
    // propagating taint. This catches `const x = db.query(tainted)` and
    // `const x = await db.query(tainted)`.
    if (onSink) {
        // Unwrap await/parenthesized expressions to find the inner call
        let sinkCheckNode = rhs;
        while (sinkCheckNode.type === 'await_expression' || sinkCheckNode.type === 'await'
            || sinkCheckNode.type === 'parenthesized_expression') {
            sinkCheckNode = sinkCheckNode.namedChildren[0];
            if (!sinkCheckNode) break;
        }
        if (sinkCheckNode && CALL_NODE_TYPES.has(sinkCheckNode.type)) {
            const sinkMatch = matchSink(sinkCheckNode, sourceText, language);
            if (sinkMatch && onSink) {
                emitSinkResults(sinkMatch, scope, sourceText, language, taintReturningFns, onSink, stores);
            }
        }
    }

    const taint = checkExpressionTaint(rhs, scope, sourceText, language, taintReturningFns, stores);
    if (!taint) return;

    const allRhsTaints = collectAllTaints(rhs, scope, sourceText, language, taintReturningFns, stores);

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
        if (allRhsTaints.length > 1) {
            scope.allTaints.set(name, allRhsTaints.map(t => ({
                ...t,
                path: [...t.path, {
                    line: decl.startPosition.row + 1,
                    variable: name,
                    operation: 'assign' as const,
                    description: `${name} = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
                }],
            })));
        }
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
    stores?: ModuleStores,
    fnContext?: string,
): void {
    // Assignment: x = expr or x += expr
    if (node.type === 'assignment_expression' || node.type === 'assignment'
        || node.type === 'augmented_assignment') {
        const lhs = node.child(0);
        const rhs = node.child(node.childCount - 1);
        if (!lhs || !rhs || lhs === rhs) return;

        // Check if RHS is a sink call with tainted arguments
        if (CALL_NODE_TYPES.has(rhs.type)) {
            const sinkMatch = matchSink(rhs, sourceText, language);
            if (sinkMatch) {
                emitSinkResults(sinkMatch, scope, sourceText, language, taintReturningFns, onSink, stores);
            }
        }

        const taint = checkExpressionTaint(rhs, scope, sourceText, language, taintReturningFns, stores);

        // Check for member-assignment sinks (el.innerHTML = tainted)
        if (taint && lhs.type === 'member_expression') {
            const propNode = lhs.child(lhs.childCount - 1);
            if (propNode) {
                const propText = sourceText.slice(propNode.startIndex, propNode.endIndex);
                for (const def of SINK_REGISTRY) {
                    if (!def.languages.includes(language)) continue;
                    for (const matcher of def.matchers) {
                        if (matcher.kind !== 'member-assignment') continue;
                        if (matcher.property === propText) {
                            onSink({
                                source: taint.source,
                                sourceLine: taint.sourceLine,
                                sink: def.id,
                                sinkLine: node.startPosition.row + 1,
                                canonicalType: def.canonicalType,
                                propagationPath: [...taint.path, {
                                    line: node.startPosition.row + 1,
                                    variable: `${propText} = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
                                    operation: 'sink-arg',
                                    description: `${def.id} = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
                                }],
                                isTainted: true,
                            sourceKind: taint.sourceKind || 'request input',
                            });
                        }
                    }
                }
            }
        }

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
            const allRhsTaints = collectAllTaints(rhs, scope, sourceText, language, taintReturningFns, stores);
            if (allRhsTaints.length > 1) {
                scope.allTaints.set(name, allRhsTaints.map(t => ({
                    ...t,
                    path: [...t.path, {
                        line: node.startPosition.row + 1,
                        variable: name,
                        operation: 'assign' as const,
                        description: `${name} = ${sourceText.slice(rhs.startIndex, rhs.endIndex)}`,
                    }],
                })));
            }
        }
        if (stores) detectStoreWrite(node, scope, sourceText, language, taintReturningFns, stores, fnContext || 'module');
        return;
    }

    // Sink call — the statement's own call plus sink calls nested in its
    // arguments (e.g. res.send(fs.readFileSync(p))), excluding callbacks,
    // which are processed as their own scopes below.
    const sinkCalls: TreeSitterNode[] = [node];
    if (CALL_NODE_TYPES.has(node.type)) {
        const visit = (n: TreeSitterNode): void => {
            for (const c of n.namedChildren) {
                if (FUNCTION_NODE_TYPES.has(c.type)) continue;
                if (CALL_NODE_TYPES.has(c.type)) sinkCalls.push(c);
                visit(c);
            }
        };
        visit(node);
    }
    for (const callNode of sinkCalls) {
    const sinkMatch = matchSink(callNode, sourceText, language);
    if (sinkMatch) {
        emitSinkResults(sinkMatch, scope, sourceText, language, taintReturningFns, onSink, stores);
    }
    }

    if (stores && CALL_NODE_TYPES.has(node.type)) {
        detectStoreWrite(node, scope, sourceText, language, taintReturningFns, stores, fnContext || 'module');
    }

    // Recurse into arrow/function callbacks passed as call arguments.
    // This catches app.post('/path', (req, res) => { ... }) where the
    // handler body contains sources and sinks. Walk the entire call
    // subtree to find function nodes (they may be nested inside arguments).
    if (CALL_NODE_TYPES.has(node.type)) {
        for (const child of walk(node)) {
            // Skip the outer call node itself — only look at children
            if (child === node) continue;
            if (FUNCTION_NODE_TYPES.has(child.type)) {
                const body = functionBody(child);
                if (body) {
                    const childScope: Scope = { tainted: new Map(), allTaints: new Map(), parent: scope };
                    processScope(body, childScope, sourceText, language, taintReturningFns, onSink, () => {}, stores);
                }
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
    stores?: ModuleStores,
    fnContext?: string,
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
                            const childScope: Scope = { tainted: new Map(), allTaints: new Map(), parent: scope };
                            processScope(body, childScope, sourceText, language, taintReturningFns, onSink, onReturn, stores, fnName);
                        }
                        continue;
                    }
                    processDeclarator(decl, scope, sourceText, language, taintReturningFns, onSink, stores);
                }
            }
            continue;
        }

        // Expression statement
        if (stmt.type === 'expression_statement') {
            const expr = stmt.namedChildren[0];
            if (expr) processExpression(expr, scope, sourceText, language, taintReturningFns, onSink, stores, fnContext);
            continue;
        }

        // Python assignment (not inside expression_statement)
        if (stmt.type === 'assignment' || stmt.type === 'augmented_assignment') {
            processExpression(stmt, scope, sourceText, language, taintReturningFns, onSink, stores, fnContext);
            continue;
        }

        // Return statement
        if (stmt.type === 'return_statement' || stmt.type === 'return') {
            const expr = stmt.namedChildren[0];
            if (expr) {
                // Check for sinks within the return expression
                for (const node of walk(expr)) {
                    if (CALL_NODE_TYPES.has(node.type)) {
                        const sinkMatch = matchSink(node, sourceText, language);
                        if (sinkMatch) {
                            emitSinkResults(sinkMatch, scope, sourceText, language, taintReturningFns, onSink, stores);
                        }
                    }
                }
                const taint = checkExpressionTaint(expr, scope, sourceText, language, taintReturningFns, stores);
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
                const childScope: Scope = { tainted: new Map(), allTaints: new Map(), parent: scope };
                processScope(body, childScope, sourceText, language, taintReturningFns, onSink, onReturn, stores, functionName(stmt, sourceText) || fnContext);
            }
            continue;
        }

        // Export statement — recurse into the declaration
        if (stmt.type === 'export_statement') {
            for (const child of stmt.namedChildren) {
                if (STATEMENT_TYPES.has(child.type)) {
                    processScope({ namedChildren: [child] } as any, scope, sourceText, language, taintReturningFns, onSink, onReturn, stores, fnContext);
                }
            }
            continue;
        }

        // for..of / for..in iteration — taint loop variable from store
        if ((stmt.type === 'for_in_statement' || stmt.type === 'for_each_statement') && stores) {
            const children = stmt.namedChildren;
            if (children.length >= 2) {
                const iterVar = children[0];
                const iterExpr = children[1];
                if (iterExpr) {
                    let exprTaint: TaintInfo | null = null;
                    const storeRead = checkStoreReadTaint(iterExpr, sourceText, stores);
                    if (storeRead) {
                        exprTaint = storeRead;
                    } else if (isIdentifier(iterExpr)) {
                        const iterName = sourceText.slice(iterExpr.startIndex, iterExpr.endIndex);
                        const storeEntry = stores.taintedStores.get(iterName);
                        if (storeEntry) {
                            exprTaint = makeStoreReadTaint(storeEntry, iterExpr.startPosition.row + 1, iterName);
                        }
                    }
                    if (!exprTaint) {
                        exprTaint = checkExpressionTaint(iterExpr, scope, sourceText, language, taintReturningFns, stores);
                    }
                    if (exprTaint) {
                        let varName: string | null = null;
                        if (iterVar.type === 'lexical_declaration' || iterVar.type === 'variable_declaration') {
                            const decl = iterVar.namedChildren[0];
                            if (decl) {
                                const lhs = decl.child(0);
                                if (lhs && isIdentifier(lhs)) {
                                    varName = sourceText.slice(lhs.startIndex, lhs.endIndex);
                                }
                            }
                        } else if (isIdentifier(iterVar)) {
                            varName = sourceText.slice(iterVar.startIndex, iterVar.endIndex);
                        }
                        if (varName) {
                            scope.tainted.set(varName, {
                                ...exprTaint,
                                path: [...exprTaint.path, {
                                    line: stmt.startPosition.row + 1,
                                    variable: varName,
                                    operation: 'assign',
                                    description: `${varName} from iteration`,
                                }],
                            });
                        }
                    }
                }
            }
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
                if (child.type === 'with_item' || child.type === 'with_clause') {
                    for (const item of walk(child)) {
                        if (item !== child && CALL_NODE_TYPES.has(item.type)) {
                            processExpression(item, scope, sourceText, language, taintReturningFns, onSink, stores, fnContext);
                        }
                    }
                } else if (child.type === 'statement_block' || child.type === 'block'
                    || STATEMENT_TYPES.has(child.type)) {
                    processScope(
                        child.type === 'statement_block' || child.type === 'block' ? child : { namedChildren: [child] } as any,
                        scope, sourceText, language, taintReturningFns, onSink, onReturn, stores, fnContext,
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

        const scope: Scope = { tainted: new Map(), allTaints: new Map(), parent: null };
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
 * @param seedParams  optional: parameter names to pre-taint as sources
 *                    (used by cross-file taint tracking to analyze
 *                    imported functions)
 * @returns taint results, one per tainted sink argument. Empty when the
 *          grammar is missing, the file fails to parse, or no tainted data
 *          reaches any sink (best-effort: never throws).
 */
export async function trackTaint(
    source: string,
    language: SinkLanguage,
    seedParams?: string[],
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
    const moduleScope: Scope = { tainted: new Map(), allTaints: new Map(), parent: null };

    // Pre-seed parameters as taint sources (for cross-file analysis)
    if (seedParams) {
        for (const param of seedParams) {
            moduleScope.tainted.set(param, {
                source: `<param:${param}>`,
                sourceLine: 1,
                path: [{
                    line: 1,
                    variable: param,
                    operation: 'source',
                    description: `Parameter ${param} (tainted by caller)`,
                }],
                sanitizersApplied: [],
                sourceKind: 'request input',
            });
        }
    }

    const moduleStores: ModuleStores = { taintedStores: new Map() };
    processScope(root, moduleScope, source, language, taintReturningFns, onSink, () => {}, moduleStores);

    return results;
}
