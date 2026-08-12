/**
 * Phase B — AST-based sink finder.
 *
 * Walks a parsed file once and matches every call/assignment/jsx-attribute
 * against the sink registry. Returns findings with argument shapes and
 * enclosing-function context so the Taint Tracker (Phase C) and the Juror
 * can reason about exploitability without re-parsing.
 *
 * Replaces the regex `sinkFloorService` with zero false positives on
 * variable names that happen to match sink names (`const exec = ...`),
 * sinks inside comments (AST skips them), and sinks inside string literals.
 */

import { parseSource, nodeText, TreeSitterNode } from './parserLoader';
import {
    walk, callParts, baseIdentifier, firstAncestor, isIdentifier, isStringLiteral,
} from './astHelpers';
import { SINK_REGISTRY, SinkLanguage, SinkDefinition, SinkMatcher } from './sinkRegistry';
import { matchTaintSource } from './taintSources';

// ── Output types ────────────────────────────────────────────────────────────

export interface ArgInfo {
    kind: 'literal' | 'template' | 'identifier' | 'binary' | 'call' | 'other';
    /** For literal: the string value. For identifier: the variable name. For call: the call name. */
    value?: string;
    /** For template: whether the template has interpolation. */
    interpolated?: boolean;
}

export interface SinkFinding {
    /** 1-indexed start line. */
    line: number;
    /** 1-indexed end line (inclusive). */
    endLine: number;
    /** Sink id from the registry: 'exec', 'eval', 'innerHTML'. */
    sink: string;
    /** Canonical vulnerability type (matches API taxonomy). */
    canonicalType: string;
    severity: 'Critical' | 'High' | 'Medium';
    /** The full call/assignment expression text (for display). */
    callExpression: string;
    /** Each argument's shape — empty for member-assignment / jsx-attribute. */
    arguments: ArgInfo[];
    /** Name of the enclosing function, or null at module level. */
    enclosingFunction: string | null;
    /** Whether the sink is inside a try/catch block. */
    isInsideTryCatch: boolean;
}

// ── Argument shape classification ──────────────────────────────────────────

function classifyArg(node: TreeSitterNode, source: string): ArgInfo {
    // JS/TS string literal
    if (isStringLiteral(node)) {
        return { kind: 'literal', value: source.slice(node.startIndex, node.endIndex) };
    }
    // Python string node is also 'string'
    if (node.type === 'string') {
        return { kind: 'literal', value: source.slice(node.startIndex, node.endIndex) };
    }
    // Numeric, boolean, regex, null, undefined → literal
    if (['number', 'true', 'false', 'null', 'undefined', 'none', 'float', 'integer', 'boolean'].includes(node.type)) {
        return { kind: 'literal', value: source.slice(node.startIndex, node.endIndex) };
    }
    // Function/arrow expressions are code, not user input — treat as literal
    // for requireNonLiteralArg purposes (taint tracker handles closure taint).
    if (['arrow_function', 'function_expression', 'function'].includes(node.type)) {
        return { kind: 'literal', value: '<function>' };
    }
    // Template literal / template string
    if (node.type === 'template_string' || node.type === 'template_literal') {
        const interpolated = node.namedChildren.some(
            c => c.type === 'template_substitution' || c.type === 'template_expr',
        );
        return { kind: 'template', interpolated };
    }
    // Identifier — a variable reference
    if (isIdentifier(node)) {
        return { kind: 'identifier', value: source.slice(node.startIndex, node.endIndex) };
    }
    // Python identifier is 'identifier'
    if (node.type === 'identifier') {
        return { kind: 'identifier', value: source.slice(node.startIndex, node.endIndex) };
    }
    // Binary expression (concatenation, arithmetic)
    if (node.type === 'binary_expression' || node.type === 'binary_operator_expression') {
        return { kind: 'binary' };
    }
    // Python f-string / formatted string
    if (node.type === 'concatenated_string' || node.type === 'string_interpolation') {
        return { kind: 'template', interpolated: true };
    }
    // Call expression
    if (node.type === 'call_expression' || node.type === 'call') {
        const p = callParts(node, source);
        return { kind: 'call', value: p ? (p.receiver ? `${p.receiver}.${p.method}` : p.method) : undefined };
    }
    // Member expression (e.g. req.body.q) — treat as identifier-like
    if (node.type === 'member_expression' || node.type === 'attribute') {
        return { kind: 'identifier', value: source.slice(node.startIndex, node.endIndex) };
    }
    return { kind: 'other' };
}

/** True if an argument is non-literal (potentially attacker-controlled). */
function isNonLiteral(arg: ArgInfo): boolean {
    if (arg.kind === 'literal') return false;
    if (arg.kind === 'template' && !arg.interpolated) return false;
    return true;
}

/**
 * Check if an argument node's source text contains a user-input taint source.
 * Used by `requireUserSource` to filter sinks that only matter when the
 * argument is attacker-controlled (SSRF, header injection, SSTI).
 *
 * This is a local text check, not full taint propagation — it catches direct
 * references like `req.query.url` and `req.body.template` but not indirect
 * flows like `const url = req.query.url; fetch(url)`. The taint tracker
 * (Phase C) handles indirect flows separately.
 */
function argHasUserSource(
    argNodes: TreeSitterNode[],
    source: string,
    language: SinkLanguage,
): boolean {
    for (const node of argNodes) {
        const text = source.slice(node.startIndex, node.endIndex);
        // Direct source: req.body, req.query, etc. — also catches template
        // interpolation `...${req.query.url}...` and concatenation "..." + req.query.url
        if (matchTaintSource(text, language)) return true;
        // For template literals, check each interpolation expression
        if (node.type === 'template_string' || node.type === 'template_literal') {
            for (const child of walk(node)) {
                if (child.type === 'template_substitution' || child.type === 'template_expr') {
                    const exprText = source.slice(child.startIndex, child.endIndex);
                    if (matchTaintSource(exprText, language)) return true;
                }
            }
        }
        // For binary expressions (concatenation), check both sides
        if (node.type === 'binary_expression' || node.type === 'binary_operator_expression') {
            for (const child of node.namedChildren) {
                const childText = source.slice(child.startIndex, child.endIndex);
                if (matchTaintSource(childText, language)) return true;
            }
        }
    }
    return false;
}

// ── Enclosing function + try/catch ──────────────────────────────────────────

const FUNCTION_NODE_TYPES = new Set([
    'function_declaration', 'function_definition', 'method_definition',
    'async_function_declaration', 'async_function_definition',
    'arrow_function', 'function_expression',
    'generator_function_declaration', 'generator_declaration',
]);

const TRY_TYPES = new Set(['try_statement', 'try']);

function enclosingFunctionName(node: TreeSitterNode, source: string): string | null {
    const fn = firstAncestor(node, n => FUNCTION_NODE_TYPES.has(n.type));
    if (!fn) return null;
    // Named function: function foo() {} — the name is the first identifier child
    const id = fn.namedChildren.find(c => isIdentifier(c));
    if (id) return source.slice(id.startIndex, id.endIndex);
    // const foo = () => {} — the name is on the declarator's parent
    const parent = fn.parent;
    if (parent) {
        if (parent.type === 'lexical_declaration' || parent.type === 'variable_declaration') {
            for (const decl of parent.namedChildren) {
                if (decl.type !== 'variable_declarator') continue;
                const name = decl.child(0);
                if (name && isIdentifier(name)) {
                    return source.slice(name.startIndex, name.endIndex);
                }
            }
        }
        // Python: `name = def x():` → assignment
        if (parent.type === 'assignment') {
            const target = parent.child(0);
            if (target && isIdentifier(target)) {
                return source.slice(target.startIndex, target.endIndex);
            }
        }
    }
    return '<anonymous>';
}

function isInsideTryCatch(node: TreeSitterNode): boolean {
    return firstAncestor(node, n => TRY_TYPES.has(n.type)) !== null;
}

// ── Matching ────────────────────────────────────────────────────────────────

/** Extract (receiver, method, args, line) from call_expression/call/new_expression. */
interface CallInfo {
    receiver: string | null;
    method: string;
    args: TreeSitterNode[];
    line: number;
}

function extractCallInfo(node: TreeSitterNode, source: string): CallInfo | null {
    if (node.type === 'call_expression' || node.type === 'call') {
        const p = callParts(node, source);
        if (!p) return null;
        let args = p.args;
        // Tagged template literal: `tag\`...\`` — tree-sitter parses the
        // template_literal as the last child directly (not inside an
        // `arguments` node). callParts then extracts the template's named
        // children (substitutions) instead of the template itself. Detect
        // this and use the template node as the sole argument.
        const lastChild = node.child(node.childCount - 1);
        if (lastChild
            && (lastChild.type === 'template_literal' || lastChild.type === 'template_string')) {
            args = [lastChild];
        }
        return { receiver: p.receiver, method: p.method, args, line: p.line };
    }
    if (node.type === 'new_expression') {
        // new_expression: `new Constructor(args)` — constructor is the first named child.
        const constructor = node.namedChildren.find(c =>
            c.type === 'identifier' || c.type === 'member_expression',
        );
        if (!constructor) return null;
        let receiver: string | null = null;
        let method = '';
        if (constructor.type === 'member_expression') {
            const obj = constructor.child(0);
            const prop = constructor.child(constructor.childCount - 1);
            if (obj && prop) {
                receiver = baseIdentifier(obj, source) ?? nodeText(obj, source);
                method = source.slice(prop.startIndex, prop.endIndex);
            }
        } else {
            method = source.slice(constructor.startIndex, constructor.endIndex);
        }
        // Args: last named child that's an arguments/argument_list node.
        const argsNode = node.namedChildren.find(c =>
            c.type === 'arguments' || c.type === 'argument_list',
        );
        const args: TreeSitterNode[] = [];
        if (argsNode) {
            for (const c of argsNode.namedChildren) args.push(c);
        }
        return { receiver, method, args, line: node.startPosition.row };
    }
    return null;
}

/** Match a call's (receiver, method) against a single `call` matcher. */
function matchCall(
    matcher: Extract<SinkMatcher, { kind: 'call' }>,
    receiver: string | null,
    method: string,
): boolean {
    if (method !== matcher.method) return false;
    if (matcher.receiver === undefined) return receiver === null;
    if (matcher.receiver === '*') return true;
    return receiver === matcher.receiver;
}

/** Check if a definition applies to the given language. */
function defForLanguage(def: SinkDefinition, lang: SinkLanguage): boolean {
    return def.languages.includes(lang);
}

// ── Finder ──────────────────────────────────────────────────────────────────

/**
 * Find all security sinks in source code via AST analysis.
 *
 * @param source  the file's source text
 * @param language  the grammar to parse with
 * @returns sink findings, ordered by line. Empty when the grammar is missing
 *          or the file fails to parse (best-effort: never throws).
 */
export async function findSinks(
    source: string,
    language: SinkLanguage,
): Promise<SinkFinding[]> {
    const parsed = await parseSource(source, language);
    if (!parsed) return [];
    const { root } = parsed;

    const findings: SinkFinding[] = [];
    // Dedup key: `${line}:${canonicalType}` — same as the regex sink floor.
    const seen = new Set<string>();

    for (const node of walk(root)) {
        // ── 1. Call sinks (call_expression / call / new_expression) ──────
        if (node.type === 'call_expression' || node.type === 'call' || node.type === 'new_expression') {
            const info = extractCallInfo(node, source);
            if (!info) continue;
            for (const def of SINK_REGISTRY) {
                if (!defForLanguage(def, language)) continue;
                let matched = false;
                for (const matcher of def.matchers) {
                    if (matcher.kind !== 'call') continue;
                    if (matchCall(matcher, info.receiver, info.method)) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) continue;
                const args = info.args.map(a => classifyArg(a, source));
                // For call sinks, only the FIRST argument is the injection
                // vector (the query string, the path, the redirect URL).
                // Subsequent arguments are parameters/options (e.g.
                // db.query("SELECT...?", [params]) — the array is NOT an
                // injection vector). Checking all args would false-positive
                // on parameterized queries.
                if (def.requireNonLiteralArg && !(args.length > 0 && isNonLiteral(args[0]))) continue;
                if (def.requireUserSource && !argHasUserSource(info.args, source, language)) continue;
                const key = `${info.line + 1}:${def.canonicalType}`;
                if (seen.has(key)) continue;
                seen.add(key);
                findings.push({
                    line: info.line + 1,
                    endLine: (node.endPosition?.row ?? info.line) + 1,
                    sink: def.id,
                    canonicalType: def.canonicalType,
                    severity: def.severity,
                    callExpression: source.slice(node.startIndex, node.endIndex),
                    arguments: args,
                    enclosingFunction: enclosingFunctionName(node, source),
                    isInsideTryCatch: isInsideTryCatch(node),
                });
                break; // first matching definition wins (registry is severity-ordered)
            }
            continue;
        }

        // ── 2. Member-assignment sinks (.innerHTML = ...) ────────────────
        if (node.type === 'assignment_expression' || node.type === 'assignment') {
            const lhs = node.child(0);
            if (!lhs) continue;
            // LHS must be a member_expression / attribute
            if (lhs.type !== 'member_expression' && lhs.type !== 'attribute') continue;
            const propNode = lhs.child(lhs.childCount - 1);
            if (!propNode) continue;
            const propName = source.slice(propNode.startIndex, propNode.endIndex);
            for (const def of SINK_REGISTRY) {
                if (!defForLanguage(def, language)) continue;
                let matched = false;
                for (const matcher of def.matchers) {
                    if (matcher.kind !== 'member-assignment') continue;
                    if (matcher.property === propName) { matched = true; break; }
                }
                if (!matched) continue;
                const rhs = node.child(node.childCount - 1);
                const args = rhs ? [classifyArg(rhs, source)] : [];
                if (def.requireNonLiteralArg && !args.some(isNonLiteral)) continue;
                const key = `${node.startPosition.row + 1}:${def.canonicalType}`;
                if (seen.has(key)) continue;
                seen.add(key);
                findings.push({
                    line: node.startPosition.row + 1,
                    endLine: (node.endPosition?.row ?? node.startPosition.row) + 1,
                    sink: def.id,
                    canonicalType: def.canonicalType,
                    severity: def.severity,
                    callExpression: source.slice(node.startIndex, node.endIndex),
                    arguments: args,
                    enclosingFunction: enclosingFunctionName(node, source),
                    isInsideTryCatch: isInsideTryCatch(node),
                });
                break;
            }
            continue;
        }

        // ── 3. JSX attribute sinks (dangerouslySetInnerHTML) ─────────────
        if (node.type === 'jsx_attribute') {
            const nameNode = node.child(0);
            if (!nameNode) continue;
            const attrName = source.slice(nameNode.startIndex, nameNode.endIndex);
            for (const def of SINK_REGISTRY) {
                if (!defForLanguage(def, language)) continue;
                let matched = false;
                for (const matcher of def.matchers) {
                    if (matcher.kind !== 'jsx-attribute') continue;
                    if (matcher.name === attrName) { matched = true; break; }
                }
                if (!matched) continue;
                const key = `${node.startPosition.row + 1}:${def.canonicalType}`;
                if (seen.has(key)) continue;
                seen.add(key);
                // The value is child(1) or namedChildren[1]
                const valueNode = node.namedChildren.length > 1 ? node.namedChildren[1] : null;
                const args = valueNode ? [classifyArg(valueNode, source)] : [];
                findings.push({
                    line: node.startPosition.row + 1,
                    endLine: (node.endPosition?.row ?? node.startPosition.row) + 1,
                    sink: def.id,
                    canonicalType: def.canonicalType,
                    severity: def.severity,
                    callExpression: source.slice(node.startIndex, node.endIndex),
                    arguments: args,
                    enclosingFunction: enclosingFunctionName(node, source),
                    isInsideTryCatch: isInsideTryCatch(node),
                });
                break;
            }
        }
    }

    findings.sort((a, b) => a.line - b.line);
    return findings;
}
