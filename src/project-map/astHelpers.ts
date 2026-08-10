/**
 * Phase 4 — generic Tree-sitter AST helpers shared by Layer 1 (static
 * extraction) and Layer 2 (dynamic detection). Keeping them in one place
 * means the two layers share the same notion of "a call to X" and "a
 * string literal at this position".
 */

import * as fs from 'fs';
import * as path from 'path';
import { TreeSitterNode } from './parserLoader';

/** Walk the tree depth-first, yielding every named + unnamed node. */
export function* walk(node: TreeSitterNode): Iterable<TreeSitterNode> {
    yield node;
    for (const child of node.children) {
        yield* walk(child);
    }
}

/** Walk named nodes only (skips punctuation/brackets). */
export function* walkNamed(node: TreeSitterNode): Iterable<TreeSitterNode> {
    for (const n of walk(node)) {
        if (n.type !== '' && !n.type.startsWith('.')) {
            yield n;
        }
    }
}

/** True iff node is a string-literal node (JS/TS/Python all share 'string'). */
export function isStringLiteral(node: TreeSitterNode): boolean {
    return node.type === 'string';
}

/** True iff node is an identifier (variable reference). */
export function isIdentifier(node: TreeSitterNode): boolean {
    return node.type === 'identifier';
}

/** Get the text of a string literal without the surrounding quotes. */
export function stringLiteralValue(node: TreeSitterNode, source: string): string {
    if (!isStringLiteral(node)) return '';
    const raw = node.startIndex < node.endIndex
        ? source.slice(node.startIndex, node.endIndex)
        : '';
    // Strip surrounding quotes/backticks. Template literals keep ${...} as-is
    // (callers can detect template_argument_substitution if they need exactness).
    if (raw.length >= 2) {
        const f = raw[0];
        const l = raw[raw.length - 1];
        if ((f === '"' && l === '"') || (f === "'" && l === "'") || (f === '`' && l === '`')) {
            return raw.slice(1, -1);
        }
    }
    return raw;
}

/**
 * Find the first ancestor matching a predicate.
 */
export function firstAncestor(
    node: TreeSitterNode,
    pred: (n: TreeSitterNode) => boolean,
): TreeSitterNode | null {
    let cur: TreeSitterNode | null | undefined = node.parent;
    while (cur) {
        if (pred(cur)) return cur;
        cur = cur.parent;
    }
    return null;
}

/**
 * For a call_expression like `app.get('/x', mw, handler)`, return the parts:
 *   { receiver: 'app', method: 'get', args: [nodes...] }
 * Works for Python calls too (`app.get("/x", handler)`) because both
 * grammars expose call_expression with function being a member_expression.
 */
export interface CallParts {
    /**
     * The BASE identifier the call is rooted at ('app', 'router', 'res',
     * 'prisma'), or null for a free call.
     *
     * This is the base of the whole access chain, not the immediately
     * preceding expression: for `res.status(201).json(x)` the receiver is
     * `res`, not the text `res.status(201)`. Callers universally want to ask
     * "is this a call on the response object / the app / an imported module",
     * and comparing against the literal preceding text answers that question
     * wrongly the moment a chained call appears.
     */
    receiver: string | null;
    /** The full receiver expression as written, for display. */
    receiverText: string | null;
    /** The method name ('get', 'use', 'post', ...). */
    method: string;
    /** Argument nodes (positional). */
    args: TreeSitterNode[];
    /** Source-line of the call (0-indexed). */
    line: number;
}

/**
 * Walk an access chain down to the identifier it is rooted at.
 *
 * `res.status(201)` -> `res`, `prisma.user` -> `prisma`,
 * `supabase.from('x').select('*')` -> `supabase`. Returns null when the chain
 * bottoms out in something that is not an identifier (a literal, `this`, an
 * immediately-invoked function), in which case callers fall back to the text.
 */
export function baseIdentifier(node: TreeSitterNode, source: string): string | null {
    let cur: TreeSitterNode | null = node;
    // Bounded to keep a pathological/incorrectly-parsed tree from spinning.
    for (let hops = 0; cur && hops < 64; hops++) {
        if (isIdentifier(cur)) return source.slice(cur.startIndex, cur.endIndex);
        switch (cur.type) {
            case 'member_expression':
            case 'attribute':
            case 'call_expression':
            case 'call':
            case 'subscript_expression':
            case 'subscript':
                cur = cur.child(0);
                break;
            case 'await_expression':
            case 'await':
            case 'parenthesized_expression':
            case 'non_null_expression':
            case 'as_expression':
                cur = cur.namedChildren[0] ?? null;
                break;
            default:
                return null;
        }
    }
    return null;
}

/** Parse a call node into CallParts. Returns null if not a recognizable call. */
export function callParts(callNode: TreeSitterNode, source: string): CallParts | null {
    // JS/TS: 'call_expression' with function = 'member_expression'.
    // Python: 'call' with func = 'attribute' (e.g. app.get).
    const func = callNode.child(0);
    if (!func) return null;

    let receiver: string | null = null;
    let receiverText: string | null = null;
    let method = '';

    if (func.type === 'member_expression' || func.type === 'attribute') {
        const obj = func.child(0);
        const prop = func.child(func.childCount - 1);
        if (obj && prop) {
            receiverText = source.slice(obj.startIndex, obj.endIndex);
            receiver = baseIdentifier(obj, source) ?? receiverText;
            method = source.slice(prop.startIndex, prop.endIndex);
        }
    } else if (func.type === 'identifier') {
        method = source.slice(func.startIndex, func.endIndex);
    } else {
        return null;
    }

    // Collect args. JS: arguments node; Python: arguments node. Both have
    // named children for the positional args.
    const argsNode = callNode.child(callNode.childCount - 1);
    const args: TreeSitterNode[] = [];
    if (argsNode) {
        for (const c of argsNode.namedChildren) {
            args.push(c);
        }
    }

    return {
        receiver,
        receiverText,
        method,
        args,
        line: callNode.startPosition.row,
    };
}

/**
 * Resolve an identifier to a string value when it's defined as a
 * simple const/variable assignment to a string literal IN THE SAME FILE.
 * Used for intra-file dataflow confidence (0.6).
 *
 * `assignments` is a map of variableName -> stringLiteralValue, built by
 * a pre-pass over the file.
 */
export function resolveIdentifier(
    name: string,
    assignments: Map<string, string>,
): string | null {
    return assignments.get(name) ?? null;
}

/**
 * Build a map of `name -> string literal value` for every
 *   const X = 'literal'  /  let X = 'literal'  /  X = 'literal'
 * in the file. Also handles Python `X = 'literal'` at module level.
 */
export function collectStringAssignments(root: TreeSitterNode, source: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const n of walk(root)) {
        // JS/TS lexical_declaration / variable_declaration
        if (n.type === 'lexical_declaration' || n.type === 'variable_declaration') {
            for (const decl of n.namedChildren) {
                if (decl.type !== 'variable_declarator') continue;
                const name = decl.child(0);
                const value = decl.child(decl.childCount - 1);
                if (name && value && isIdentifier(name) && isStringLiteral(value)) {
                    out.set(source.slice(name.startIndex, name.endIndex), stringLiteralValue(value, source));
                }
            }
            continue;
        }
        // Python: simple assignment statement `name = "str"`
        if (n.type === 'assignment' || n.type === 'assign') {
            const left = n.child(0);
            const right = n.child(n.childCount - 1);
            if (left && right && isIdentifier(left) && isStringLiteral(right)) {
                out.set(source.slice(left.startIndex, left.endIndex), stringLiteralValue(right, source));
            }
            continue;
        }
        // JS expression statement that's an assignment (X = "y" without var)
        if (n.type === 'assignment_expression') {
            const left = n.child(0);
            const right = n.child(n.childCount - 1);
            if (left && right && isIdentifier(left) && isStringLiteral(right)) {
                out.set(source.slice(left.startIndex, left.endIndex), stringLiteralValue(right, source));
            }
        }
    }
    return out;
}

/**
 * Collect the local names bound by a destructuring pattern.
 *
 * Handles object and array patterns, renames (`{ a: b }` binds `b`), defaults
 * (`{ a = 1 }` binds `a`), and rest elements (`{ ...rest }`). Nested patterns
 * recurse. Used to map destructured `require()` bindings back to their module.
 */
function boundPatternNames(pattern: TreeSitterNode, source: string): string[] {
    const names: string[] = [];
    const visit = (node: TreeSitterNode): void => {
        switch (node.type) {
            case 'object_pattern':
            case 'array_pattern':
                for (const child of node.namedChildren) visit(child);
                return;
            case 'pair_pattern': {
                // { key: local } — only the value side introduces a binding.
                const value = node.namedChildren[node.namedChildren.length - 1];
                if (value) visit(value);
                return;
            }
            case 'object_assignment_pattern':
            case 'assignment_pattern': {
                // { a = default } — the left side is the binding.
                const target = node.namedChildren[0];
                if (target) visit(target);
                return;
            }
            case 'rest_pattern':
            case 'shorthand_property_identifier_pattern':
            case 'shorthand_property_identifier':
                for (const child of node.namedChildren) visit(child);
                if (node.namedChildren.length === 0) {
                    names.push(source.slice(node.startIndex, node.endIndex));
                }
                return;
            default:
                if (isIdentifier(node)) {
                    names.push(source.slice(node.startIndex, node.endIndex));
                    return;
                }
                for (const child of node.namedChildren) visit(child);
        }
    };
    visit(pattern);
    return names;
}

/**
 * Normalise a Python module reference into the same relative-path shape the
 * JS/TS import specs use, so one resolver handles both.
 *
 *   `.deps`      -> `./deps`
 *   `..models`   -> `../models`
 *   `.`          -> `./`
 *   `sqlalchemy.orm` -> unchanged (absolute; matched by name, not resolved)
 */
export function pythonModuleSpec(mod: string): string {
    const trimmed = mod.trim();
    const leading = /^\.+/.exec(trimmed);
    if (!leading) return trimmed;
    const depth = leading[0].length;
    const rest = trimmed.slice(depth).replace(/\./g, '/');
    const prefix = depth === 1 ? './' : '../'.repeat(depth - 1);
    return prefix + rest;
}

/** Collect every import in the file as { localName -> sourceSpec }. */
export function collectImports(root: TreeSitterNode, source: string): Map<string, string> {
    const out = new Map<string, string>();
    for (const n of walk(root)) {
        // JS/TS import statements. Python also uses the node type
        // `import_statement`, so the JS shape is only claimed when the
        // statement actually carries a string module specifier — otherwise it
        // falls through to the Python handling below.
        if (n.type === 'import_statement' || n.type === 'import_declaration') {
            const sourceNode = n.namedChildren.find(c => isStringLiteral(c));
            if (sourceNode) {
                const from = stringLiteralValue(sourceNode, source);
                // `import { a, b as c } from 'mod'` nests the specifiers two
                // levels down (import_clause > named_imports > import_specifier),
                // so the bindings are gathered by walking the statement rather
                // than by reading direct children — named imports are the
                // dominant ESM idiom and missing them makes the file look like
                // it imports nothing.
                for (const spec of walk(n)) {
                    if (spec === sourceNode) continue;
                    if (spec.type === 'import_specifier' || spec.type === 'namespace_import') {
                        const local = spec.namedChildren[spec.namedChildren.length - 1];
                        if (local && isIdentifier(local)) {
                            out.set(source.slice(local.startIndex, local.endIndex), from);
                        }
                        continue;
                    }
                    // Default import: an identifier directly under the clause.
                    if (isIdentifier(spec) && spec.parent?.type === 'import_clause') {
                        out.set(source.slice(spec.startIndex, spec.endIndex), from);
                    }
                }
                continue;
            }
        }
        // Python `import a.b`, `import a.b as c`, `from x.y import A, B as C`.
        //
        // The imported NAMES are `dotted_name` nodes just like the module is,
        // so they cannot be told apart by node type — only by position. The
        // module is the first named child; everything after it is a binding.
        if (n.type === 'import_statement' || n.type === 'import_from_statement') {
            const children = n.namedChildren;
            if (children.length === 0) continue;

            const bindLast = (node: TreeSitterNode, mod: string): void => {
                // `import os.path` binds `os`; `from x import a` binds `a`.
                const text = source.slice(node.startIndex, node.endIndex);
                const segments = text.split('.');
                const local = n.type === 'import_from_statement'
                    ? segments[segments.length - 1]
                    : segments[0];
                if (local) out.set(local.trim(), mod);
            };

            if (n.type === 'import_from_statement') {
                const moduleNode = children[0];
                const rawMod = source.slice(moduleNode.startIndex, moduleNode.endIndex);
                const mod = pythonModuleSpec(rawMod);
                const packageOnly = /^\.+$/.test(rawMod.trim());
                for (const c of children.slice(1)) {
                    if (c.type === 'wildcard_import') continue;
                    if (c.type === 'aliased_import') {
                        const alias = c.child(c.childCount - 1);
                        if (alias && isIdentifier(alias)) {
                            out.set(source.slice(alias.startIndex, alias.endIndex), mod);
                        }
                        continue;
                    }
                    // `from . import views` names a sibling MODULE, not a symbol
                    // of the current package, so the spec has to grow the name
                    // for it to resolve to a file.
                    if (packageOnly) {
                        const name = source.slice(c.startIndex, c.endIndex).trim();
                        out.set(name.split('.').pop()!, mod + name);
                        continue;
                    }
                    bindLast(c, mod);
                }
                continue;
            }

            // Plain `import a.b [as c]` — every child is its own module.
            for (const c of children) {
                if (c.type === 'aliased_import') {
                    const target = c.namedChildren[0];
                    const alias = c.child(c.childCount - 1);
                    const mod = target ? source.slice(target.startIndex, target.endIndex) : '';
                    if (alias && isIdentifier(alias)) {
                        out.set(source.slice(alias.startIndex, alias.endIndex), mod);
                    }
                    continue;
                }
                if (c.type === 'dotted_name' || isIdentifier(c)) {
                    bindLast(c, source.slice(c.startIndex, c.endIndex));
                }
            }
            continue;
        }
        // CommonJS: const X = require('mod') and const { A, B: C } = require('mod').
        // Destructured requires are the dominant idiom for several libraries we
        // must detect (`const { PrismaClient } = require('@prisma/client')`), so
        // binding patterns are walked for identifiers rather than skipped.
        if (n.type === 'lexical_declaration' || n.type === 'variable_declaration') {
            for (const decl of n.namedChildren) {
                if (decl.type !== 'variable_declarator') continue;
                const name = decl.child(0);
                const value = decl.child(decl.childCount - 1);
                if (!name || !value || value.type !== 'call_expression') continue;
                const parts = callParts(value, source);
                if (!parts || parts.method !== 'require' || parts.receiver !== null || parts.args.length !== 1) {
                    continue;
                }
                const a = parts.args[0];
                if (!isStringLiteral(a)) continue;
                const from = stringLiteralValue(a, source);
                if (isIdentifier(name)) {
                    out.set(source.slice(name.startIndex, name.endIndex), from);
                    continue;
                }
                // Binding pattern: map every bound local name to the module.
                for (const local of boundPatternNames(name, source)) {
                    out.set(local, from);
                }
            }
        }
    }
    return out;
}

/** Resolve a module spec like './middleware/auth' to an absolute file path. */
export function resolveModulePath(
    spec: string,
    fromFile: string,
    workspaceRoot: string,
): string | null {
    if (!spec.startsWith('.') && !spec.startsWith('/')) return null; // bare specifier = node_modules
    const base = path.resolve(path.dirname(fromFile), spec);
    const candidates = [
        base,
        base + '.ts',
        base + '.tsx',
        base + '.js',
        base + '.jsx',
        base + '.mjs',
        base + '.cjs',
        base + '.py',
        path.join(base, 'index.ts'),
        path.join(base, 'index.js'),
        path.join(base, 'index.tsx'),
        path.join(base, '__init__.py'),
    ];
    for (const c of candidates) {
        if (fs.existsSync(c)) return path.relative(workspaceRoot, c).replace(/\\/g, '/');
    }
    return null;
}
