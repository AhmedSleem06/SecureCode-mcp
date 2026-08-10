/**
 * Phase 4 Layer 2 — dynamic import / meta-programming detection.
 *
 * Scans the AST for the D1-D10 patterns from the README Phase 4 spec and
 * emits one DynamicPattern per detection with confidence 0.0. These are
 * the relationships we cannot statically resolve, and they're exactly the
 * ones a runtime trace can later confirm (upgrading to 0.8).
 *
 * Patterns:
 *   D1  require(<variable>)            — require with a non-literal arg
 *   D2  import(<variable>)             — dynamic import() with non-literal arg
 *   D3  require(`template ${x}`)       — template-literal import / require
 *   D4  app.use(process.env.X)         — config-driven middleware (env-driven)
 *   D5  require('loader')(name)         — proxy loader (calling the result of require)
 *   D6  new Function(...)              — Function constructor
 *   D7  vm.runIn*                       — vm module execution
 *   D8  if (x) require('a') else ...   — conditional require
 *   D9  eval(...)                      — eval-driven module resolution
 *   D10 require(glob.sync(...))        — wildcard / glob-driven loader
 */

import { TreeSitterNode } from './parserLoader';
import { callParts, isIdentifier, isStringLiteral, walk } from './astHelpers';
import { DynamicPattern, DynamicPatternType } from './types';

/** Make a short snippet for the panel (one line, trimmed). */
function snippet(source: string, node: TreeSitterNode): string {
    let txt = source.slice(node.startIndex, node.endIndex);
    // Collapse to one line and trim length.
    txt = txt.replace(/\s+/g, ' ').trim();
    if (txt.length > 120) txt = txt.slice(0, 117) + '...';
    return txt;
}

function make(
    type: DynamicPatternType,
    node: TreeSitterNode,
    source: string,
    file: string,
): DynamicPattern {
    return {
        type,
        file,
        line: node.startPosition.row + 1,
        snippet: snippet(source, node),
        confidence: 0.0,
    };
}

/**
 * Detect all D1-D10 patterns in a parsed file.
 *
 * @param file   workspace-relative file path
 * @param source file source text
 * @param root   parsed Tree-sitter root node
 */
export function detectDynamicPatterns(
    file: string,
    source: string,
    root: TreeSitterNode,
): DynamicPattern[] {
    const out: DynamicPattern[] = [];
    const seen = new Set<string>();

    const add = (p: DynamicPattern) => {
        const key = `${p.type}:${p.file}:${p.line}`;
        if (seen.has(key)) return;
        seen.add(key);
        out.push(p);
    };

    for (const n of walk(root)) {
        // --- Call expressions cover D1, D2, D5, D9, D10 ---
        if (n.type === 'call_expression' || n.type === 'call') {
            const p = callParts(n, source);
            if (p) {
                // D1: require(<non-literal>)
                if (p.method === 'require' && p.receiver === null && p.args.length >= 1) {
                    const arg = p.args[0];
                    if (!isStringLiteral(arg)) {
                        // D3: template-literal require
                        if (arg.type === 'template_string' || arg.type === 'template_literal') {
                            add(make('D3', n, source, file));
                        } else if (isIdentifier(arg)) {
                            // Could be D1, D8 (if inside an if), or D10 (if fed by glob.sync).
                            // We'll classify as D1 here; D8/D10 refine below.
                            // Check for D10: identifier assigned from glob.sync(...)
                            const name = source.slice(arg.startIndex, arg.endIndex);
                            if (isAssignedFromGlobSync(root, source, name)) {
                                add(make('D10', n, source, file));
                            } else if (isInsideConditional(root, source, n)) {
                                add(make('D8', n, source, file));
                            } else {
                                add(make('D1', n, source, file));
                            }
                        } else {
                            add(make('D1', n, source, file));
                        }
                    }
                }
                // D7: vm.runIn* — a member call, so it must be matched here on
                // call_expression. (The new_expression branch below never sees
                // it, since `vm.runInThisContext(code)` is a call, not a `new`.)
                if (/^runIn/.test(p.method) && (p.receiver === 'vm' || p.receiver === null || /vm$/.test(p.receiver ?? ''))) {
                    add(make('D7', n, source, file));
                }
                // D9: eval(...)
                if (p.method === 'eval' && p.receiver === null && p.args.length >= 1 && !isStringLiteral(p.args[0])) {
                    add(make('D9', n, source, file));
                }
            }

            // D2: dynamic import(). `import(spec)` parses as a call_expression
            // whose function child is a bare `import` node, which callParts()
            // cannot describe (there is no identifier to read a method name
            // from), so it is matched structurally instead.
            const fn = n.namedChildren[0];
            if (fn && (fn.type === 'import' || fn.type === 'import_expression')) {
                const args = n.namedChildren.find(c => c.type === 'arguments' || c.type === 'argument_list');
                const first = args?.namedChildren[0];
                if (first && !isStringLiteral(first)) {
                    add(make('D2', n, source, file));
                }
            }

            // D5: outer call whose receiver is a require(...) call.
            // require('loader')(target) — receiver of outer is a call_expression.
            if (n.type === 'call_expression') {
                const outerFunc = n.child(0);
                if (outerFunc && outerFunc.type === 'call_expression') {
                    const inner = callParts(outerFunc, source);
                    if (inner && inner.method === 'require' && inner.receiver === null && inner.args.length === 1 && isStringLiteral(inner.args[0])) {
                        add(make('D5', n, source, file));
                    }
                }
            }

            // D4: app.use(process.env.X) — config-driven middleware.
            if (p && p.method === 'use' && p.receiver && ['app', 'router', 'server', 'fastify'].includes(p.receiver)) {
                for (const arg of p.args) {
                    const txt = source.slice(arg.startIndex, arg.endIndex);
                    if (/process\.env\./.test(txt) || /\bgetenv\b/.test(txt) || /\bos\.environ\b/.test(txt)) {
                        add(make('D4', n, source, file));
                    }
                }
            }
        }

        // --- D2: import_expression / dynamic import node ---
        if (n.type === 'import_expression' || n.type === 'import') {
            const arg = n.namedChildren.find(c => !isStringLiteral(c) && c.type !== 'import');
            if (arg) {
                add(make('D2', n, source, file));
            }
        }

        // --- D6: new Function(...) / D7: new vm.Script(...) ---
        // For a new_expression, child(0) is the `new` KEYWORD; the constructor
        // is the first *named* child. Reading child(0) yields "new" and matches
        // nothing, which is why this silently detected nothing.
        if (n.type === 'new_expression' || n.type === 'call') {
            const callee = n.namedChildren[0];
            if (callee && (callee.type === 'identifier' || callee.type === 'member_expression' || callee.type === 'attribute')) {
                const name = source.slice(callee.startIndex, callee.endIndex);
                if (name === 'Function' || /(^|\.)Function$/.test(name)) {
                    add(make('D6', n, source, file));
                }
                if (/^vm\.runIn/.test(name) || /^runIn/.test(name) || /(^|\.)Script$/.test(name)) {
                    add(make('D7', n, source, file));
                }
            }
        }
    }

    return out;
}

const GLOB_SOURCE_RE = /\bglob\.sync\b|\bglobby\b|\bfast-glob\b|\brequire\.context\b|\bglobSync\b/;

/**
 * True iff `name` is (transitively) bound to a glob.sync(...) / globby(...)
 * result.
 *
 * Two shapes are recognised:
 *   const files = glob.sync('*.js'); require(files[0]);   // direct
 *   for (const f of glob.sync('*.js')) require(f);        // loop element
 *   const files = glob.sync('*.js');
 *   for (const f of files) require(f);                    // loop over a binding
 *
 * The loop forms matter because iterating a glob result is the idiomatic way
 * this pattern appears, and treating it as a plain D1 loses the information
 * that the module set is filesystem-driven.
 *
 * Note a `lexical_declaration`'s child(0) is the `const`/`let` KEYWORD — the
 * binding lives inside a `variable_declarator`, which is why this walks
 * declarators rather than reading positional children.
 */
function isAssignedFromGlobSync(root: TreeSitterNode, source: string, name: string): boolean {
    const globBoundNames = new Set<string>();

    // Pass 1: collect names bound directly to a glob-ish expression.
    for (const n of walk(root)) {
        if (n.type === 'lexical_declaration' || n.type === 'variable_declaration') {
            for (const decl of n.namedChildren) {
                if (decl.type !== 'variable_declarator') continue;
                const target = decl.namedChildren[0];
                const value = decl.namedChildren[decl.namedChildren.length - 1];
                if (!target || !value || target === value) continue;
                if (!isIdentifier(target)) continue;
                if (GLOB_SOURCE_RE.test(source.slice(value.startIndex, value.endIndex))) {
                    globBoundNames.add(source.slice(target.startIndex, target.endIndex));
                }
            }
            continue;
        }
        if (n.type === 'assignment_expression' || n.type === 'assign' || n.type === 'assignment') {
            const target = n.namedChildren[0];
            const value = n.namedChildren[n.namedChildren.length - 1];
            if (!target || !value || target === value) continue;
            if (!isIdentifier(target)) continue;
            if (GLOB_SOURCE_RE.test(source.slice(value.startIndex, value.endIndex))) {
                globBoundNames.add(source.slice(target.startIndex, target.endIndex));
            }
        }
    }

    if (globBoundNames.has(name)) return true;

    // Pass 2: for-of / for-in loop variables iterating a glob-ish sequence, or
    // iterating a name already known to hold one.
    for (const n of walk(root)) {
        if (n.type !== 'for_in_statement' && n.type !== 'for_of_statement' && n.type !== 'for_statement') continue;
        const loopVar = n.namedChildren.find(c => isIdentifier(c));
        if (!loopVar) continue;
        if (source.slice(loopVar.startIndex, loopVar.endIndex) !== name) continue;
        // The iterated expression is any later named child.
        const rest = n.namedChildren.filter(c => c !== loopVar);
        for (const c of rest) {
            const txt = source.slice(c.startIndex, c.endIndex);
            if (GLOB_SOURCE_RE.test(txt)) return true;
            if (isIdentifier(c) && globBoundNames.has(txt)) return true;
        }
    }

    return false;
}

/** True iff a node sits inside an if/ternary that branches on something. */
function isInsideConditional(root: TreeSitterNode, source: string, node: TreeSitterNode): boolean {
    let cur: TreeSitterNode | null | undefined = node.parent;
    while (cur) {
        if (cur.type === 'if_statement' || cur.type === 'conditional_expression' || cur.type === 'ternary_expression' || cur.type === 'if') {
            return true;
        }
        cur = cur.parent;
    }
    return false;
}
