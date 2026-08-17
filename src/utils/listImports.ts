/**
 * Import listing utility — parses a file and returns its imports.
 *
 * Uses collectImports from astHelpers, which handles:
 *   - ES modules: import X from 'mod', import { A, B } from 'mod'
 *   - CommonJS: const X = require('mod'), const { A, B } = require('mod')
 *   - Python: import mod, from mod import X, import mod.sub as alias
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseSource, grammarForFile } from '../project-map/parserLoader';
import { collectImports, walk } from '../project-map/astHelpers';

export interface ImportEntry {
    name: string;       // local binding name
    source: string;     // module spec
    line: number;       // 1-indexed line of the import statement
}

export async function listImports(
    workspaceRoot: string,
    filePath: string,
): Promise<ImportEntry[]> {
    const absPath = path.resolve(workspaceRoot, filePath);
    const content = fs.readFileSync(absPath, 'utf8');
    const lang = grammarForFile(absPath);
    if (lang === 'unknown') return [];

    const parsed = await parseSource(content, lang);
    if (!parsed) return [];

    const { root } = parsed;
    const importMap = collectImports(root, content);

    // collectImports returns a Map<localName, sourceSpec> but doesn't track
    // line numbers. Walk the AST to find import statements and their lines.
    const lineMap = new Map<string, number>(); // localName -> line

    for (const n of walk(root)) {
        if (n.type === 'import_declaration' || n.type === 'import_statement') {
            const line = n.startPosition.row + 1;
            // Find the local names bound by this import
            for (const child of walk(n)) {
                if (child.type === 'import_specifier' || child.type === 'namespace_import') {
                    const local = child.namedChildren[child.namedChildren.length - 1];
                    if (local && local.type === 'identifier') {
                        const name = content.slice(local.startIndex, local.endIndex);
                        lineMap.set(name, line);
                    }
                }
                if (child.type === 'identifier' && child.parent?.type === 'import_clause') {
                    const name = content.slice(child.startIndex, child.endIndex);
                    lineMap.set(name, line);
                }
            }
            // Python import_statement
            if (n.type === 'import_statement' && !n.namedChildren.find(c => c.type === 'string')) {
                for (const c of n.namedChildren) {
                    if (c.type === 'dotted_name' || c.type === 'identifier') {
                        const name = content.slice(c.startIndex, c.endIndex);
                        lineMap.set(name.split('.')[0], line);
                    }
                    if (c.type === 'aliased_import') {
                        const alias = c.child(c.childCount - 1);
                        if (alias && alias.type === 'identifier') {
                            lineMap.set(content.slice(alias.startIndex, alias.endIndex), line);
                        }
                    }
                }
            }
        }
        if (n.type === 'import_from_statement') {
            const line = n.startPosition.row + 1;
            for (const c of n.namedChildren.slice(1)) {
                if (c.type === 'aliased_import') {
                    const alias = c.child(c.childCount - 1);
                    if (alias && alias.type === 'identifier') {
                        lineMap.set(content.slice(alias.startIndex, alias.endIndex), line);
                    }
                } else if (c.type === 'dotted_name' || c.type === 'identifier') {
                    const name = content.slice(c.startIndex, c.endIndex);
                    lineMap.set(name.split('.').pop()!, line);
                }
            }
        }
        // CommonJS require
        if (n.type === 'lexical_declaration' || n.type === 'variable_declaration') {
            for (const decl of n.namedChildren) {
                if (decl.type !== 'variable_declarator') continue;
                const value = decl.child(decl.childCount - 1);
                if (!value || value.type !== 'call_expression') continue;
                // Check if it's a require() call
                const text = content.slice(value.startIndex, value.endIndex);
                if (!text.includes('require(')) continue;

                const line = n.startPosition.row + 1;
                const nameNode = decl.child(0);
                if (!nameNode) continue;

                if (nameNode.type === 'identifier') {
                    lineMap.set(content.slice(nameNode.startIndex, nameNode.endIndex), line);
                } else {
                    // Binding pattern: walk for identifiers
                    for (const child of walk(nameNode)) {
                        if (child.type === 'identifier' && child.parent?.type !== 'member_expression') {
                            lineMap.set(content.slice(child.startIndex, child.endIndex), line);
                        }
                    }
                }
            }
        }
    }

    // Build the result from the import map + line map
    const entries: ImportEntry[] = [];
    for (const [name, source] of importMap) {
        entries.push({
            name,
            source,
            line: lineMap.get(name) || 0,
        });
    }

    entries.sort((a, b) => a.line - b.line);
    return entries;
}

export function formatImports(imports: ImportEntry[], filePath: string): string {
    if (imports.length === 0) {
        return `No imports found in ${filePath}.`;
    }
    const lines: string[] = [`Imports in ${filePath} (${imports.length}):`];
    for (const imp of imports) {
        lines.push(`  L${imp.line}  ${imp.name}  from  "${imp.source}"`);
    }
    return lines.join('\n');
}
