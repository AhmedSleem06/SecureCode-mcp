/**
 * Symbol index — structural find_definition and find_references across the
 * workspace. Replaces regex-based search_code for "where is X defined?" and
 * "who calls X?" questions.
 *
 * Two providers:
 *   - TypeScriptProgramProvider: uses ts.createProgram for JS/TS/TSX —
 *     accurate cross-file definition + references via the type system.
 *   - TreeSitterProvider: uses tree-sitter AST for Python — intra-file
 *     definition + workspace-wide reference search via identifier matching.
 *
 * Both return SymbolLocation[] with provider + confidence metadata.
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseSource, grammarForFile } from './parserLoader';
import { walk, isIdentifier, collectImports } from './astHelpers';
import { resolveWorkspacePath } from '../utils/files';
import { searchCode } from '../utils/searchCode';

export interface SymbolQuery {
    /** Workspace-relative file path where the symbol was referenced. */
    filePath: string;
    /** The symbol name to search for. */
    symbol: string;
    /** Optional 1-indexed line (for disambiguation). */
    line?: number;
    /** Optional 0-indexed column (for disambiguation). */
    column?: number;
}

export interface SymbolLocation {
    /** Workspace-relative file path. */
    filePath: string;
    /** 1-indexed line. */
    line: number;
    /** 1-indexed column (0 if unknown). */
    column: number;
    /** The provider that produced this result. */
    provider: 'typescript' | 'tree-sitter';
    /** Confidence: 1.0 for TypeScript, 0.8 for tree-sitter. */
    confidence: number;
    /** What this location represents. */
    kind: 'definition' | 'reference';
}

interface SymbolProvider {
    readonly name: string;
    findDefinition(query: SymbolQuery, workspaceRoot: string): Promise<SymbolLocation[]>;
    findReferences(query: SymbolQuery, workspaceRoot: string): Promise<SymbolLocation[]>;
}

// ── TypeScript provider ────────────────────────────────────────────────────

class TypeScriptProgramProvider implements SymbolProvider {
    readonly name = 'typescript';

    private isSupported(filePath: string): boolean {
        const ext = path.extname(filePath).toLowerCase();
        return ext === '.ts' || ext === '.tsx' || ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs';
    }

    async findDefinition(query: SymbolQuery, workspaceRoot: string): Promise<SymbolLocation[]> {
        if (!this.isSupported(query.filePath)) return [];
        const tsResult = this.runTypeScript(query, workspaceRoot, 'definition');
        if (tsResult.length > 0) return tsResult;
        // Fall back to tree-sitter for same-file definitions when TS
        // can't resolve (e.g. temp dirs without node_modules).
        return treeSitterProvider.findDefinition(query, workspaceRoot);
    }

    async findReferences(query: SymbolQuery, workspaceRoot: string): Promise<SymbolLocation[]> {
        if (!this.isSupported(query.filePath)) return [];
        // For references, workspace-wide search is more reliable than
        // ts.findAllReferences (which requires a full program with all
        // files). The agent needs "who uses this name?" — regex search
        // with word boundaries is precise enough for that question.
        try {
            const escaped = query.symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const result = await searchCode(workspaceRoot, `\\b${escaped}\\b`, undefined);
            const out: SymbolLocation[] = [];
            for (const hit of result.hits || []) {
                out.push({
                    filePath: hit.path,
                    line: hit.line,
                    column: 0,
                    provider: 'typescript',
                    confidence: 0.9,
                    kind: 'reference',
                });
            }
            return out;
        } catch {
            return [];
        }
    }

    private runTypeScript(query: SymbolQuery, workspaceRoot: string, mode: 'definition' | 'references'): SymbolLocation[] {
        try {
            const ts = require('typescript');
            const absPath = resolveWorkspacePath(workspaceRoot, query.filePath);

            const program = ts.createProgram({
                rootNames: [absPath],
                options: {
                    allowJs: true,
                    jsx: ts.JsxEmit.React,
                    noEmit: true,
                    skipLibCheck: true,
                    target: ts.ScriptTarget.ES2022,
                    module: ts.ModuleKind.CommonJS,
                    moduleResolution: ts.ModuleResolutionKind.NodeJs,
                },
                host: ts.createCompilerHost({}),
            });

            const sourceFile = program.getSourceFile(absPath);
            if (!sourceFile) return [];

            // Find the identifier position to search from
            const pos = this.findSymbolPosition(sourceFile, query.symbol, query.line);
            if (pos === -1) return [];

            const checker = program.getTypeChecker();
            const out: SymbolLocation[] = [];

            if (mode === 'definition') {
                const symbol = checker.getSymbolAtLocation(sourceFile as any, pos as any);
                if (!symbol) return [];

                const declarations = symbol.declarations || [];
                for (const decl of declarations) {
                    const declFile = decl.getSourceFile();
                    const declPath = declFile.fileName;
                    const relPath = path.relative(workspaceRoot, declPath).replace(/\\/g, '/');

                    const start = decl.getStart ? decl.getStart() : 0;
                    const lineChar = declFile.getLineAndCharacterOfPosition(start);
                    out.push({
                        filePath: relPath,
                        line: lineChar.line + 1,
                        column: lineChar.character + 1,
                        provider: 'typescript',
                        confidence: 1.0,
                        kind: 'definition',
                    });
                }
            } else {
                // References
                const symbol = checker.getSymbolAtLocation(sourceFile as any, pos as any);
                if (!symbol) return [];

                const refs = checker.findAllReferences(symbol) || [];
                for (const ref of refs) {
                    const refFile = ref.fileName;
                    const relPath = path.relative(workspaceRoot, refFile).replace(/\\/g, '/');
                    const lineChar = ts.getLineAndCharacterOfPosition(refFile, ref.textSpan.start);
                    if (!lineChar) continue;

                    out.push({
                        filePath: relPath,
                        line: lineChar.line + 1,
                        column: lineChar.character + 1,
                        provider: 'typescript',
                        confidence: 1.0,
                        kind: 'reference',
                    });
                }
            }

            return out;
        } catch {
            return [];
        }
    }

    private findSymbolPosition(sourceFile: any, symbol: string, hintLine?: number): number {
        let bestPos = -1;
        let bestDist = Infinity;

        const visit = (node: any) => {
            if (node.kind === 79 /* Identifier */ && node.text === symbol) {
                const line = sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
                const dist = hintLine ? Math.abs(line - hintLine) : 0;
                if (dist < bestDist) {
                    bestDist = dist;
                    bestPos = node.getStart();
                }
            }
            tsForEachChild(node, visit);
        };
        visit(sourceFile);

        return bestPos;
    }
}

function tsForEachChild(node: any, cb: (n: any) => void): void {
    if (node && typeof node.forEachChild === 'function') {
        node.forEachChild(cb);
    }
}

// ── Tree-sitter provider (Python + fallback) ──────────────────────────────

class TreeSitterProvider implements SymbolProvider {
    readonly name = 'tree-sitter';

    async findDefinition(query: SymbolQuery, workspaceRoot: string): Promise<SymbolLocation[]> {
        // For Python: search the file + its imports for the function definition
        const grammar = grammarForFile(query.filePath);
        if (grammar === 'unknown') return [];

        try {
            const absPath = resolveWorkspacePath(workspaceRoot, query.filePath);
            const content = fs.readFileSync(absPath, 'utf8');
            const parsed = await parseSource(content, grammar as any);
            if (!parsed) return [];

            const { root } = parsed;
            const imports = collectImports(root, content);

            // First: is the definition in THIS file?
            const localDef = this.findLocalDefinition(root, content, query.symbol);
            if (localDef) {
                return [{
                    filePath: query.filePath,
                    line: localDef.line,
                    column: localDef.column,
                    provider: 'tree-sitter',
                    confidence: 0.8,
                    kind: 'definition',
                }];
            }

            // Second: is it imported from another file?
            const importSource = imports.get(query.symbol);
            if (importSource) {
                const resolvedFile = this.resolveImport(importSource, query.filePath, workspaceRoot);
                if (resolvedFile) {
                    const resolvedContent = fs.readFileSync(resolvedFile, 'utf8');
                    const resolvedGrammar = grammarForFile(resolvedFile);
                    if (resolvedGrammar !== 'unknown') {
                        const resolvedParsed = await parseSource(resolvedContent, resolvedGrammar as any);
                        if (resolvedParsed) {
                            const defInImport = this.findLocalDefinition(resolvedParsed.root, resolvedContent, query.symbol);
                            if (defInImport) {
                                return [{
                                    filePath: path.relative(workspaceRoot, resolvedFile).replace(/\\/g, '/'),
                                    line: defInImport.line,
                                    column: defInImport.column,
                                    provider: 'tree-sitter',
                                    confidence: 0.7,
                                    kind: 'definition',
                                }];
                            }
                        }
                    }
                }
            }

            return [];
        } catch {
            return [];
        }
    }

    async findReferences(query: SymbolQuery, workspaceRoot: string): Promise<SymbolLocation[]> {
        // For Python: workspace-wide search for the symbol name
        try {
            const result = await searchCode(workspaceRoot, `\\b${query.symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, undefined);
            const out: SymbolLocation[] = [];
            for (const hit of result.hits || []) {
                out.push({
                    filePath: hit.path,
                    line: hit.line,
                    column: 0,
                    provider: 'tree-sitter',
                    confidence: 0.6,
                    kind: 'reference',
                });
            }
            return out;
        } catch {
            return [];
        }
    }

    private findLocalDefinition(root: any, source: string, name: string): { line: number; column: number } | null {
        const FUNCTION_TYPES = new Set([
            'function_declaration', 'function_definition', 'method_definition',
            'async_function_declaration', 'async_function_definition',
            'arrow_function', 'function_expression',
            'generator_function_declaration', 'generator_declaration',
            'class_definition', 'class_declaration',
        ]);

        for (const n of walk(root)) {
            if (!FUNCTION_TYPES.has(n.type)) continue;
            for (const child of n.namedChildren) {
                if (isIdentifier(child) || child.type === 'type_identifier') {
                    const text = source.slice(child.startIndex, child.endIndex);
                    if (text === name) {
                        return {
                            line: n.startPosition.row + 1,
                            column: n.startPosition.column + 1,
                        };
                    }
                }
            }
            // const name = () => {} — check parent
            const parent = n.parent;
            if (parent && (parent.type === 'lexical_declaration' || parent.type === 'variable_declaration')) {
                const decl = parent.namedChildren.find(c => c.type === 'variable_declarator');
                if (decl) {
                    const id = decl.child(0);
                    if (id && isIdentifier(id) && source.slice(id.startIndex, id.endIndex) === name) {
                        return {
                            line: parent.startPosition.row + 1,
                            column: parent.startPosition.column + 1,
                        };
                    }
                }
            }
        }
        return null;
    }

    private resolveImport(spec: string, fromFile: string, workspaceRoot: string): string | null {
        if (!spec.startsWith('.')) return null;
        const fromDir = path.dirname(path.resolve(workspaceRoot, fromFile));
        const base = path.resolve(fromDir, spec);
        const candidates = [
            base, base + '.ts', base + '.tsx', base + '.js', base + '.jsx',
            base + '.mjs', base + '.cjs', base + '.py',
            path.join(base, 'index.ts'), path.join(base, 'index.js'),
            path.join(base, '__init__.py'),
        ];
        for (const c of candidates) {
            if (fs.existsSync(c)) return c;
        }
        return null;
    }
}

// ── Provider registry ──────────────────────────────────────────────────────

const tsProvider = new TypeScriptProgramProvider();
const treeSitterProvider = new TreeSitterProvider();

function getProvider(filePath: string): SymbolProvider {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.ts' || ext === '.tsx' || ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') {
        return tsProvider;
    }
    return treeSitterProvider;
}

// ── Public API ──────────────────────────────────────────────────────────────

export async function findDefinition(
    workspaceRoot: string,
    filePath: string,
    symbol: string,
    line?: number,
): Promise<string> {
    try {
        resolveWorkspacePath(workspaceRoot, filePath);
    } catch (e: any) {
        return `Error: ${e.message}`;
    }

    const provider = getProvider(filePath);
    const locations = await provider.findDefinition({ filePath, symbol, line }, workspaceRoot);

    if (locations.length === 0) {
        return `No definition found for "${symbol}" in ${filePath}.`;
    }

    const lines = [`Definition of "${symbol}" (${locations.length} location(s)):`];
    for (const loc of locations) {
        const prov = loc.provider === 'typescript' ? 'ts' : 'ast';
        lines.push(`  ${loc.filePath}:${loc.line}:${loc.column} [${prov}, confidence ${loc.confidence}]`);
    }
    return lines.join('\n');
}

export async function findReferences(
    workspaceRoot: string,
    filePath: string,
    symbol: string,
    line?: number,
): Promise<string> {
    try {
        resolveWorkspacePath(workspaceRoot, filePath);
    } catch (e: any) {
        return `Error: ${e.message}`;
    }

    const provider = getProvider(filePath);
    const locations = await provider.findReferences({ filePath, symbol, line }, workspaceRoot);

    if (locations.length === 0) {
        return `No references found for "${symbol}" in ${filePath}.`;
    }

    const lines = [`References to "${symbol}" (${locations.length} location(s)):`];
    for (const loc of locations) {
        const prov = loc.provider === 'typescript' ? 'ts' : 'ast';
        lines.push(`  ${loc.filePath}:${loc.line} [${prov}, confidence ${loc.confidence}]`);
    }
    return lines.join('\n');
}
