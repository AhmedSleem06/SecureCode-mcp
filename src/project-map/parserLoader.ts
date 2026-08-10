/**
 * Phase 4 — web-tree-sitter loader + WASM grammar resolver.
 *
 * web-tree-sitter ships a Node ESM/CJS entry plus language WASM blobs.
 * In a VS Code extension the compiled JS runs from dist/, so the WASM
 * files MUST be co-located somewhere we can resolve at runtime. We bundle
 * the grammars under `resources/tree-sitter/` (see
 * `resources/tree-sitter/README.md` for the vendoring recipe) and resolve
 * them with an absolute path computed from the extension install dir.
 *
 * Loading is lazy and memoized: grammars are ~1-3 MB each and we only
 * need the one matching the file being parsed.
 */

import * as fs from 'fs';
import * as path from 'path';

// web-tree-sitter's published types are loose; load at runtime and cast.
// We intentionally do NOT add a @types/web-tree-sitter dependency so the
// extension keeps compiling without an extra devDep install — the small
// surface we use is declared inline below.
type TreeSitter = {
    Language: {
        load(filePath: string): Promise<unknown>;
    };
    Parser: (new () => TreeSitterParser) & {
        /** Static initializer in web-tree-sitter >= 0.26. */
        init?: () => Promise<void>;
        /** Language namespace on the legacy (<= 0.25) export shape. */
        Language?: { load(filePath: string): Promise<unknown> };
    };
    /** Module-level initializer in web-tree-sitter <= 0.25. */
    init?: () => Promise<void>;
};
type TreeSitterParser = {
    setLanguage(language: unknown): void;
    parse(source: string): TreeSitterTree;
    delete(): void;
};
type TreeSitterTree = {
    /** Property in >= 0.26; the legacy API exposed getRootNode(). */
    rootNode?: TreeSitterNode;
    getRootNode?: () => TreeSitterNode;
    delete(): void;
};
export type TreeSitterNode = {
    type: string;
    startIndex: number;
    endIndex: number;
    startPosition: { row: number; column: number };
    endPosition: { row: number; column: number };
    text?: string;
    childCount: number;
    child(i: number): TreeSitterNode;
    namedChildren: TreeSitterNode[];
    children: TreeSitterNode[];
    parent?: TreeSitterNode | null;
};

let _tsPromise: Promise<TreeSitter> | null = null;
const _languageCache = new Map<string, Promise<unknown>>();
let _parserCache: TreeSitterParser | null = null;

/**
 * Locate the directory holding the bundled WASM grammars.
 *
 * Standalone MCP: resolve from the package root (dist/project-map -> ../../resources/tree-sitter).
 * Override with SECURECODE_GRAMMAR_DIR for custom installs.
 */
function grammarDir(): string {
    if (process.env.SECURECODE_GRAMMAR_DIR) {
        return process.env.SECURECODE_GRAMMAR_DIR;
    }
    // __dirname when compiled is <pkg>/dist/project-map. Two levels up.
    const here = __dirname;
    const pkgRoot = path.resolve(here, '..', '..');
    return path.join(pkgRoot, 'resources', 'tree-sitter');
}

/**
 * Lazy-load and initialise web-tree-sitter (Node CJS entry).
 *
 * The WASM runtime MUST be initialised before any Language.load() call. The
 * initialiser moved between versions: >= 0.26 exposes a static `Parser.init()`,
 * while <= 0.25 exposed a module-level `init()`. We try both, in that order.
 * Getting this wrong is silent — Language.load() rejects and the Project Map
 * degrades to producing nothing — so both shapes are handled explicitly.
 */
function loadTreeSitter(): Promise<TreeSitter> {
    if (_tsPromise) return _tsPromise;
    _tsPromise = (async () => {
        // web-tree-sitter's package "main" is the CJS bundle that works in Node.
        const mod = require('web-tree-sitter') as TreeSitter;
        if (typeof mod.Parser?.init === 'function') {
            await mod.Parser.init();
        } else if (typeof mod.init === 'function') {
            await mod.init();
        }
        return mod;
    })();
    return _tsPromise;
}

/** Resolve the Language namespace across both export shapes. */
function languageNamespace(ts: TreeSitter): { load(filePath: string): Promise<unknown> } {
    const ns = ts.Language ?? ts.Parser?.Language;
    if (!ns || typeof ns.load !== 'function') {
        throw new Error('SecureCode: web-tree-sitter exposes no Language.load()');
    }
    return ns;
}

/**
 * Load a language grammar by short name. Memoized per language.
 * Throws if the WASM file is missing — callers should catch and degrade
 * gracefully (the Project Map is best-effort; a missing grammar must never
 * break a scan).
 */
export function loadLanguage(name: 'javascript' | 'typescript' | 'tsx' | 'python'): Promise<unknown> {
    if (_languageCache.has(name)) return _languageCache.get(name)!;
    const p = (async () => {
        const ts = await loadTreeSitter();
        const file = path.join(grammarDir(), `tree-sitter-${name}.wasm`);
        if (!fs.existsSync(file)) {
            throw new Error(`SecureCode: tree-sitter grammar missing: ${file}`);
        }
        return languageNamespace(ts).load(file);
    })();
    _languageCache.set(name, p);
    return p;
}

/**
 * Parse source code with a grammar. Returns the root node or null when the
 * grammar is unavailable (best-effort: callers must handle null).
 */
export async function parseSource(
    source: string,
    language: 'javascript' | 'typescript' | 'tsx' | 'python',
): Promise<{ tree: TreeSitterTree; root: TreeSitterNode } | null> {
    try {
        const ts = await loadTreeSitter();
        const lang = await loadLanguage(language);
        if (!_parserCache) {
            _parserCache = new ts.Parser();
        }
        const parser = _parserCache;
        parser.setLanguage(lang);
        const tree = parser.parse(source);
        // >= 0.26 exposes `rootNode` as a property; <= 0.25 had getRootNode().
        const root = tree.rootNode ?? tree.getRootNode?.();
        if (!root) {
            throw new Error('SecureCode: tree-sitter returned no root node');
        }
        return { tree, root };
    } catch (err) {
        // Best-effort: never let a parser failure kill the scan.
        console.warn('SecureCode: tree-sitter parse failed:', err);
        return null;
    }
}

/**
 * Convenience: extract the source text for a node using the original source
 * string. Tree-sitter nodes don't always carry .text (depends on version).
 */
export function nodeText(node: TreeSitterNode, source: string): string {
    if (node.text !== undefined) return node.text;
    return source.slice(node.startIndex, node.endIndex);
}

/** Pick a grammar for a file path. */
export function grammarForFile(
    filePath: string,
): 'javascript' | 'typescript' | 'tsx' | 'python' | 'unknown' {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.ts') return 'typescript';
    if (ext === '.tsx') return 'tsx';
    if (ext === '.py') return 'python';
    if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') return 'javascript';
    return 'unknown';
}
