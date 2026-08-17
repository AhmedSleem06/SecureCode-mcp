/**
 * Phase 4 Layer 1 — static extraction.
 *
 * Walks a parsed file once and produces one EndpointRecord per route
 * registration site, plus the cross-file context (middleware chain,
 * validators, params, auth, ORM, call graph, response shape).
 *
 * Four registration styles are recognised, because they are the four ways the
 * corpus of real projects actually declares routes:
 *
 *   - a call on a router object     `app.get('/x', handler)` / `@app.get('/x')`
 *   - a filesystem path             Next.js `app/api/x/route.ts` exporting GET
 *   - a URLconf table               Django `path('x/', views.x)`
 *
 * Everything that needs to look outside this file — which middleware the
 * router is mounted behind, what a middleware module actually checks, whether
 * an imported singleton is a Prisma client — arrives through the optional
 * `CrossFileContext`, which the cache builds (it owns the filesystem). Layer 1
 * itself stays a pure function of nodes and text.
 */

import { TreeSitterNode, nodeText } from './parserLoader';
import {
    baseIdentifier, callParts, collectImports, collectStringAssignments,
    firstAncestor, isIdentifier, isStringLiteral,
    resolveIdentifier, stringLiteralValue, walk,
} from './astHelpers';
import { CrossFileContext, DepFile, InheritedMiddleware, joinMountedPath } from './crossFile';
import { collectSchemas, SchemaDef, SCHEMA_VALIDATION_METHODS } from './schemas';
import {
    dataLayerBindings, DataLayerMatch, detectAuth, detectAuthInFunction,
    detectDataLayer, detectResponseShape,
    isDjangoRouteRegistration, isRouteRegistration, isUseRegistration,
    isWebSocketRegistration,
    normalizeMethod, RESPONSE_CONSTRUCTORS, toDataLayer,
} from './detectors';
import {
    AuthScheme, CallGraphNode, Confidence, DataLayer,
    EndpointParam, EndpointRecord, HttpMethod, MiddlewareEntry, ParamSource,
    ResponseShape, ValidatorLibrary, WebSocketHandler,
} from './types';

/** One global middleware registration: app.use(mw) or app.use('/path', mw). */
export interface GlobalMiddleware {
    name: string;
    registrationLine: number;
    /** Source file when imported, else same-file. */
    sourceFile: string;
    /** Whether the path arg was a string literal (router-scoped) or absent. */
    pathPrefix: string | null;
    confidence: number;
}

export interface Layer1Result {
    endpoints: EndpointRecord[];
    /** WebSocket handler registrations discovered in this file. */
    websockets: WebSocketHandler[];
    /** app.use(...) registrations in order (for the panel + cross-file stitch). */
    globalMiddleware: GlobalMiddleware[];
    imports: Record<string, string>;
}

type Framework = 'express' | 'fastapi' | 'nextjs' | 'django';

/** A handler body, which for Django lives in a different file than the route. */
interface HandlerBody {
    node: TreeSitterNode;
    source: string;
    file: string;
    imports: Map<string, string>;
    schemas: Map<string, SchemaDef>;
}

/** Everything known about a route before the shared per-endpoint pass runs. */
interface EndpointDraft {
    framework: Framework;
    method: HttpMethod;
    path: string;
    pathConfidence: number;
    /** 1-indexed registration line. */
    line: number;
    handlerName: string;
    handler: HandlerBody | null;
    middleware: MiddlewareEntry[];
    /** Middleware inherited from where this file's router is mounted. */
    inherited: InheritedMiddleware[];
    /** Params known from the registration site itself (path converters). */
    seedParams: EndpointParam[];
    /** Names of framework dependencies guarding the route (FastAPI `Depends`). */
    dependencies: string[];
    /** Decorators applied to the handler (Django method/auth decorators). */
    decorators: string[];
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/** Infer the ParamSource from a member like `req.body.x` / `req.query.y`. */
function paramSourceFromAccess(txt: string): ParamSource {
    if (/\bbody\b/.test(txt)) return 'body';
    if (/\bquery\b/.test(txt)) return 'query';
    if (/\bparams\b/.test(txt)) return 'path';
    if (/\bheaders?\b/.test(txt)) return 'header';
    if (/\bcookies?\b/.test(txt)) return 'cookie';
    return 'unknown';
}

/** Accessor forms that name their own parameter in a string argument. */
const NAMED_ACCESSORS: { re: RegExp; source: ParamSource }[] = [
    // Next.js: req.nextUrl.searchParams.get('q'), new URL(...).searchParams
    { re: /\bsearchParams\s*\.\s*get\(\s*['"`]([^'"`]+)['"`]/g, source: 'query' },
    // Django: request.GET.get("tag") / request.GET["tag"]
    { re: /\brequest\s*\.\s*GET\s*\.\s*get\(\s*['"]([^'"]+)['"]/g, source: 'query' },
    { re: /\brequest\s*\.\s*GET\s*\[\s*['"]([^'"]+)['"]\s*\]/g, source: 'query' },
    { re: /\brequest\s*\.\s*POST\s*\.\s*get\(\s*['"]([^'"]+)['"]/g, source: 'body' },
    { re: /\brequest\s*\.\s*POST\s*\[\s*['"]([^'"]+)['"]\s*\]/g, source: 'body' },
    // Express bracket access: req.query['page'], req.headers['x-api-key']
    { re: /\b(?:req|request)\s*\.\s*query\s*\[\s*['"]([^'"]+)['"]\s*\]/g, source: 'query' },
    { re: /\b(?:req|request)\s*\.\s*body\s*\[\s*['"]([^'"]+)['"]\s*\]/g, source: 'body' },
    { re: /\b(?:req|request)\s*\.\s*params\s*\[\s*['"]([^'"]+)['"]\s*\]/g, source: 'path' },
    { re: /\b(?:req|request)\s*\.\s*(?:headers|header)\s*\[\s*['"]([^'"]+)['"]\s*\]/g, source: 'header' },
];

/** Request objects a destructuring can pull a whole parameter bag out of. */
const DESTRUCTURE_SOURCE_RE = /^(?:req|request|ctx)\.(body|query|params|headers|cookies)$/;

/**
 * Extract the parameters an endpoint consumes.
 *
 * Reading `req.<source>.<name>` is only one of the ways a handler names its
 * inputs, and on real code it is the minority: bodies are commonly
 * destructured or declared entirely inside a validation schema, path params
 * arrive through a framework context object, and FastAPI declares everything
 * in the signature. All of those forms are collected here.
 */
function extractParams(
    handler: HandlerBody,
    seed: EndpointParam[],
    framework: Framework,
): EndpointParam[] {
    const out = new Map<string, EndpointParam>();
    const add = (p: EndpointParam) => {
        const existing = out.get(p.name);
        if (!existing) {
            out.set(p.name, p);
            return;
        }
        // A field covered by a schema is validated even if it is also read raw.
        if (!existing.validated && p.validated) {
            out.set(p.name, { ...existing, validated: true, validator: p.validator });
        }
    };
    for (const p of seed) add(p);

    const { node, source, schemas } = handler;
    const text = source.slice(node.startIndex, node.endIndex);

    // --- 1. member reads: req.body.x / req.params.id -----------------------
    for (const n of walk(node)) {
        if (n.type !== 'member_expression' && n.type !== 'attribute' && n.type !== 'subscript') continue;
        const txt = source.slice(n.startIndex, n.endIndex);
        const m = txt.match(/\b(req|request|ctx|c)\.(body|query|params|headers|header|cookies)\.(\w+)/i);
        if (!m) continue;
        add({
            name: m[3],
            type: 'unknown',
            source: paramSourceFromAccess(txt),
            validated: false,
            confidence: Confidence.STATIC_LITERAL,
        });
    }

    // --- 2. destructuring: const { qty } = req.body ------------------------
    for (const n of walk(node)) {
        if (n.type !== 'variable_declarator' && n.type !== 'assignment') continue;
        const target = n.child(0);
        const value = n.child(n.childCount - 1);
        if (!target || !value || target === value) continue;
        if (target.type !== 'object_pattern' && target.type !== 'object') continue;
        const valueText = source.slice(value.startIndex, value.endIndex).trim();
        const m = valueText.match(DESTRUCTURE_SOURCE_RE);
        if (!m) continue;
        const src = paramSourceFromAccess(m[1]);
        for (const name of patternBindings(target, source)) {
            add({
                name,
                type: 'unknown',
                source: src,
                validated: false,
                confidence: Confidence.STATIC_LITERAL,
            });
        }
    }

    // --- 3. accessors that name the parameter in a string ------------------
    for (const { re, source: src } of NAMED_ACCESSORS) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
            add({
                name: m[1],
                type: 'unknown',
                source: src,
                validated: false,
                confidence: Confidence.STATIC_LITERAL,
            });
        }
    }

    // --- 4. Python signature declarations ----------------------------------
    for (const p of signatureParameters(node)) {
        const txt = source.slice(p.startIndex, p.endIndex);
        const nameNode = p.child(0);
        if (!nameNode || !isIdentifier(nameNode)) continue;
        const name = source.slice(nameNode.startIndex, nameNode.endIndex);

        // A parameter annotated with a schema model IS the body: its fields,
        // not the parameter name, are what the request carries.
        const annotation = txt.split(':')[1]?.split('=')[0]?.trim();
        const model = annotation ? schemas.get(annotation) : undefined;
        if (model) {
            for (const field of model.fields) {
                add({
                    name: field,
                    type: 'unknown',
                    source: 'body',
                    validated: true,
                    validator: model.library,
                    confidence: Confidence.STATIC_LITERAL,
                });
            }
            continue;
        }

        let src: ParamSource = 'unknown';
        if (/\bPath\s*\(/.test(txt)) src = 'path';
        else if (/\bQuery\s*\(/.test(txt)) src = 'query';
        else if (/\bBody\s*\(/.test(txt)) src = 'body';
        else if (/\bHeader\s*\(/.test(txt)) src = 'header';
        else if (/\bCookie\s*\(/.test(txt)) src = 'cookie';
        if (src === 'unknown') continue;
        add({
            name,
            type: annotation || 'unknown',
            source: src,
            // FastAPI's Path()/Query()/Body() coerce and reject at the framework
            // level, which is validation even without a validator library.
            validated: true,
            validator: 'pydantic',
            confidence: Confidence.STATIC_LITERAL,
        });
    }

    // --- 5. schema validation calls: CreateUser.parse(req.body) ------------
    for (const n of walk(node)) {
        if (n.type !== 'call_expression' && n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p || !p.receiver) continue;
        if (!SCHEMA_VALIDATION_METHODS.has(p.method)) continue;
        const schema = schemas.get(p.receiver);
        if (!schema) continue;
        for (const field of schema.fields) {
            add({
                name: field,
                type: 'unknown',
                source: 'body',
                validated: true,
                validator: schema.library,
                confidence: Confidence.STATIC_LITERAL,
            });
        }
    }

    // Next.js path params arrive on the context object, which the folder name
    // already told us about; nothing further to read from the body.
    void framework;
    return [...out.values()];
}

/** Names bound by an object/array destructuring pattern. */
function patternBindings(pattern: TreeSitterNode, source: string): string[] {
    const names: string[] = [];
    for (const n of walk(pattern)) {
        if (n.type === 'shorthand_property_identifier_pattern'
            || n.type === 'shorthand_property_identifier') {
            names.push(source.slice(n.startIndex, n.endIndex));
            continue;
        }
        if (n.type === 'pair_pattern' || n.type === 'pair') {
            const value = n.namedChildren[n.namedChildren.length - 1];
            if (value && isIdentifier(value)) {
                names.push(source.slice(value.startIndex, value.endIndex));
            }
        }
    }
    return names;
}

/** The parameter nodes of a function definition, if it has a signature. */
function signatureParameters(fn: TreeSitterNode): TreeSitterNode[] {
    const params = fn.namedChildren.find(c =>
        c.type === 'parameters' || c.type === 'formal_parameters');
    if (!params) return [];
    return params.namedChildren.filter(p =>
        p.type === 'typed_parameter' || p.type === 'typed_default_parameter');
}

// ---------------------------------------------------------------------------
// Call graph
// ---------------------------------------------------------------------------

/** Receivers that build the response rather than doing work the handler cares about. */
const RESPONSE_RECEIVERS = new Set([
    'res', 'response', 'reply', 'ctx',
    'NextResponse', 'JsonResponse', 'HttpResponse', 'HttpResponseRedirect',
]);

/** Free functions that construct a response (Django `render`, Flask `jsonify`). */
const RESPONSE_BUILDERS = new Set(Object.keys(RESPONSE_CONSTRUCTORS));

/** Build the call graph for a handler: every function it calls. */
function extractCallGraph(
    handlerRoot: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
): CallGraphNode[] {
    const seen = new Set<string>();
    const out: CallGraphNode[] = [];
    // Framework declarations in the handler's own SIGNATURE — FastAPI's
    // `Depends()` / `Query()` / `Path()` / `Body()` — describe how the request
    // is bound, not work the handler does, and are already reflected in the
    // params and authScheme. Their span is captured up front because
    // tree-sitter hands back a fresh wrapper object on every `.parent` access,
    // so ancestors cannot be compared by identity.
    const signature = handlerRoot.namedChildren.find(c =>
        c.type === 'parameters' || c.type === 'formal_parameters');
    const inSignature = (n: TreeSitterNode) => Boolean(signature)
        && n.startIndex >= signature!.startIndex
        && n.endIndex <= signature!.endIndex;

    for (const n of walk(handlerRoot)) {
        if (n.type !== 'call_expression' && n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p) continue;
        // Skip res.json/send/etc. — those are response shape, not call graph.
        if (p.receiver && RESPONSE_RECEIVERS.has(p.receiver)) continue;
        if (!p.receiver && RESPONSE_BUILDERS.has(p.method)) continue;
        // Skip the framework's own registration methods (don't recurse into app.get).
        if (p.receiver === 'app' || p.receiver === 'router' || p.receiver === 'fastify' || p.receiver === 'server') continue;
        if (inSignature(n)) continue;
        const name = p.receiver ? `${p.receiver}.${p.method}` : p.method;
        if (seen.has(name)) continue;
        seen.add(name);
        const calleeFile = imports.get(p.receiver || p.method) || imports.get(p.method);
        // A call written out in the source always happens; the only thing the
        // import map adds is WHERE the callee is defined. Downgrading a call we
        // can see to 0.6 because we cannot name its file conflates "does this
        // call happen" with "which file defines it".
        out.push({
            name,
            calleeFile,
            callLine: p.line + 1,
            confidence: Confidence.STATIC_LITERAL,
        });
    }
    return out;
}

// ---------------------------------------------------------------------------
// Handler lookup
// ---------------------------------------------------------------------------

/** Get the name of a handler function node (or '<anonymous>'). */
function handlerNameOf(node: TreeSitterNode | null, source: string): string {
    if (!node) return '<anonymous>';
    // function foo() {}
    const id = node.namedChildren.find(c => isIdentifier(c));
    if (id) return source.slice(id.startIndex, id.endIndex);
    // const foo = (...) => {}
    const parent = node.parent;
    if (parent && (parent.type === 'lexical_declaration' || parent.type === 'variable_declaration' || parent.type === 'assignment_expression')) {
        const name = parent.child(0);
        if (name && isIdentifier(name)) return source.slice(name.startIndex, name.endIndex);
    }
    return '<anonymous>';
}

/** Locate a top-level (or nested) function declaration by name. */
export function findFunctionByName(root: TreeSitterNode, source: string, name: string): TreeSitterNode | null {
    for (const n of walk(root)) {
        if (n.type === 'function_declaration' || n.type === 'function_definition' || n.type === 'method_definition') {
            const id = n.namedChildren.find(c => isIdentifier(c));
            if (id && source.slice(id.startIndex, id.endIndex) === name) return n;
        }
        // const name = (...) => {}
        if (n.type === 'lexical_declaration' || n.type === 'variable_declaration') {
            for (const decl of n.namedChildren) {
                if (decl.type !== 'variable_declarator') continue;
                const declName = decl.child(0);
                if (declName && isIdentifier(declName) && source.slice(declName.startIndex, declName.endIndex) === name) {
                    const fnNode = decl.child(decl.childCount - 1);
                    if (fnNode && (fnNode.type === 'arrow_function' || fnNode.type === 'function_expression')) {
                        return fnNode;
                    }
                }
            }
        }
    }
    return null;
}

/**
 * The Python function a decorator is attached to, for `@app.get("/x")` route
 * decorators. Returns null for any other call node.
 */
function decoratedFunction(callNode: TreeSitterNode): TreeSitterNode | null {
    const decorator = callNode.parent;
    if (!decorator || decorator.type !== 'decorator') return null;
    const owner = decorator.parent;
    if (!owner || owner.type !== 'decorated_definition') return null;
    return owner.namedChildren.find(c =>
        c.type === 'function_definition' || c.type === 'async_function_definition') ?? null;
}

/** Decorator source text applied to a Python function definition. */
function decoratorsOf(fn: TreeSitterNode, source: string): string[] {
    const owner = fn.parent;
    if (!owner || owner.type !== 'decorated_definition') return [];
    return owner.namedChildren
        .filter(c => c.type === 'decorator')
        .map(c => source.slice(c.startIndex, c.endIndex));
}

// ---------------------------------------------------------------------------
// Route paths
// ---------------------------------------------------------------------------

/** A route path plus how much we trust it. */
export interface ResolvedPath {
    path: string;
    confidence: number;
}

/**
 * Resolve the first argument of a route registration to a path.
 *
 * A string literal is taken as written. A bare identifier is resolved against
 * the file's string assignments (`const BASE = '/v2'`) at intra-file-dataflow
 * confidence. A template literal with an interpolation is genuinely unknowable
 * statically, so it surfaces as '?' per the EndpointRecord contract rather
 * than causing the endpoint to be dropped.
 */
export function resolveRoutePath(
    node: TreeSitterNode | undefined,
    source: string,
    assignments: Map<string, string>,
): ResolvedPath {
    if (!node) return { path: '?', confidence: Confidence.UNRESOLVED };
    if (isStringLiteral(node)) {
        return { path: stringLiteralValue(node, source), confidence: Confidence.STATIC_LITERAL };
    }
    if (node.type === 'template_string' || node.type === 'template_literal') {
        const interpolated = node.namedChildren.some(c =>
            c.type === 'template_substitution' || c.type === 'template_expr');
        if (interpolated) return { path: '?', confidence: Confidence.UNRESOLVED };
        const raw = source.slice(node.startIndex, node.endIndex);
        return { path: raw.replace(/^`|`$/g, ''), confidence: Confidence.STATIC_LITERAL };
    }
    if (isIdentifier(node)) {
        const name = source.slice(node.startIndex, node.endIndex);
        const resolved = resolveIdentifier(name, assignments);
        return resolved === null
            ? { path: '?', confidence: Confidence.UNRESOLVED }
            : { path: resolved, confidence: Confidence.INTRA_FILE_DATAFLOW };
    }
    return { path: '?', confidence: Confidence.UNRESOLVED };
}

/**
 * Route path for a Next.js app-router file, derived from where the file sits.
 *
 * `app/api/products/[id]/route.ts` -> `/api/products/[id]`. Route groups
 * (`(marketing)`) and parallel-route slots (`@modal`) are organisational and
 * contribute nothing to the URL. Returns null when the file is not a route.
 */
export function nextAppRouterPath(file: string): string | null {
    const normalised = file.replace(/\\/g, '/');
    const appMatch = /(?:^|\/)app\/(.*\/)?route\.(?:t|j)sx?$/.exec(normalised);
    if (appMatch) {
        const segments = (appMatch[1] ?? '')
            .split('/')
            .filter(s => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
        return '/' + segments.join('/');
    }
    // Pages router: pages/api/orders/[id].ts -> /api/orders/[id]
    const pagesMatch = /(?:^|\/)pages\/(api\/.*)\.(?:t|j)sx?$/.exec(normalised);
    if (pagesMatch) {
        const segments = pagesMatch[1].split('/').filter(Boolean);
        const last = segments[segments.length - 1];
        if (last === 'index') segments.pop();
        return '/' + segments.join('/');
    }
    return null;
}

/** HTTP methods Next.js app-router files export as named functions. */
const NEXT_METHOD_EXPORTS = new Set<HttpMethod>([
    'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
]);

/** Path params declared by a route path, across the frameworks' syntaxes. */
function pathParams(routePath: string): EndpointParam[] {
    const out: EndpointParam[] = [];
    const push = (name: string, validated: boolean) => {
        if (!name || out.some(p => p.name === name)) return;
        out.push({
            name,
            type: 'unknown',
            source: 'path',
            validated,
            confidence: Confidence.STATIC_LITERAL,
        });
    };
    // Next.js: [id], [...slug], [[...slug]]
    for (const m of routePath.matchAll(/\[+\.{0,3}([^\]]+?)\]+/g)) push(m[1], false);
    // Django: <int:pk>, <slug>. A converter coerces and rejects, which is
    // validation performed by the framework rather than a validator library.
    for (const m of routePath.matchAll(/<(?:(\w+):)?(\w+)>/g)) push(m[2], Boolean(m[1]));
    return out;
}

// ---------------------------------------------------------------------------
// Cross-file resolution
// ---------------------------------------------------------------------------

/** True for a middleware expression we cannot resolve to anything at all. */
function isDynamicExpression(text: string): boolean {
    return /require\s*\(|process\.env|import\s*\(|os\.environ|getenv/.test(text);
}

/** Strip a trailing call so `cors()` and `express.json()` name something. */
function calleeBase(text: string): string {
    const trimmed = text.trim();
    const identifier = /^([A-Za-z_$][\w$]*)/.exec(trimmed);
    return identifier ? identifier[1] : trimmed;
}

/** Auth scheme implemented by a named middleware or dependency function. */
function authOfName(
    name: string,
    file: string,
    root: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
    ctx: CrossFileContext | undefined,
): AuthScheme {
    const base = calleeBase(name);
    const spec = imports.get(base);
    const dep = spec && ctx ? ctx.deps.get(spec) : undefined;
    if (dep) {
        const fn = findFunctionByName(dep.root, dep.source, base);
        if (fn) return detectAuthInFunction(fn, dep.source) as AuthScheme;
        return detectAuth(dep.imports, dep.root, dep.source) as AuthScheme;
    }
    const local = findFunctionByName(root, source, base);
    if (local) return detectAuthInFunction(local, source) as AuthScheme;
    void file;
    return 'none';
}

/** True iff a Next.js middleware matcher covers this route path. */
function matchesNextMatcher(routePath: string, matchers: string[]): boolean {
    for (const raw of matchers) {
        const prefix = raw.replace(/\/?:[\w]+\*?$/, '').replace(/\/?\(\.\*\)$/, '');
        if (prefix === raw) {
            if (routePath === raw) return true;
            continue;
        }
        if (routePath === prefix || routePath.startsWith(prefix + '/')) return true;
    }
    return false;
}

/** FastAPI `Depends(name)` references inside a node. */
function dependsNames(node: TreeSitterNode, source: string): string[] {
    const out: string[] = [];
    for (const n of walk(node)) {
        if (n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p || p.receiver !== null || p.method !== 'Depends') continue;
        const arg = p.args[0];
        if (!arg) continue;
        out.push(source.slice(arg.startIndex, arg.endIndex).trim());
    }
    return out;
}

/** Data layer this file uses, following one hop through a local re-export. */
function resolveDataLayer(
    imports: Map<string, string>,
    root: TreeSitterNode,
    source: string,
    ctx: CrossFileContext | undefined,
): { layer: DataLayerMatch; bindings: Set<string> } {
    const direct = detectDataLayer(imports);
    if (direct !== 'none') {
        return { layer: direct, bindings: dataLayerBindings(direct, imports, root, source) };
    }
    // A local module can be the data layer: `lib/prisma.ts` constructs the
    // client and re-exports it, so the route file never imports @prisma/client.
    if (!ctx) return { layer: 'none', bindings: new Set() };
    for (const [spec, dep] of ctx.deps) {
        const depLayer = detectDataLayer(dep.imports);
        if (depLayer === 'none') continue;
        const seed = [...imports.entries()]
            .filter(([, s]) => s === spec)
            .map(([local]) => local);
        if (seed.length === 0) continue;
        return {
            layer: depLayer,
            bindings: dataLayerBindings(depLayer, imports, root, source, seed),
        };
    }
    return { layer: 'none', bindings: new Set() };
}

/** True iff this handler actually touches the data layer the file provides. */
function usesDataLayer(handlerText: string, layer: DataLayerMatch, bindings: Set<string>): boolean {
    if (layer === 'none') return false;
    if (layer === 'django-orm' && /\.objects\./.test(handlerText)) return true;
    for (const b of bindings) {
        if (new RegExp(`\\b${b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(handlerText)) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/**
 * Extract all endpoints + global middleware from a parsed file.
 *
 * @param file     workspace-relative file path
 * @param source   file source text
 * @param root     parsed Tree-sitter root node
 * @param ctx      cross-file facts, when the caller could resolve them
 * @returns Layer1Result (endpoints, global middleware, imports)
 */
export function extractLayer1(
    file: string,
    source: string,
    root: TreeSitterNode,
    ctx?: CrossFileContext,
): Layer1Result {
    const assignments = collectStringAssignments(root, source);
    const imports = collectImports(root, source);
    const schemas = collectSchemas(root, source, imports);
    const fileAuth = detectAuth(imports, root, source) as AuthScheme;
    const data = resolveDataLayer(imports, root, source, ctx);

    const endpoints: EndpointRecord[] = [];
    const websockets: WebSocketHandler[] = [];
    const globalMiddleware: GlobalMiddleware[] = [];
    const drafts: EndpointDraft[] = [];

    // Pass 0: collect WebSocket handler registrations (ws.on('message', h), io.on('connection', h), ...).
    // Runs before the HTTP passes so that a file with no routes still yields a
    // useful map entry for real-time / WebSocket-only projects.
    for (const n of walk(root)) {
        const ws = isWebSocketRegistration(n, source);
        if (!ws) continue;
        const handlerName = ws.handler
            ? (isIdentifier(ws.handler)
                ? source.slice(ws.handler.startIndex, ws.handler.endIndex)
                : handlerNameOf(ws.handler, source))
            : '<anonymous>';
        websockets.push({
            id: `${file}:${ws.line + 1}:${ws.event}`,
            event: ws.event,
            handlerName,
            sourceFile: file,
            line: ws.line + 1,
            receiver: ws.receiver,
            confidence: Confidence.STATIC_LITERAL,
        });
    }

    // Pass 1: collect app.use(...) global middleware registrations in order.
    for (const n of walk(root)) {
        const use = isUseRegistration(n, source);
        if (!use) continue;
        // app.use('/api', auth)  ->  pathPrefix='/api', mw=auth
        // app.use(cors)         ->  pathPrefix=null, mw=cors
        let pathPrefix: string | null = null;
        let mwIndex = 0;
        if (use.args.length >= 2 && isStringLiteral(use.args[0])) {
            pathPrefix = stringLiteralValue(use.args[0], source);
            mwIndex = 1;
        }
        for (let i = mwIndex; i < use.args.length; i++) {
            const arg = use.args[i];
            const rawName = isIdentifier(arg) ? source.slice(arg.startIndex, arg.endIndex) : nodeText(arg, source);
            const name = calleeBase(rawName);
            // `app.use(cors())` registers the result of calling an import, so
            // the import has to be looked up under the callee's name.
            const importedFrom = imports.get(name) ?? imports.get(calleeBase(name));
            globalMiddleware.push({
                name,
                registrationLine: use.line + 1,
                sourceFile: importedFrom ?? file,
                pathPrefix,
                confidence: importedFrom ? Confidence.STATIC_LITERAL : Confidence.INTRA_FILE_DATAFLOW,
            });
        }
    }

    // Router-level FastAPI dependencies: APIRouter(dependencies=[Depends(x)])
    // applies to every route registered on that router.
    const routerDependencies = new Map<string, string[]>();
    for (const n of walk(root)) {
        if (n.type !== 'variable_declarator' && n.type !== 'assignment') continue;
        const target = n.child(0);
        const value = n.child(n.childCount - 1);
        if (!target || !value || target === value || !isIdentifier(target)) continue;
        if (value.type !== 'call' && value.type !== 'call_expression') continue;
        const p = callParts(value, source);
        if (!p || (p.method !== 'APIRouter' && p.method !== 'FastAPI')) continue;
        routerDependencies.set(
            source.slice(target.startIndex, target.endIndex),
            dependsNames(value, source),
        );
    }

    // Pass 2: router-object route registrations (Express/Fastify/Koa/FastAPI).
    for (const n of walk(root)) {
        const route = isRouteRegistration(n, source);
        if (!route) continue;
        const resolved = resolveRoutePath(route.args[0], source, assignments);

        // A Python decorator route (`@app.get("/x")`) carries only route
        // configuration in its arguments; the handler is the function the
        // decorator is attached to. Reading the last argument as the handler
        // there picks up the path string and binds nothing.
        const decoratedFn = decoratedFunction(n);
        const handlerNode = route.args[route.args.length - 1];
        const routeMiddlewareNodes = decoratedFn ? [] : route.args.slice(1, route.args.length - 1);

        let handlerFn: TreeSitterNode | null = decoratedFn;
        if (!handlerFn && handlerNode && isIdentifier(handlerNode)) {
            handlerFn = findFunctionByName(root, source, source.slice(handlerNode.startIndex, handlerNode.endIndex));
        } else if (!handlerFn && handlerNode && (handlerNode.type === 'arrow_function' || handlerNode.type === 'function_expression')) {
            handlerFn = handlerNode;
        }
        const handlerName = decoratedFn
            ? handlerNameOf(decoratedFn, source)
            : (handlerNode && isIdentifier(handlerNode)
                ? source.slice(handlerNode.startIndex, handlerNode.endIndex)
                : handlerNameOf(handlerFn, source));

        const middleware: MiddlewareEntry[] = [];
        for (const g of globalMiddleware) {
            if (g.pathPrefix === null || resolved.path === '?' || resolved.path.startsWith(g.pathPrefix)) {
                middleware.push({
                    name: g.name,
                    sourceFile: g.sourceFile,
                    registrationLine: g.registrationLine,
                    confidence: g.confidence,
                });
            }
        }
        for (const mwn of routeMiddlewareNodes) {
            const name = isIdentifier(mwn) ? source.slice(mwn.startIndex, mwn.endIndex) : nodeText(mwn, source);
            const importedFrom = imports.get(name) ?? imports.get(calleeBase(name));
            middleware.push({
                name,
                sourceFile: importedFrom ?? file,
                registrationLine: route.line + 1,
                confidence: importedFrom ? Confidence.STATIC_LITERAL : Confidence.INTRA_FILE_DATAFLOW,
            });
        }

        const dependencies = [
            ...(route.receiver ? routerDependencies.get(route.receiver) ?? [] : []),
            ...(decoratedFn ? dependsNames(decoratedFn, source) : []),
        ];

        drafts.push({
            framework: decoratedFn ? 'fastapi' : 'express',
            method: normalizeMethod(route.method),
            path: resolved.path,
            pathConfidence: resolved.confidence,
            line: route.line + 1,
            handlerName,
            handler: handlerFn ? { node: handlerFn, source, file, imports, schemas } : null,
            middleware,
            inherited: ctx?.inherited ?? [],
            seedParams: [],
            dependencies,
            decorators: decoratedFn ? decoratorsOf(decoratedFn, source) : [],
        });
    }

    // Pass 3: Next.js app router — method and path come from the filesystem,
    // so there is no registration call to find.
    const nextPath = nextAppRouterPath(file);
    if (nextPath !== null) {
        for (const n of walk(root)) {
            if (n.type !== 'function_declaration' && n.type !== 'generator_function_declaration') continue;
            const id = n.namedChildren.find(c => isIdentifier(c));
            if (!id) continue;
            const name = source.slice(id.startIndex, id.endIndex) as HttpMethod;
            if (!NEXT_METHOD_EXPORTS.has(name)) continue;
            if (!firstAncestor(n, a => a.type === 'export_statement')) continue;
            drafts.push({
                framework: 'nextjs',
                method: name,
                path: nextPath,
                pathConfidence: Confidence.STATIC_LITERAL,
                line: n.startPosition.row + 1,
                handlerName: name,
                handler: { node: n, source, file, imports, schemas },
                middleware: [],
                inherited: ctx?.inherited ?? [],
                seedParams: pathParams(nextPath),
                dependencies: [],
                decorators: [],
            });
        }
    }

    // Pass 4: Django URLconf. The registration site says nothing about the
    // method, the params or the response — all of that lives in the view.
    for (const n of walk(root)) {
        const entry = isDjangoRouteRegistration(n, source);
        if (!entry) continue;
        const routePath = stringLiteralValue(entry.path, source);
        const view = entry.view ? resolveDjangoView(entry.view, source, root, imports, ctx) : null;
        drafts.push({
            framework: 'django',
            method: view ? djangoMethod(view.decorators) : 'GET',
            path: routePath,
            pathConfidence: Confidence.STATIC_LITERAL,
            line: entry.line + 1,
            handlerName: view?.name ?? '<anonymous>',
            handler: view?.handler ?? null,
            middleware: [],
            inherited: ctx?.inherited ?? [],
            seedParams: pathParams(routePath),
            dependencies: [],
            decorators: view?.decorators ?? [],
        });
    }

    // Shared per-endpoint pass.
    for (const d of drafts) {
        endpoints.push(buildEndpoint(d, file, root, source, imports, fileAuth, data, ctx));
    }

    return {
        endpoints,
        websockets,
        globalMiddleware,
        imports: Object.fromEntries(imports),
    };
}

/** Resolve `views.article_list` in a URLconf to the view function's body. */
function resolveDjangoView(
    node: TreeSitterNode,
    source: string,
    root: TreeSitterNode,
    imports: Map<string, string>,
    ctx: CrossFileContext | undefined,
): { name: string; handler: HandlerBody | null; decorators: string[] } | null {
    const text = source.slice(node.startIndex, node.endIndex).trim();
    const segments = text.split('.');
    const name = segments[segments.length - 1];
    const moduleAlias = segments.length > 1 ? segments[0] : name;

    const spec = imports.get(moduleAlias) ?? imports.get(name);
    const dep = spec && ctx ? ctx.deps.get(spec) : undefined;
    if (dep) {
        const fn = findFunctionByName(dep.root, dep.source, name);
        if (fn) {
            return {
                name,
                handler: {
                    node: fn,
                    source: dep.source,
                    file: dep.file,
                    imports: dep.imports,
                    schemas: collectSchemas(dep.root, dep.source, dep.imports),
                },
                decorators: decoratorsOf(fn, dep.source),
            };
        }
    }
    const local = findFunctionByName(root, source, name);
    if (local) {
        return {
            name,
            handler: { node: local, source, file: '', imports, schemas: new Map() },
            decorators: decoratorsOf(local, source),
        };
    }
    return { name, handler: null, decorators: [] };
}

/** HTTP method a Django view is restricted to by its decorators. */
function djangoMethod(decorators: string[]): HttpMethod {
    for (const d of decorators) {
        if (/@require_POST\b/.test(d)) return 'POST';
        if (/@require_GET\b/.test(d)) return 'GET';
        if (/@require_safe\b/.test(d)) return 'GET';
        const m = /@require_http_methods\(\s*\[([^\]]*)\]/.exec(d);
        if (m) {
            const methods = [...m[1].matchAll(/['"](\w+)['"]/g)].map(x => x[1].toUpperCase());
            if (methods.length === 1) return methods[0] as HttpMethod;
            if (methods.length > 1) return 'ALL';
        }
    }
    return 'GET';
}

/** Auth a Django view's decorators establish. */
function djangoDecoratorAuth(decorators: string[]): AuthScheme {
    for (const d of decorators) {
        if (/@login_required|@permission_required|@staff_member_required|@user_passes_test/.test(d)) {
            return 'session';
        }
    }
    return 'none';
}

/** Turn a draft into the finished record: params, calls, auth, ORM, confidence. */
function buildEndpoint(
    d: EndpointDraft,
    file: string,
    root: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
    fileAuth: AuthScheme,
    data: { layer: DataLayerMatch; bindings: Set<string> },
    ctx: CrossFileContext | undefined,
): EndpointRecord {
    const middleware: MiddlewareEntry[] = [
        ...d.inherited.map(m => ({
            name: m.name,
            sourceFile: m.sourceFile,
            registrationLine: m.registrationLine,
            confidence: m.confidence,
        })),
        ...d.middleware,
    ];

    let params: EndpointParam[] = d.seedParams;
    let callGraph: CallGraphNode[] = [];
    let responseShape: ResponseShape = 'unknown';
    let dataLayer: DataLayer = 'none';

    if (d.handler) {
        params = extractParams(d.handler, d.seedParams, d.framework);
        callGraph = extractCallGraph(d.handler.node, d.handler.source, d.handler.imports);
        responseShape = detectResponseShape(d.handler.node, d.handler.source);

        const handlerText = d.handler.source.slice(d.handler.node.startIndex, d.handler.node.endIndex);
        // Django's route file and view file are different files, so the data
        // layer has to be judged from whichever file the body lives in.
        const scope = d.handler.file && d.handler.file !== file
            ? resolveDataLayer(d.handler.imports, d.handler.node, d.handler.source, undefined)
            : data;
        if (usesDataLayer(handlerText, scope.layer, scope.bindings)) {
            dataLayer = toDataLayer(scope.layer);
        }
    }

    // FastAPI serialises whatever the handler returns, so a handler that never
    // touches a response object still answers with JSON.
    if (responseShape === 'unknown' && d.framework === 'fastapi') responseShape = 'json';

    // The validator that covers THIS endpoint is the one its params went
    // through — a sibling route's zod import says nothing about this route.
    const validated = params.find(p => p.validator);
    const validatorLibrary: ValidatorLibrary = validated?.validator ?? 'none';

    const authScheme = resolveAuth(d, middleware, file, root, source, imports, fileAuth, ctx);

    const allConfs = [
        d.pathConfidence,
        ...middleware.map(m => m.confidence),
        ...params.map(p => p.confidence),
        ...callGraph.map(c => c.confidence),
    ];

    const mounted = ctx?.mountPrefix ? joinMountedPath(ctx.mountPrefix, d.path) : undefined;

    return {
        id: `${file}:${d.line}:${d.method}:${d.path}`,
        method: d.method,
        path: d.path,
        mountedPath: mounted && mounted !== d.path ? mounted : undefined,
        handlerName: d.handlerName,
        sourceFile: file,
        line: d.line,
        middleware,
        params,
        authScheme,
        dataLayer,
        validatorLibrary,
        callGraph,
        responseShape,
        pathConfidence: d.pathConfidence,
        confidence: Math.min(...allConfs),
        runtimeConfirmed: false,
    };
}

/**
 * Which auth scheme actually guards this endpoint.
 *
 * Answered from the guards themselves — the middleware chain (including the
 * chain inherited from wherever the router is mounted), framework
 * dependencies, and decorators — rather than from what the file imports. A
 * router file behind `app.use('/api', requireAuth)` imports nothing
 * auth-related and is still authenticated; a file that imports `jsonwebtoken`
 * for one route does not thereby protect the others.
 */
function resolveAuth(
    d: EndpointDraft,
    middleware: MiddlewareEntry[],
    file: string,
    root: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
    fileAuth: AuthScheme,
    ctx: CrossFileContext | undefined,
): AuthScheme {
    // Next.js edge middleware guards by URL pattern, not by import.
    if (ctx?.nextMiddleware && matchesNextMatcher(d.path, ctx.nextMiddleware.matchers)) {
        return ctx.nextMiddleware.auth;
    }
    const fromDecorator = djangoDecoratorAuth(d.decorators);
    if (fromDecorator !== 'none') return fromDecorator;

    for (const dep of d.dependencies) {
        const scheme = authOfName(dep, file, root, source, imports, ctx);
        if (scheme !== 'none') return scheme;
    }

    let sawDynamic = false;
    for (const m of d.inherited) {
        if (m.dynamic) { sawDynamic = true; continue; }
        if (m.auth !== 'none') return m.auth;
    }
    for (const m of middleware) {
        if (isDynamicExpression(m.name)) { sawDynamic = true; continue; }
        const scheme = authOfName(m.name, file, root, source, imports, ctx);
        if (scheme !== 'none') return scheme;
    }
    // A guard we could not resolve at all is not the same as no guard.
    if (sawDynamic) return 'unknown';

    return fileAuth;
}
