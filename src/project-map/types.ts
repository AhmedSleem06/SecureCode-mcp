/**
 * Phase 4 Project Map — shared types.
 *
 * The Project Map is a local, Tree-sitter-derived model of every HTTP
 * endpoint in the workspace plus the cross-file context that protects it
 * (middleware chain, validators, auth, ORM/data layer). It is what lets the
 * Juror reason about whether a route is actually defended, and what lets
 * the Attacker build endpoint-specific scenarios instead of generic ones.
 *
 * Nothing here ever leaves the machine: only the derived `EndpointContext`
 * for the file under scan is attached to the scan payload, and that is the
 * ONLY new field the API contract gains (optional; ignored by today's API).
 */

/** HTTP method, uppercased. */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'ALL';

/** Where a parameter lives on the request. */
export type ParamSource = 'body' | 'query' | 'path' | 'header' | 'cookie' | 'unknown';

/** Auth scheme detected for an endpoint. */
export type AuthScheme =
    | 'jwt'           // passport-jwt / jsonwebtoken verify, fastapi jwt
    | 'session'       // express-session / cookie-session / django sessions
    | 'api-key'       // x-api-key / Authorization: ApiKey / fastapi Depends api_key
    | 'oauth'         // passport-google / authlib
    | 'basic'         // passport-http / httpbasic
    | 'none'          // nothing detected
    | 'unknown';

/** ORM / data layer detected for an endpoint. */
export type DataLayer =
    | 'prisma'
    | 'typeorm'
    | 'sequelize'
    | 'knex'
    | 'mongoose'
    | 'raw-sql'
    | 'supabase'      // supabase-js / PostgREST — a data layer with no ORM
    | 'sqlalchemy'
    | 'django-orm'
    | 'none'
    | 'unknown';

/** Validator library detected for a parameter or handler. */
export type ValidatorLibrary =
    | 'zod'
    | 'joi'
    | 'express-validator'
    | 'yup'
    | 'ajv'
    | 'pydantic'
    | 'marshmallow'
    | 'none'
    | 'unknown';

/** Response shape detected for an endpoint. */
export type ResponseShape = 'json' | 'html' | 'redirect' | 'stream' | 'file' | 'text' | 'unknown';

/**
 * Confidence scores per the README Phase 4 spec.
 *
 * 1.0  — static literal (string-literal path, directly-registered middleware)
 * 0.8  — runtime-confirmed (trace hook observed the relationship)
 * 0.6  — intra-file dataflow (resolved from a same-file const/variable)
 * 0.2  — unresolved (could not statically resolve; not yet traced)
 * 0.15 — meta-programming (new Function / vm.runIn* / dynamic require)
 * 0.1  — fully unresolved, no usable evidence
 * 0.0  — dynamic import pattern (D1-D10), flagged but un-confirmed
 */
export const Confidence = {
    STATIC_LITERAL: 1.0,
    RUNTIME_CONFIRMED: 0.8,
    INTRA_FILE_DATAFLOW: 0.6,
    UNRESOLVED: 0.2,
    META_PROGRAMMING: 0.15,
    FULLY_UNRESOLVED: 0.1,
    DYNAMIC_PATTERN: 0.0,
} as const;

/** A single parameter on an endpoint. */
export interface EndpointParam {
    name: string;
    /** Best-effort type annotation as a string ('string', 'number', 'User', 'unknown'). */
    type: string;
    source: ParamSource;
    /** True iff a validator call covers this param. */
    validated: boolean;
    /** Which validator library was detected, when validated. */
    validator?: ValidatorLibrary;
    /** Confidence that this param actually exists at this source. */
    confidence: number;
}

/** A middleware entry in an endpoint's chain (registration order). */
export interface MiddlewareEntry {
    /** Local name of the middleware function or import. */
    name: string;
    /** File where the middleware is defined or imported (workspace-relative). */
    sourceFile: string;
    /** Line where it was registered (app.use(...) or app.get('/', mw, handler)). */
    registrationLine: number;
    /** Confidence that this middleware actually applies to this endpoint. */
    confidence: number;
}

/** One node in the handler's call graph (a function the handler invokes). */
export interface CallGraphNode {
    /** Local name of the called function. */
    name: string;
    /** File where the called function is defined, when resolvable. */
    calleeFile?: string;
    /** Line of the call site. */
    callLine: number;
    /** Confidence that this call actually happens. */
    confidence: number;
}

/**
 * The full per-endpoint record — one of these is produced for every
 * `app.get('/x', handler)` / `@app.get('/x')` / `@router.get('/x')` /
 * `@app.route('/x')` / Fastify `.get('/x', handler)` / Koa `router.get(...)`
 * / FastAPI `@app.get('/x')` / Django `path('x', view)` site discovered.
 */
export interface EndpointRecord {
    /** Stable id: `${file}:${line}:${method}:${path}`. */
    id: string;
    method: HttpMethod;
    /**
     * Route path AS REGISTERED at the route site (string literal when
     * available; '?' when dynamic). For a router mounted under a prefix in
     * another file this stays router-local — see `mountedPath`.
     */
    path: string;
    /**
     * Full externally-visible path, when the router carrying this route is
     * mounted under a prefix somewhere else (`/api/users` + `/:id`).
     *
     * Kept alongside `path` rather than replacing it: consumers key off the
     * as-registered path to line up with the source, while an attacker or a
     * trace needs the URL that is actually reachable. Absent when the router
     * is not mounted anywhere we can see.
     */
    mountedPath?: string;
    /** Handler function local name (or '<anonymous>'). */
    handlerName: string;
    /** Workspace-relative source file of the handler. */
    sourceFile: string;
    /** 1-indexed line of the handler registration / decorator. */
    line: number;
    /** Middleware chain in registration order (global app.use first, then route mw). */
    middleware: MiddlewareEntry[];
    /** Parameters extracted from the handler signature + validators. */
    params: EndpointParam[];
    authScheme: AuthScheme;
    dataLayer: DataLayer;
    validatorLibrary: ValidatorLibrary;
    callGraph: CallGraphNode[];
    responseShape: ResponseShape;
    /**
     * Confidence that `path` is the path this endpoint is really registered
     * at: 1.0 for a string literal or a filesystem-derived route, 0.6 when it
     * came from a same-file constant, UNRESOLVED when it is '?'.
     *
     * Kept separate from `confidence` because it is the one piece of evidence
     * that exists even for an endpoint with no middleware, params or calls —
     * without it such a record would be indistinguishable from one where
     * nothing at all could be extracted.
     */
    pathConfidence?: number;
    /** Aggregate confidence for the whole record (min of relationship confidences). */
    confidence: number;
    /** True iff a runtime trace confirmed this endpoint exists and was hit. */
    runtimeConfirmed: boolean;
}

/** Layer 2 dynamic import pattern type (D1-D10). */
export type DynamicPatternType =
    | 'D1'  // require(variable)
    | 'D2'  // dynamic import() with variable
    | 'D3'  // template-literal import / require
    | 'D4'  // config-driven middleware (app.use(process.env.X))
    | 'D5'  // proxy loader (require('loader')(name))
    | 'D6'  // new Function(...)
    | 'D7'  // vm.runIn*
    | 'D8'  // conditional require (if (x) require('a') else require('b'))
    | 'D9'  // eval-driven module resolution
    | 'D10'; // wildcard / glob-driven loader

/** A single dynamic import / meta-programming detection. */
export interface DynamicPattern {
    type: DynamicPatternType;
    file: string;
    line: number;
    /** Short code snippet for surfacing in the panel. */
    snippet: string;
    /** Initial confidence — always 0.0 per spec. */
    confidence: number;
}

/** Per-file extraction output. */
export interface FileExtraction {
    file: string;
    language: 'javascript' | 'typescript' | 'tsx' | 'python' | 'unknown';
    endpoints: EndpointRecord[];
    dynamicPatterns: DynamicPattern[];
    /** Imports resolved for cross-file use: name -> sourceFile (workspace-relative). */
    imports: Record<string, string>;
    /** mtimes/hash used by the cache. */
    mtime: number;
    hash: string;
}

/** The whole map. */
export interface ProjectMap {
    /** Workspace-relative file -> FileExtraction. */
    files: Record<string, FileExtraction>;
    /** Flat endpoint list (denormalized for the panel). */
    endpoints: EndpointRecord[];
    /** Flat dynamic-pattern list. */
    dynamicPatterns: DynamicPattern[];
    /** Schema version, bumped when the on-disk format changes. */
    version: number;
    /** Last full rebuild timestamp (ms). */
    builtAt: number;
}

/** Schema version for the on-disk cache. Bump to invalidate old caches. */
export const PROJECT_MAP_SCHEMA_VERSION = 1;

/**
 * EndpointContext — the slice of the Project Map that travels with a
 * scan. This is the ONLY new field added to the scan payload, and the API
 * contract is unchanged (today's API ignores it; Phase 5 consumes it).
 *
 * It captures everything the Juror needs to reason about whether the
 * middleware on this route actually defends the sink being scanned:
 * the middleware chain (with source files), the parameters and their
 * validation status, the auth scheme, the ORM/data layer, the handler
 * call graph, and the confidence per relationship.
 */
export interface EndpointContext {
    /** Stable id: `${sourceFile}:${line}:${method}:${path}`. */
    id?: string;
    method: HttpMethod;
    path: string;
    /** Full externally-visible path when the router is mounted under a prefix. */
    mountedPath?: string;
    handlerName: string;
    sourceFile: string;
    line: number;
    middleware: MiddlewareEntry[];
    params: EndpointParam[];
    authScheme: AuthScheme;
    dataLayer: DataLayer;
    validatorLibrary: ValidatorLibrary;
    callGraph: CallGraphNode[];
    responseShape: ResponseShape;
    confidence: number;
    runtimeConfirmed: boolean;
}

/**
 * How a related file relates to the file being scanned.
 *
 * Mirrors `FileRelationship` in the API's `src/types/scanTypes.ts` exactly.
 * The API renders the label verbatim into the Scout/Juror/Fixer prompts, so a
 * value outside this union is not a type error on the wire — it is a prompt
 * that says something the model has never been told how to read.
 */
export type FileRelationship =
    | 'imports'
    | 'imported_by'
    | 'route_handler'
    | 'shared_type'
    | 'config'
    | 'middleware';

/**
 * A neighbouring source file shipped alongside the scanned file so the model
 * can see what the file under scan depends on.
 *
 * Travels as `workspaceHints.relatedFiles`, which the API already consumes:
 * `formatRelatedFilesContext` (api/src/services/contextService.ts) folds it
 * into the Scout, Juror and Fixer prompts.
 */
export interface RelatedFile {
    /** Workspace-relative, POSIX separators — the label the model sees. */
    filePath: string;
    content: string;
    relationship: FileRelationship;
}

/** Convert an EndpointRecord into the serializable EndpointContext. */
export function toEndpointContext(r: EndpointRecord): EndpointContext {
    return {
        id: r.id,
        method: r.method,
        path: r.path,
        mountedPath: r.mountedPath,
        handlerName: r.handlerName,
        sourceFile: r.sourceFile,
        line: r.line,
        middleware: r.middleware,
        params: r.params,
        authScheme: r.authScheme,
        dataLayer: r.dataLayer,
        validatorLibrary: r.validatorLibrary,
        callGraph: r.callGraph,
        responseShape: r.responseShape,
        confidence: r.confidence,
        runtimeConfirmed: r.runtimeConfirmed,
    };
}
