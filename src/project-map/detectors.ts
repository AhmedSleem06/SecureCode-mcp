/**
 * Phase 4 Layer 1 — framework / library detectors.
 *
 * Each detector takes the file's source text + the assignments map + the
 * imports map and returns a label (or 'unknown'). Keeping these in one
 * place means Layer 1 extraction can stay focused on routing structure.
 */

import { TreeSitterNode } from './parserLoader';
import { callParts, firstAncestor, isStringLiteral, stringLiteralValue, walk } from './astHelpers';
import type { DataLayer } from './types';

export type AuthMatch = 'jwt' | 'session' | 'api-key' | 'oauth' | 'basic' | 'none';

/** Detect auth scheme from imports + call sites. */
export function detectAuth(
    imports: Map<string, string>,
    root: TreeSitterNode,
    source: string,
): AuthMatch {
    const from = (mod: string) =>
        [...imports.values()].some(s => s.includes(mod));

    if (from('passport-jwt') || from('jsonwebtoken') || from('fastapi-jwt') || from('jose')) return 'jwt';
    if (from('express-session') || from('cookie-session') || from('django.contrib.sessions') || from('starlette.sessions')) return 'session';
    if (from('passport-google') || from('passport-github') || from('authlib') || from('itsdangerous')) return 'oauth';
    if (from('passport-http') || from('http-auth')) return 'basic';

    // api-key: look for x-api-key access or a Depends(api_key) in the file
    for (const n of walk(root)) {
        if (n.type === 'subscript_expression' || n.type === 'subscript') {
            const txt = source.slice(n.startIndex, n.endIndex);
            if (/x-api-key|apiKey|api_key/i.test(txt)) return 'api-key';
        }
    }

    // JWT heuristic: jsonwebtoken.verify call
    for (const n of walk(root)) {
        if (n.type === 'call_expression' || n.type === 'call') {
            const p = callParts(n, source);
            if (!p) continue;
            if (p.receiver === 'jwt' && p.method === 'verify') return 'jwt';
            if (p.receiver === 'passport' && p.method === 'authenticate') {
                return 'oauth'; // passport.authenticate('google', ...) default
            }
        }
    }
    return 'none';
}

/** Module specs that identify each data layer, most specific first. */
const DATA_LAYER_SPECS: { layer: DataLayerMatch; test: (spec: string) => boolean }[] = [
    { layer: 'prisma', test: s => s.includes('@prisma/client') },
    { layer: 'typeorm', test: s => s.includes('typeorm') },
    { layer: 'sequelize', test: s => s.includes('sequelize') },
    { layer: 'knex', test: s => s === 'knex' || s.includes('/knex') },
    { layer: 'mongoose', test: s => s.includes('mongoose') },
    { layer: 'supabase', test: s => s.includes('@supabase/') || s === 'supabase' || s.startsWith('supabase.') },
    { layer: 'sqlalchemy', test: s => s === 'sqlalchemy' || s.startsWith('sqlalchemy.') },
    { layer: 'django-orm', test: s => s === 'django' || s.startsWith('django.') },
];

export type DataLayerMatch =
    | 'prisma' | 'typeorm' | 'sequelize' | 'knex' | 'mongoose' | 'raw-sql'
    | 'supabase' | 'sqlalchemy' | 'django-orm' | 'none';

/** Detect ORM / data layer from imports. */
export function detectDataLayer(imports: Map<string, string>): DataLayerMatch {
    const specs = [...imports.values()];
    for (const { layer, test } of DATA_LAYER_SPECS) {
        if (specs.some(test)) return layer;
    }
    return 'none';
}

/**
 * Map an internal detector match to the public `DataLayer` taxonomy.
 *
 * The Project Map ground truth deliberately uses `"unknown"` (not `"none"`)
 * for a handler that DOES touch a data client the taxonomy cannot name.
 * Supabase/PostgREST is now labeled `"supabase"`. `"none"` is reserved for
 * "the handler touches no data layer at all".
 */
export function toDataLayer(layer: DataLayerMatch): DataLayer {
    switch (layer) {
        case 'supabase': return 'supabase';
        default: return layer;
    }
}

/**
 * Local names that stand for the data layer in this file: the imported client
 * itself plus anything constructed from it (`const prisma = new PrismaClient()`,
 * `const supabase = createClient(...)`).
 *
 * Used to decide whether a given handler actually touches the data layer, as
 * opposed to merely living in a file that imports one.
 */
export function dataLayerBindings(
    layer: DataLayerMatch,
    imports: Map<string, string>,
    root: TreeSitterNode,
    source: string,
    seed?: Iterable<string>,
): Set<string> {
    const names = new Set<string>(seed ?? []);
    if (layer === 'none') return names;
    const match = DATA_LAYER_SPECS.find(d => d.layer === layer);
    for (const [local, spec] of imports) {
        if (match ? match.test(spec) : false) names.add(local);
    }
    // Anything built from one of those names is also the data layer.
    for (const n of walk(root)) {
        if (n.type !== 'variable_declarator' && n.type !== 'assignment') continue;
        const target = n.child(0);
        const value = n.child(n.childCount - 1);
        if (!target || !value || target === value) continue;
        if (target.type !== 'identifier') continue;
        const valueText = source.slice(value.startIndex, value.endIndex);
        if ([...names].some(b => new RegExp(`\\b${escapeForRegExp(b)}\\b`).test(valueText))) {
            names.add(source.slice(target.startIndex, target.endIndex));
        }
    }
    return names;
}

function escapeForRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export type ValidatorMatch = 'zod' | 'joi' | 'express-validator' | 'yup' | 'ajv' | 'pydantic' | 'marshmallow' | 'none';

/** Detect validator library from imports. */
export function detectValidator(imports: Map<string, string>): ValidatorMatch {
    const specs = [...imports.values()];
    if (specs.some(s => s === 'zod' || s.startsWith('zod/'))) return 'zod';
    if (specs.some(s => s.includes('joi'))) return 'joi';
    if (specs.some(s => s.includes('express-validator'))) return 'express-validator';
    if (specs.some(s => s === 'yup' || s.startsWith('yup/'))) return 'yup';
    if (specs.some(s => s.includes('ajv'))) return 'ajv';
    if (specs.some(s => s === 'pydantic' || s.startsWith('pydantic.'))) return 'pydantic';
    if (specs.some(s => s === 'marshmallow' || s.startsWith('marshmallow.'))) return 'marshmallow';
    return 'none';
}

/** Known route-registration method names across Express/Fastify/Koa/Python. */
const ROUTE_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'all', 'route']);
const KNOWN_RECEIVERS = new Set(['app', 'router', 'server', 'fastify', 'api', 'route', 'controller', 'rtr']);

/** Node types a route path can legitimately be written as. */
function isPathExpression(node: TreeSitterNode): boolean {
    return isStringLiteral(node)
        || node.type === 'identifier'
        || node.type === 'template_string'
        || node.type === 'template_literal';
}

/** True iff a call node is a route registration: app.get('/x', handler) etc. */
export function isRouteRegistration(
    callNode: TreeSitterNode,
    source: string,
): { receiver: string | null; method: string; args: TreeSitterNode[]; line: number } | null {
    if (callNode.type !== 'call_expression' && callNode.type !== 'call') return null;
    const p = callParts(callNode, source);
    if (!p || !p.receiver) return null;
    if (!KNOWN_RECEIVERS.has(p.receiver)) return null;
    if (!ROUTE_METHODS.has(p.method.toLowerCase())) return null;
    if (p.args.length < 1) return null;
    // The path may be a constant or a template literal, not just a literal.
    // Resolution (and the '?' fallback for a genuinely dynamic path) belongs to
    // the caller; dropping the registration here loses the endpoint entirely.
    if (!isPathExpression(p.args[0])) return null;
    // A non-literal single argument is far more likely to be a getter
    // (`app.get(setting)`) than a route, so require a handler alongside it.
    if (!isStringLiteral(p.args[0]) && p.args.length < 2) return null;
    return p;
}

/** Django URLconf registration functions. */
const DJANGO_ROUTE_FUNCTIONS = new Set(['path', 're_path', 'url']);

/**
 * True iff a call is a Django URLconf entry: `path("articles/", views.list)`.
 *
 * These are bare calls with no receiver, so they cannot be told from any other
 * one-word function call by shape alone. Membership of a `urlpatterns` list is
 * what makes them a route, and it is also how Django itself decides.
 */
export function isDjangoRouteRegistration(
    callNode: TreeSitterNode,
    source: string,
): { path: TreeSitterNode; view: TreeSitterNode | null; line: number } | null {
    if (callNode.type !== 'call') return null;
    const p = callParts(callNode, source);
    if (!p || p.receiver !== null) return null;
    if (!DJANGO_ROUTE_FUNCTIONS.has(p.method)) return null;
    if (p.args.length < 1 || !isStringLiteral(p.args[0])) return null;
    if (!firstAncestor(callNode, n => isUrlpatternsAssignment(n, source))) return null;
    const positional = p.args.filter(a => a.type !== 'keyword_argument');
    return { path: positional[0], view: positional[1] ?? null, line: p.line };
}

/** True iff a node is the `urlpatterns = [...]` assignment. */
function isUrlpatternsAssignment(node: TreeSitterNode, source: string): boolean {
    if (node.type !== 'assignment') return false;
    const target = node.child(0);
    if (!target) return false;
    return source.slice(target.startIndex, target.endIndex).trim() === 'urlpatterns';
}

/** True iff a call node is app.use(...) (global/route middleware registration). */
export function isUseRegistration(
    callNode: TreeSitterNode,
    source: string,
): { receiver: string | null; args: TreeSitterNode[]; line: number } | null {
    if (callNode.type !== 'call_expression' && callNode.type !== 'call') return null;
    const p = callParts(callNode, source);
    if (!p || !p.receiver) return null;
    if (p.method !== 'use') return null;
    if (!KNOWN_RECEIVERS.has(p.receiver)) return null;
    return { receiver: p.receiver, args: p.args, line: p.line };
}

/** HTTP method normalization for the EndpointRecord. */
export function normalizeMethod(m: string): 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'ALL' {
    const u = m.toUpperCase();
    if (u === 'ROUTE' || u === 'ALL') return 'ALL';
    return u as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
}

/** Response objects whose methods describe the body being sent. */
const RESPONSE_OBJECTS = new Set(['res', 'response', 'reply', 'ctx', 'NextResponse', 'Response']);

/**
 * Free response constructors. Django and Flask build the response by calling a
 * function rather than by calling a method on a response object, so the shape
 * is carried by the callee name instead of the receiver.
 */
export const RESPONSE_CONSTRUCTORS: Record<string, 'json' | 'html' | 'redirect' | 'stream' | 'file' | 'text'> = {
    JsonResponse: 'json',
    jsonify: 'json',
    render: 'html',
    render_template: 'html',
    redirect: 'redirect',
    HttpResponseRedirect: 'redirect',
    FileResponse: 'file',
    send_file: 'file',
    StreamingHttpResponse: 'stream',
    HttpResponse: 'text',
};

/** Detect response shape from the handler's return / res.send / res.json calls. */
export function detectResponseShape(
    handlerRoot: TreeSitterNode,
    source: string,
): 'json' | 'html' | 'redirect' | 'stream' | 'file' | 'text' | 'unknown' {
    let sawJson = false, sawRender = false, sawRedirect = false, sawSend = false, sawStream = false, sawFile = false;
    const note = (shape: string) => {
        switch (shape) {
            case 'json': sawJson = true; break;
            case 'html': sawRender = true; break;
            case 'redirect': sawRedirect = true; break;
            case 'text': sawSend = true; break;
            case 'stream': sawStream = true; break;
            case 'file': sawFile = true; break;
        }
    };
    for (const n of walk(handlerRoot)) {
        if (n.type !== 'call_expression' && n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p) continue;
        if (!p.receiver) {
            const shape = RESPONSE_CONSTRUCTORS[p.method];
            if (shape) note(shape);
            continue;
        }
        if (RESPONSE_OBJECTS.has(p.receiver)) {
            switch (p.method) {
                case 'json': sawJson = true; break;
                case 'render': sawRender = true; break;
                case 'redirect': sawRedirect = true; break;
                case 'send': sawSend = true; break;
                case 'sendStream': case 'stream': case 'pipe': sawStream = true; break;
                case 'sendFile': case 'download': case 'attachment': sawFile = true; break;
            }
        }
    }
    if (sawRedirect) return 'redirect';
    if (sawRender) return 'html';
    if (sawFile) return 'file';
    if (sawStream) return 'stream';
    if (sawJson) return 'json';
    if (sawSend) return 'text';
    return 'unknown';
}

/**
 * Detect the auth scheme a specific FUNCTION implements, from evidence inside
 * its own body.
 *
 * Distinct from `detectAuth`, which answers "does this FILE deal in auth" from
 * its imports. That question is the wrong one for a middleware or a FastAPI
 * dependency: `get_db` and `get_current_user` live in the same module, and only
 * one of them is a guard.
 */
export function detectAuthInFunction(
    fnRoot: TreeSitterNode,
    source: string,
): AuthMatch {
    const text = source.slice(fnRoot.startIndex, fnRoot.endIndex);
    if (/x-api-key|\bapi_key\b|\bapiKey\b/i.test(text)) return 'api-key';
    for (const n of walk(fnRoot)) {
        if (n.type !== 'call_expression' && n.type !== 'call') continue;
        const p = callParts(n, source);
        if (!p) continue;
        const receiver = (p.receiver ?? '').toLowerCase();
        if (/^(jwt|jose|jsonwebtoken|jwtlib)$/.test(receiver)
            && ['verify', 'decode', 'sign'].includes(p.method)) {
            return 'jwt';
        }
        if (receiver === 'passport' && p.method === 'authenticate') return 'oauth';
        // `req.cookies.get('sb-access-token')` / `request.session[...]`.
        if (/\bcookies?\b|\bsession\b/i.test(p.receiverText ?? '')) return 'session';
    }
    if (/\bsession\b/i.test(text)) return 'session';
    return 'none';
}

/** Quick check: does the file import any framework we recognize at all? */
export function isLikelyFrameworkFile(imports: Map<string, string>): boolean {
    const specs = [...imports.values()];
    return specs.some(s =>
        s === 'express' || s.startsWith('express/') ||
        s === 'fastify' || s.startsWith('fastify/') ||
        s === 'koa' || s.startsWith('koa/') ||
        s === 'koa-router' || s === '@koa/router' ||
        s === 'fastapi' ||
        s === 'django' || s.startsWith('django.')
    );
}

/**
 * WebSocket lifecycle event names. A `.on(name, h)` where `name` is one of
 * these is treated as a WebSocket handler even when the receiver name does not
 * look like a socket — `io.on('connection', h)` is the canonical socket.io
 * server setup and the receiver `io` is not in the WS_RECEIVER set.
 */
const WS_EVENTS = new Set([
    'connection', 'message', 'disconnect', 'error', 'close', 'open',
    'upgrade', 'ping', 'pong', 'listening', 'unexpected-response',
    'handshake', 'data', 'end',
]);

/**
 * Receiver names that are conventionally WebSocket objects. A `.on(name, h)`
 * on one of these is treated as a WebSocket handler even when the event name
 * is not in WS_EVENTS (custom application events over socket.io).
 */
const WS_RECEIVERS = new Set([
    'ws', 'wss', 'socket', 'io', 'sio', 'webSocket', 'websocket',
    'client', 'connection', 'sock',
]);

/** True iff a receiver name looks like a WebSocket object. */
function isWsReceiver(receiver: string): boolean {
    const r = receiver.toLowerCase();
    if (WS_RECEIVERS.has(r)) return true;
    // Catches `wsServer`, `socketRef`, `wsClient`, `ioServer`…
    return /^(ws|socket|io|wss|sock)[A-Z0-9_]/.test(r) || /[A-Z0-9_](ws|socket|io)$/.test(r);
}

/**
 * Detect a WebSocket handler registration: `.on(event, handler)` where the
 * event is a known WS lifecycle event OR the receiver looks like a socket.
 *
 * Returns the event name, handler node, receiver name and line, or null when
 * the call is not a WebSocket registration.
 */
export function isWebSocketRegistration(
    callNode: TreeSitterNode,
    source: string,
): { receiver: string; event: string; handler: TreeSitterNode | null; line: number } | null {
    if (callNode.type !== 'call_expression' && callNode.type !== 'call') return null;
    const p = callParts(callNode, source);
    if (!p || !p.receiver) return null;
    // `.on(...)` / `.addEventListener(...)` / `.handle(...)`
    if (p.method !== 'on' && p.method !== 'addEventListener' && p.method !== 'handle') return null;
    if (p.args.length < 1) return null;
    const eventArg = p.args[0];
    if (!isStringLiteral(eventArg)) return null;
    const event = stringLiteralValue(eventArg, source);
    if (!event) return null;

    const receiverLooksWs = isWsReceiver(p.receiver);
    const eventIsWs = WS_EVENTS.has(event.toLowerCase());
    // Require either the receiver name or the event name to look WebSocket-y.
    // `emitter.on('tick', h)` is not a WebSocket handler; `io.on('tick', h)`
    // is, because socket.io uses arbitrary custom events over the socket.
    if (!receiverLooksWs && !eventIsWs) return null;
    // For generic EventEmitters that also have `.on('error', h)` (e.g.
    // process, streams), require the receiver to look WebSocket-y when the
    // event is a common EventEmitter event.
    if (!receiverLooksWs && (event === 'error' || event === 'end' || event === 'data')) {
        return null;
    }

    const handler = p.args.length >= 2 ? p.args[p.args.length - 1] : null;
    return { receiver: p.receiver, event, handler, line: p.line };
}
