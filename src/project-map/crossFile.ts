/**
 * Phase 4 — the facts Layer 1 needs from OUTSIDE the file it is extracting.
 *
 * Three questions cannot be answered from one file, and all three change the
 * security reading of an endpoint:
 *
 *   1. What does this middleware actually check? `requireApiKey` is just a
 *      name until the module defining it is read.
 *   2. What is this router mounted behind? A route file registered by
 *      `app.use('/api', requireAuth)` somewhere else is authenticated, and
 *      contains no evidence of it.
 *   3. Is this imported singleton a data layer? `lib/prisma.ts` constructs the
 *      client so that route files never import `@prisma/client` themselves.
 *
 * The types live here so `layer1.ts` stays a pure AST function; `cache.ts`,
 * which owns the filesystem, builds the context.
 */

import { TreeSitterNode } from './parserLoader';
import { AuthScheme } from './types';

/** A parsed dependency of the file being extracted. */
export interface DepFile {
    /** Workspace-relative path. */
    file: string;
    source: string;
    root: TreeSitterNode;
    imports: Map<string, string>;
}

/**
 * Middleware that applies to every route in a file because of where the file's
 * router was mounted, resolved at the mount site (which is the only place the
 * prefix and the middleware order are both visible).
 */
export interface InheritedMiddleware {
    name: string;
    /** File the middleware is defined in, or the mounting file. */
    sourceFile: string;
    registrationLine: number;
    confidence: number;
    /** Auth scheme this middleware implements, resolved where it was mounted. */
    auth: AuthScheme;
    /** True when the middleware expression could not be resolved at all. */
    dynamic: boolean;
}

/** Where a file's router is mounted, and what guards it there. */
export interface MountPoint {
    /** Path prefix the router is mounted under ('/api/users'). */
    prefix: string;
    /** File that performed the mount. */
    mountedBy: string;
    registrationLine: number;
    /** Middleware registered before the mount that covers this prefix. */
    inherited: InheritedMiddleware[];
}

export interface CrossFileContext {
    /** Import spec as written in this file -> the parsed dependency. */
    deps: Map<string, DepFile>;
    /** Middleware applying to every route in this file. */
    inherited: InheritedMiddleware[];
    /**
     * Prefix this file's router is mounted under, or '' when it is not mounted
     * anywhere we can see. Kept separate from `EndpointRecord.path`, which the
     * contract defines as the path AS REGISTERED at the route site.
     */
    mountPrefix: string;
    /** Next.js edge middleware guarding routes whose path matches. */
    nextMiddleware?: { matchers: string[]; auth: AuthScheme; file: string };
}

/** Join a mount prefix and a router-local path into the external path. */
export function joinMountedPath(prefix: string, routePath: string): string {
    if (!prefix) return routePath;
    if (routePath === '?' || routePath === '') return prefix;
    if (routePath === '/') return prefix;
    const left = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
    const right = routePath.startsWith('/') ? routePath : '/' + routePath;
    return left + right;
}
