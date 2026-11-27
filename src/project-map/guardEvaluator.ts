/**
 * Phase E — guard effectiveness evaluator.
 *
 * Takes a guard (middleware function, sanitizer call, or validator) and
 * an attack type, and returns whether the guard actually stops the attack.
 *
 * The evaluator reuses:
 * - `detectAuthInFunction` from `detectors.ts` to identify auth guards
 * - The sanitizer registry from `sanitizers.ts` to identify sanitizer guards
 * - The pattern library in `guardPatterns.ts` to evaluate effectiveness
 *
 * The Juror sees these deterministic guard evaluations and doesn't have to
 * guess whether `parseInt()` stops XSS (it doesn't) or whether `escape()`
 * stops SQLi (it doesn't).
 */

import { parseSource, TreeSitterNode } from './parserLoader';
import { walk, callParts, isIdentifier, isStringLiteral, stringLiteralValue, collectImports, resolveModulePath } from './astHelpers';
import { detectAuthInFunction, AuthMatch } from './detectors';
import { matchSanitizer } from './sanitizers';
import {
    GUARD_EFFECTIVENESS, GUARD_BYPASS_EXAMPLES, GUARD_EFFECTIVE_REASONS,
    GuardType, GuardEvaluation, AttackType,
} from './guardPatterns';
import type { SinkLanguage } from './sinkRegistry';
import * as fs from 'fs';
import * as path from 'path';

// Re-export the types consumers need (they're declared in guardPatterns.ts
// but callers import them from guardEvaluator.ts for convenience).
export type { GuardEvaluation, AttackType };

// ── Guard identification ────────────────────────────────────────────────────

/**
 * Identify what type of guard a function body implements.
 * Returns the guard type, or 'unknown' if not recognized.
 */
function identifyGuardType(
    fnRoot: TreeSitterNode,
    source: string,
    language: SinkLanguage,
): GuardType {
    const text = source.slice(fnRoot.startIndex, fnRoot.endIndex);

    // ── 1. Auth guards ──────────────────────────────────────────────────────
    // Check authorization guards BEFORE generic auth detection
    // Role checks: req.user.role !== 'admin', requireRole(...), hasRole, isAdmin
    if (/req\.user\.role\s*(!==|===|!= |== )/i.test(text)
        || /\.role\s*(!==|===|!= |== )\s*['"`]/i.test(text)
        || /requireRole|hasRole|isAdmin|requireAdmin|checkRole/i.test(text)) {
        return 'authorization-role';
    }

    // Ownership checks: x.ownerId !== req.user.sub, customerId === req.user.sub, userId !== req.user.id
    if (/\b\w+\.(ownerId|owner_id|userId|user_id|customerId|customer_id|authorId|author_id)\s*(!==|===|!= |== )\s*req\.(user|auth)\./i.test(text)
        || /req\.(user|auth)\.\w+\s*(!==|===|!= |== )\s*\w+\.(ownerId|owner_id|userId|user_id|customerId|customer_id)/i.test(text)
        || /\b(ownerId|owner_id|userId|user_id|customerId|customer_id)\s*(!==|===|!= |== )\s*req\.(user|auth)\.(sub|id|uid)/i.test(text)) {
        return 'authorization-owner';
    }

    const auth = detectAuthInFunction(fnRoot, source);
    if (auth !== 'none') {
        if (auth === 'jwt') {
            // Check if algorithm is pinned
            const hasAlgorithmPin = /algorithms?\s*:/i.test(text)
                || /verifyOptions\.algorithms/i.test(text);
            return hasAlgorithmPin ? 'auth-jwt-verify' : 'auth-jwt-verify-noalg';
        }
        if (auth === 'session') return 'auth-session';
        if (auth === 'api-key') return 'auth-api-key';
    }

    // ── 2. Sanitizer calls ──────────────────────────────────────────────────
    for (const node of walk(fnRoot)) {
        if (node.type !== 'call_expression' && node.type !== 'call') continue;
        const p = callParts(node, source);
        if (!p) continue;
        const sanitizer = matchSanitizer(p.method, p.receiver, language);
        if (!sanitizer) continue;
        // Classify by sanitizer name
        if (['parseInt', 'parseFloat', 'Number', 'int', 'float', 'Boolean', 'bool'].includes(sanitizer)) {
            return 'sanitizer-numeric';
        }
        if (['escape', 'escapeHtml', 'sanitize', 'sanitizeHtml', 'clean', 'xss'].includes(sanitizer)
            || sanitizer.includes('DOMPurify') || sanitizer.includes('bleach')
            || sanitizer.includes('markupsafe') || sanitizer.includes('nh3')) {
            return 'sanitizer-html';
        }
        if (['encodeURIComponent', 'encodeURI'].includes(sanitizer)) {
            return 'sanitizer-url';
        }
    }

    // ── 3. Parameterized query ────────────────────────────────────────────
    // A parameterized query passes the query string (with ? placeholders)
    // and the params as separate arguments — no string concatenation.
    // Pattern: db.query("SELECT ... WHERE id = ?", [params]) — two args,
    // first is a string literal with ?, second is an array/expression.
    for (const node of walk(fnRoot)) {
        if (node.type !== 'call_expression' && node.type !== 'call') continue;
        const p = callParts(node, source);
        if (!p || !p.receiver) continue;
        if (['query', 'execute', 'raw', '$queryRaw'].includes(p.method)) {
            // Check for parameterized pattern: 2+ args, first is a string
            // literal containing ? or a named param, and no concatenation.
            if (p.args.length >= 2) {
                const firstArg = p.args[0];
                const argText = source.slice(firstArg.startIndex, firstArg.endIndex);
                const isStringLike = firstArg.type === 'string'
                    || firstArg.type === 'template_string'
                    || firstArg.type === 'template_literal';
                const hasPlaceholder = argText.includes('?') || /:\w+/.test(argText);
                const hasConcat = argText.includes('+');
                if (isStringLike && hasPlaceholder && !hasConcat) {
                    return 'parameterized-query';
                }
            }
        }
    }

    // ── 4. Allowlist ────────────────────────────────────────────────────────
    // A literal allowlist: if (['a', 'b', 'c'].includes(value))
    if (/if\s*\(\s*\[[^\]]*\]\s*\.(includes|indexOf|has)\s*\(/.test(text)
        || /if\s*\(\s*\w+\s+in\s+\[/.test(text)) {
        // Check if the array is a literal (not a variable)
        const hasLiteralArray = /\[\s*['"`][^\]]*\]\s*\.(includes|indexOf)/.test(text);
        return hasLiteralArray ? 'allowlist-literal' : 'allowlist-dynamic';
    }

    // ── 5. Rate limiting ──────────────────────────────────────────────────
    if (/rateLimit|rate_limit|RateLimit|express-rate-limit|slowDown/i.test(text)) {
        return 'rate-limit';
    }

    // ── 6. Helmet ──────────────────────────────────────────────────────────
    if (/helmet\s*\(|require\s*\(\s*['"]helmet['"]/.test(text)) {
        return 'helmet';
    }

    // ── 7. CORS ────────────────────────────────────────────────────────────
    if (/cors\s*\(|require\s*\(\s*['"]cors['"]/.test(text)) {
        // Check if origin is '*'
        if (/origin\s*:\s*['"]\*['"]/.test(text)) {
            return 'cors-permissive';
        }
        return 'cors-strict';
    }

    // ── 8. Validator (zod/joi/pydantic) ────────────────────────────────────
    if (/\.parse\s*\(|\.validate\s*\(|\.safeParse\s*\(/.test(text)
        && /(zod|joi|yup|pydantic|schema)/i.test(text)) {
        return 'validator';
    }

    // ── 9. Python-specific guards ─────────────────────────────────────────
    if (language === 'python') {
        // Python allowlist: if x in {'a', 'b'} or if x in ('a', 'b') or if x in ['a', 'b']
        if (/if\s+\w+\s+in\s*[\(\{\[]\s*['"][^\])}]*[\])}]/.test(text)) {
            const hasLiteralSet = /in\s*[\(\{\[]\s*['"][^)\]}]*['"]\s*[,)\]}]/.test(text);
            return hasLiteralSet ? 'allowlist-literal' : 'allowlist-dynamic';
        }

        // Python parameterized query: cursor.execute("...%s...", [params]) or
        // cursor.execute("...:name...", {...}) or session.execute(text("...:name..."), {...})
        for (const node of walk(fnRoot)) {
            if (node.type !== 'call' && node.type !== 'call_expression') continue;
            const p = callParts(node, source);
            if (!p || !p.receiver) continue;
            if (['execute', 'executemany', 'execute_many'].includes(p.method)) {
                if (p.args.length >= 2) {
                    const firstArg = p.args[0];
                    const argText = source.slice(firstArg.startIndex, firstArg.endIndex);
                    const isStringLike = firstArg.type === 'string';
                    const hasPlaceholder = argText.includes('%s') || /:\w+/.test(argText);
                    const hasConcat = argText.includes(' + ') || argText.includes('% ') || argText.includes('.format(');
                    if (isStringLike && hasPlaceholder && !hasConcat) {
                        return 'parameterized-query';
                    }
                }
            }
        }

        // Python constant-time comparison: secrets.compare_digest or hmac.compare_digest
        if (/compare_digest|secrets\.compare|hmac\.compare/.test(text)) {
            return 'auth-api-key';  // constant-time comparison = auth guard
        }

        // Python rate limiting: flask_limiter, slowapi, ratelimit decorator
        if (/flask_limiter|Limiter|slowapi|ratelimit|@limiter|@rate_limit/i.test(text)) {
            return 'rate-limit';
        }
    }

    return 'unknown';
}

// ── Evaluation ──────────────────────────────────────────────────────────────

/**
 * Evaluate a guard against a specific attack type.
 *
 * @param guardSource  the source text of the guard function
 * @param guardName    the guard's display name (middleware name)
 * @param attackType   the attack to evaluate against
 * @param language     the source language
 * @returns the evaluation result
 */
export async function evaluateGuard(
    guardSource: string,
    guardName: string,
    attackType: AttackType,
    language: SinkLanguage,
): Promise<GuardEvaluation> {
    const parsed = await parseSource(guardSource, language);
    let guardType: GuardType = 'unknown';

    if (parsed) {
        // Try to find a function body in the parsed source. The guard source
        // may be a full function declaration or just a function body.
        const { root } = parsed;
        // Look for a function declaration/definition
        let fnNode: TreeSitterNode | null = null;
        for (const n of walk(root)) {
            if (['function_declaration', 'function_definition', 'method_definition',
                'async_function_declaration', 'async_function_definition',
                'arrow_function', 'function_expression'].includes(n.type)) {
                fnNode = n;
                break;
            }
        }
        if (fnNode) {
            guardType = identifyGuardType(fnNode, guardSource, language);
        } else {
            // Parse as a bare expression/statement block
            guardType = identifyGuardType(root, guardSource, language);
        }
    }

    // Look up effectiveness
    const effective = GUARD_EFFECTIVENESS[guardType]?.[attackType];
    const isEffective = effective === true;
    const isKnown = effective !== undefined;

    // Build reason
    let reason: string;
    let bypassExample: string | undefined;

    if (isEffective) {
        reason = GUARD_EFFECTIVE_REASONS[guardType]?.[attackType]
            ?? `Guard type '${guardType}' is effective against ${attackType}`;
    } else if (isKnown) {
        // Not effective
        reason = `Guard type '${guardType}' is NOT effective against ${attackType}`;
        bypassExample = GUARD_BYPASS_EXAMPLES[guardType]?.[attackType];
    } else {
        // Unknown — guard detected but we can't determine effectiveness
        reason = `Guard detected as '${guardType}' but effectiveness against ${attackType} is unknown`;
        bypassExample = undefined;
    }

    return {
        guardName,
        guardType,
        attackType,
        effective: isEffective,
        reason,
        ...(bypassExample && { bypassExample }),
    };
}

/**
 * Evaluate multiple guards against multiple attack types.
 *
 * @param guards  array of { source, name } pairs
 * @param attacks array of attack types to evaluate each guard against
 * @param language the source language
 * @returns flat array of evaluations (one per guard×attack pair)
 */
export async function evaluateGuards(
    guards: Array<{ source: string; name: string }>,
    attacks: AttackType[],
    language: SinkLanguage,
): Promise<GuardEvaluation[]> {
    const results: GuardEvaluation[] = [];
    for (const guard of guards) {
        for (const attack of attacks) {
            try {
                const eval_ = await evaluateGuard(guard.source, guard.name, attack, language);
                results.push(eval_);
            } catch {
                // Best-effort: skip guards that fail to parse
            }
        }
    }
    return results;
}

// ── Route-level middleware analysis ──────────────────────────────────────

const ACCESS_CONTROL_ATTACKS = new Set<string>([
    'broken_access_control', 'missing_authorization', 'idor',
    'privilege_escalation', 'auth_bypass',
]);

interface MiddlewareInfo {
    name: string;
    line: number;
    file: string;
    guardType: GuardType;
}

interface RouteGuardInfo {
    method: string;
    path: string;
    line: number;
    file: string;
    middleware: MiddlewareInfo[];
    inHandlerGuards: MiddlewareInfo[];
    hasAuthentication: boolean;
    hasRoleCheck: boolean;
    hasOwnerCheck: boolean;
}

export interface RouteGuardAnalysis {
    routes: RouteGuardInfo[];
    summary: string;
}

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all']);

const OWNER_CHECK_RE = /\b(\w+)\.(ownerId|owner_id|userId|user_id|customerId|customer_id|authorId|author_id)\s*(!==|===|!=\s|==\s)\s*req\.(user|auth)\.(sub|id|uid)\b/;
const OWNER_CHECK_REV_RE = /req\.(user|auth)\.(sub|id|uid)\s*(!==|===|!=\s|==\s)\s*(\w+)\.(ownerId|owner_id|userId|user_id|customerId|customer_id|authorId|author_id)\b/;
const ROLE_CHECK_RE = /req\.(user|auth)\.role\s*(!==|===|!=\s|==\s)\s*['"`]/;

function detectInHandlerGuards(handlerSource: string, routeLine: number, fileName: string): MiddlewareInfo[] {
    const guards: MiddlewareInfo[] = [];
    const lines = handlerSource.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const absLine = routeLine + i;
        const ownerMatch = OWNER_CHECK_RE.exec(line) || OWNER_CHECK_REV_RE.exec(line);
        if (ownerMatch) {
            const desc = line.trim().replace(/\s+/g, ' ').slice(0, 80);
            guards.push({ name: desc, line: absLine, file: fileName, guardType: 'authorization-owner' });
            continue;
        }
        if (ROLE_CHECK_RE.test(line)) {
            const desc = line.trim().replace(/\s+/g, ' ').slice(0, 80);
            guards.push({ name: desc, line: absLine, file: fileName, guardType: 'authorization-role' });
        }
    }
    return guards;
}

function classifyMiddlewareName(name: string, source: string): GuardType {
    const lower = name.toLowerCase();
    if (/requirerole|hasrole|isadmin|requireadmin|checkrole|authorize/i.test(lower)) {
        return 'authorization-role';
    }
    if (/auth|verify|authenticate|requireauth|requirelogin|ensureauth|protect/i.test(lower)) {
        return 'authentication';
    }
    return 'unknown';
}

function classifyMiddlewareBody(fnSource: string, language: SinkLanguage): GuardType {
    if (/req\.user\.role\s*(!==|===|!= |== )/i.test(fnSource)
        || /\.role\s*(!==|===|!= |== )\s*['"`]/i.test(fnSource)) {
        return 'authorization-role';
    }
    if (/\b\w+\.(ownerId|owner_id|userId|user_id|customerId|customer_id)\s*(!==|===|!= |== )\s*req\.(user|auth)\./i.test(fnSource)
        || /req\.(user|auth)\.\w+\s*(!==|===|!= |== )\s*\w+\.(ownerId|owner_id|userId|user_id|customerId|customer_id)/i.test(fnSource)) {
        return 'authorization-owner';
    }
    if (/jwt\.verify|\.verify\s*\(\s*token/i.test(fnSource)
        || /req\.session\.(user|userId)|req\.isAuthenticated/i.test(fnSource)) {
        return 'authentication';
    }
    return classifyMiddlewareName(fnSource.slice(0, 200), fnSource);
}

function findFunctionSourceInParsedFile(
    source: string,
    root: TreeSitterNode,
    fnName: string,
): string | null {
    for (const node of walk(root)) {
        if (node.type === 'function_declaration' || node.type === 'async_function_declaration') {
            const idNode = node.namedChildren.find(c => isIdentifier(c));
            if (idNode && source.slice(idNode.startIndex, idNode.endIndex) === fnName) {
                return source.slice(node.startIndex, node.endIndex);
            }
        }
        if (node.type === 'variable_declarator') {
            const lhs = node.child(0);
            if (lhs && isIdentifier(lhs) && source.slice(lhs.startIndex, lhs.endIndex) === fnName) {
                return source.slice(node.startIndex, node.endIndex);
            }
        }
    }
    return null;
}

function expressPathMatches(pattern: string, routePath: string): boolean | 'unknown' {
    if (pattern === routePath) return true;
    const normalizedPattern = pattern.replace(/\/+$/, '');
    const normalizedRoute = routePath.replace(/\/+$/, '');
    if (normalizedPattern === normalizedRoute) return true;
    if (pattern.includes('*') || pattern.includes(':')) {
        const regexStr = '^' + pattern
            .replace(/\*/g, '.*')
            .replace(/:[^/]+/g, '[^/]+')
            .replace(/\//g, '\\/');
        try {
            const regex = new RegExp(regexStr);
            if (regex.test(routePath)) return true;
        } catch {
            return 'unknown';
        }
    }
    if (routePath.startsWith(pattern.replace(/\*.*$/, ''))) return true;
    return false;
}

interface UseRegistration {
    path: string | null;
    middlewareNames: string[];
    method: string;
    line: number;
    file: string;
    handlerSource?: string;
}

function extractRouteRegistrations(
    root: TreeSitterNode,
    source: string,
    fileName: string,
): { routes: UseRegistration[]; uses: UseRegistration[] } {
    const routes: UseRegistration[] = [];
    const uses: UseRegistration[] = [];

    for (const node of walk(root)) {
        if (node.type !== 'call_expression' && node.type !== 'call') continue;
        const p = callParts(node, source);
        if (!p) continue;
        const recv = p.receiver;
        if (!recv) continue;
        if (!['app', 'router', 'route', 'server'].includes(recv)) continue;

        const method = p.method.toLowerCase();
        if (!HTTP_METHODS.has(method) && method !== 'use') continue;

        let routePath: string | null = null;
        const middlewareNames: string[] = [];

        for (const arg of p.args) {
            if (isStringLiteral(arg)) {
                routePath = stringLiteralValue(arg, source);
            } else if (isIdentifier(arg)) {
                middlewareNames.push(source.slice(arg.startIndex, arg.endIndex));
            } else if (arg.type === 'call_expression' || arg.type === 'call') {
                const innerP = callParts(arg, source);
                if (innerP) {
                    const callText = innerP.receiver
                        ? `${innerP.receiver}.${innerP.method}`
                        : innerP.method;
                    const argTexts = innerP.args
                        .filter(a => isStringLiteral(a))
                        .map(a => stringLiteralValue(a, source));
                    middlewareNames.push(argTexts.length > 0 ? `${callText}('${argTexts[0]}')` : `${callText}()`);
                }
            } else if (arg.type === 'arrow_function' || arg.type === 'function_expression') {
                middlewareNames.push('<handler>');
            }
        }

        let handlerSource: string | undefined;
        const lastArg = p.args[p.args.length - 1];
        if (lastArg && (lastArg.type === 'arrow_function' || lastArg.type === 'function_expression')) {
            handlerSource = source.slice(lastArg.startIndex, lastArg.endIndex);
        }

        const entry: UseRegistration = {
            path: routePath,
            middlewareNames,
            method: method === 'use' ? 'USE' : method.toUpperCase(),
            line: node.startPosition.row + 1,
            file: fileName,
            handlerSource,
        };

        if (method === 'use') {
            uses.push(entry);
        } else {
            routes.push(entry);
        }
    }

    return { routes, uses };
}

export async function analyzeRouteGuards(
    filePath: string,
    fileSource: string,
    language: SinkLanguage,
    workspaceRoot?: string,
): Promise<RouteGuardAnalysis> {
    const parsed = await parseSource(fileSource, language);
    if (!parsed) return { routes: [], summary: 'Could not parse file.' };

    const { root } = parsed;
    const fileName = path.basename(filePath);
    const { routes, uses } = extractRouteRegistrations(root, fileSource, fileName);

    const imports = collectImports(root, fileSource);
    let routerUses: UseRegistration[] = [];
    let routerFnSources: Map<string, string> = new Map();

    for (const [localName, spec] of imports) {
        if (!spec.startsWith('./') && !spec.startsWith('../')) continue;
        if (!workspaceRoot) continue;
        const absFile = path.resolve(path.dirname(path.resolve(workspaceRoot, filePath)), spec);
        const candidates = [absFile, absFile + '.ts', absFile + '.js', absFile + '.tsx', absFile + '.jsx'];
        let resolvedPath: string | null = null;
        for (const c of candidates) {
            if (fs.existsSync(c)) { resolvedPath = c; break; }
        }
        if (!resolvedPath) continue;

        try {
            const routerSource = fs.readFileSync(resolvedPath, 'utf8');
            const routerParsed = await parseSource(routerSource, language);
            if (!routerParsed) continue;
            const routerFileName = path.basename(resolvedPath);
            const routerRegs = extractRouteRegistrations(routerParsed.root, routerSource, routerFileName);
            routerUses = routerUses.concat(routerRegs.uses);
            for (const reg of routerRegs.routes) {
                routerUses.push(reg);
            }

            for (const reg of [...routerRegs.uses, ...routerRegs.routes]) {
                for (const mwName of reg.middlewareNames) {
                    if (mwName.startsWith('<') || mwName.includes('(')) continue;
                    const fnSrc = findFunctionSourceInParsedFile(routerSource, routerParsed.root, mwName);
                    if (fnSrc) routerFnSources.set(mwName, fnSrc);
                }
            }

            for (const use of routerRegs.uses) {
                use.file = routerFileName;
            }
            for (const route of routerRegs.routes) {
                route.file = routerFileName;
            }
        } catch {
            // Cannot read router file — skip
        }
    }

    const allUses = [...uses, ...routerUses];

    for (const mwName of [...new Set([
        ...uses.flatMap(u => u.middlewareNames),
        ...routes.flatMap(r => r.middlewareNames),
    ])]) {
        if (mwName.startsWith('<') || mwName.includes('(')) continue;
        if (routerFnSources.has(mwName)) continue;
        const fnSrc = findFunctionSourceInParsedFile(fileSource, root, mwName);
        if (fnSrc) routerFnSources.set(mwName, fnSrc);
    }

    const resolvedRoutes: RouteGuardInfo[] = [];

    for (const route of routes) {
        if (route.method === 'USE') continue;
        const applicableMiddleware: MiddlewareInfo[] = [];

        for (const use of allUses) {
            if (use.path) {
                const matches = expressPathMatches(use.path, route.path || '');
                if (matches === false) continue;
            }
            if (use.method !== 'USE') {
                if (use.method !== route.method && use.method !== 'ALL') continue;
            }

            for (const mwName of use.middlewareNames) {
                if (mwName === '<handler>') continue;
                const fnSrc = routerFnSources.get(mwName.replace(/\(.*\)$/, ''));
                const guardType = fnSrc
                    ? classifyMiddlewareBody(fnSrc, language)
                    : classifyMiddlewareName(mwName, '');
                applicableMiddleware.push({
                    name: mwName,
                    line: use.line,
                    file: use.file,
                    guardType,
                });
            }
        }

        for (const mwName of route.middlewareNames) {
            if (mwName === '<handler>') continue;
            const fnSrc = routerFnSources.get(mwName.replace(/\(.*\)$/, ''));
            const guardType = fnSrc
                ? classifyMiddlewareBody(fnSrc, language)
                : classifyMiddlewareName(mwName, '');
            applicableMiddleware.push({
                name: mwName,
                line: route.line,
                file: route.file,
                guardType,
            });
        }

        const inHandlerGuards: MiddlewareInfo[] = route.handlerSource
            ? detectInHandlerGuards(route.handlerSource, route.line, route.file)
            : [];

        const allGuards = [...applicableMiddleware, ...inHandlerGuards];
        const hasAuthentication = allGuards.some(m =>
            m.guardType === 'authentication' || m.guardType === 'auth-jwt-verify'
            || m.guardType === 'auth-jwt-verify-noalg' || m.guardType === 'auth-session'
            || m.guardType === 'auth-api-key');
        const hasRoleCheck = allGuards.some(m => m.guardType === 'authorization-role');
        const hasOwnerCheck = allGuards.some(m => m.guardType === 'authorization-owner');

        resolvedRoutes.push({
            method: route.method,
            path: route.path || '<unknown>',
            line: route.line,
            file: route.file,
            middleware: applicableMiddleware,
            inHandlerGuards,
            hasAuthentication,
            hasRoleCheck,
            hasOwnerCheck,
        });
    }

    const lines: string[] = [];
    for (const r of resolvedRoutes) {
        const mwList = r.middleware.length > 0
            ? r.middleware.map(m => `${m.name} (${m.file} L${m.line}, ${m.guardType})`).join(', ')
            : 'none';
        const guardSummary: string[] = [];
        if (r.hasAuthentication) guardSummary.push('authentication');
        if (r.hasRoleCheck) guardSummary.push('authorization-role');
        if (r.hasOwnerCheck) guardSummary.push('authorization-owner');

        let line: string;
        if (guardSummary.length === 0 && r.middleware.length === 0 && r.inHandlerGuards.length === 0) {
            line = `${r.method} ${r.path}: no authentication or authorization middleware applies`;
        } else if (guardSummary.length === 0) {
            line = `${r.method} ${r.path}: middleware [${mwList}] — no authentication or authorization guard detected`;
        } else {
            line = `${r.method} ${r.path}: ${mwList} — guards: ${guardSummary.join(', ')}`;
        }
        if (r.inHandlerGuards.length > 0) {
            const ihList = r.inHandlerGuards.map(m => `${m.name} (L${m.line}, ${m.guardType})`).join('; ');
            line += `; in handler: ${ihList}`;
        }
        lines.push(line);
    }

    return {
        routes: resolvedRoutes,
        summary: lines.length > 0 ? lines.join('\n') : 'No HTTP routes found in this file.',
    };
}
