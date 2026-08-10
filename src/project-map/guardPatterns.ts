/**
 * Phase E — guard pattern library.
 *
 * Maps guard types to the attacks they do and don't stop. The guard
 * evaluator uses this to answer "does this guard actually defend against
 * this attack?" — a question the Juror would otherwise have to guess at.
 *
 * The patterns are conservative: when we can't determine effectiveness, we
 * return `unknown` rather than `effective` (a false "effective" is far more
 * dangerous than a false "unknown" — it would let the Juror mark a real
 * vulnerability as SAFE).
 */

/** Attack types that guards are evaluated against (matches canonical vuln types). */
export type AttackType =
    | 'sql_injection'
    | 'nosql_injection'
    | 'command_injection'
    | 'xss'
    | 'ssrf'
    | 'path_traversal'
    | 'open_redirect'
    | 'prototype_pollution'
    | 'insecure_deserialization'
    | 'broken_access_control';

/** Guard types we can identify and evaluate. */
export type GuardType =
    | 'sanitizer-numeric'       // parseInt, parseFloat, Number, int(), float()
    | 'sanitizer-html'          // escapeHtml, escape, DOMPurify.sanitize, bleach.clean
    | 'sanitizer-url'           // encodeURIComponent, encodeURI
    | 'parameterized-query'     // prepared statements, parameterized queries
    | 'allowlist-literal'       // allowlist with a literal set of values
    | 'allowlist-dynamic'       // allowlist with a user-controlled key
    | 'auth-jwt-verify'         // jwt.verify call
    | 'auth-jwt-verify-noalg'   // jwt.verify without algorithm pinning
    | 'auth-session'            // session-based auth check
    | 'auth-api-key'            // API key check
    | 'auth-none'               // no auth detected
    | 'rate-limit'              // rate limiting middleware
    | 'helmet'                  // helmet() — security headers
    | 'cors-strict'             // strict CORS config
    | 'cors-permissive'         // permissive CORS (origin: '*')
    | 'validator'               // schema validation (zod, joi, pydantic)
    | 'unknown';                // guard detected but type not recognized

export interface GuardEvaluation {
    /** The guard's display name. */
    guardName: string;
    /** Type of guard identified. */
    guardType: GuardType;
    /** The attack type being evaluated against. */
    attackType: AttackType;
    /** Does this guard stop this attack? */
    effective: boolean;
    /** Why it is or isn't effective. */
    reason: string;
    /** Example bypass when not effective. */
    bypassExample?: string;
}

/**
 * Pattern: which GuardType stops which AttackType.
 *
 * `true` = effective, `false` = NOT effective, `undefined` = unknown.
 * When unknown, the evaluator returns `effective: false` with a reason
 * explaining the guard was detected but its effectiveness against this
 * attack is not determinable.
 */
export const GUARD_EFFECTIVENESS: Record<GuardType, Partial<Record<AttackType, boolean>>> = {
    'sanitizer-numeric': {
        sql_injection: true,       // numbers can't carry SQL syntax
        nosql_injection: true,     // numbers can't carry NoSQL operators
        command_injection: true,   // numbers can't carry shell metachars
        xss: true,                 // numbers can't carry script tags
        open_redirect: true,       // numbers can't be URLs
        path_traversal: true,      // numbers can't carry ../
        ssrf: true,                // numbers can't be URLs
        prototype_pollution: true, // numbers can't carry __proto__
    },
    'sanitizer-html': {
        xss: true,                 // HTML escaping stops XSS
        sql_injection: false,      // HTML escaping does NOT stop SQLi
        command_injection: false,
        open_redirect: false,
        path_traversal: false,
        ssrf: false,
        prototype_pollution: false,
    },
    'sanitizer-url': {
        open_redirect: true,       // URL encoding stops redirect injection
        xss: false,                 // URL encoding does NOT stop XSS
        sql_injection: false,
        command_injection: false,
        ssrf: true,                 // URL encoding limits SSRF target manipulation
        path_traversal: false,
    },
    'parameterized-query': {
        sql_injection: true,        // parameterized queries stop SQLi
        nosql_injection: false,
        command_injection: false,
        xss: false,
    },
    'allowlist-literal': {
        sql_injection: true,
        nosql_injection: true,
        command_injection: true,
        xss: true,
        open_redirect: true,
        path_traversal: true,
        ssrf: true,
        prototype_pollution: true,
    },
    'allowlist-dynamic': {
        // An allowlist with a user-controlled key is NOT effective against anything
        sql_injection: false,
        nosql_injection: false,
        command_injection: false,
        xss: false,
        open_redirect: false,
        path_traversal: false,
        ssrf: false,
    },
    'auth-jwt-verify': {
        broken_access_control: true,  // verified JWT = authenticated
    },
    'auth-jwt-verify-noalg': {
        broken_access_control: false,  // algorithm confusion bypass
    },
    'auth-session': {
        broken_access_control: true,
    },
    'auth-api-key': {
        broken_access_control: true,
    },
    'auth-none': {
        broken_access_control: false,
    },
    'rate-limit': {
        // Rate limiting stops brute force but not the vuln types in our taxonomy
        broken_access_control: false,
    },
    'helmet': {
        xss: false,              // helmet sets headers, doesn't sanitize output
        ssrf: false,
    },
    'cors-strict': {
        // CORS strict doesn't stop any server-side vuln
    },
    'cors-permissive': {
        broken_access_control: false,
    },
    'validator': {
        // Schema validation (zod/joi/pydantic) is effective when the schema
        // constrains the type (e.g. z.number() stops SQLi). Without seeing
        // the schema, we can't say — return unknown (false + reason).
        sql_injection: false,
        xss: false,
    },
    'unknown': {},
};

/** Bypass examples for known ineffective guard×attack pairs. */
export const GUARD_BYPASS_EXAMPLES: Partial<Record<GuardType, Partial<Record<AttackType, string>>>> = {
    'sanitizer-html': {
        sql_injection: "escapeHtml doesn't stop SQLi: q' OR 1=1-- is valid HTML",
        command_injection: "escapeHtml doesn't stop cmd injection: ; cat /etc/passwd",
    },
    'sanitizer-url': {
        xss: "encodeURIComponent doesn't stop XSS: <script> stays as %3Cscript%3E (decodes in HTML)",
    },
    'sanitizer-numeric': {
        insecure_deserialization: "parseInt doesn't validate serialized objects",
    },
    'auth-jwt-verify-noalg': {
        broken_access_control: "Algorithm confusion: sign with HS256 using the public RSA key as the secret",
    },
    'allowlist-dynamic': {
        sql_injection: "User-controlled allowlist key: attacker sets key to their payload",
        xss: "User-controlled allowlist key: attacker sets key to <script>",
    },
    'rate-limit': {
        broken_access_control: "Rate limiting slows brute force but doesn't stop auth bypass",
    },
    'helmet': {
        xss: "helmet sets CSP/X-Frame-Options but doesn't sanitize response body content",
    },
    'cors-permissive': {
        broken_access_control: "CORS origin:'*' allows any origin to read responses",
    },
    'validator': {
        sql_injection: "Schema validation only stops SQLi if the schema enforces numeric/enum type",
        xss: "Schema validation only stops XSS if the schema enforces no HTML or sanitizes",
    },
};

/** Reasons explaining why a guard is effective. */
export const GUARD_EFFECTIVE_REASONS: Partial<Record<GuardType, Partial<Record<AttackType, string>>>> = {
    'sanitizer-numeric': {
        sql_injection: 'parseInt/Number produces a numeric value — no SQL syntax can survive',
        xss: 'parseInt/Number produces a numeric value — no script tags can survive',
        command_injection: 'parseInt/Number produces a numeric value — no shell metacharacters',
    },
    'sanitizer-html': {
        xss: 'HTML escaping escapes <, >, ", \', & — prevents script injection',
    },
    'parameterized-query': {
        sql_injection: 'Parameterized queries separate code from data — injection impossible',
    },
    'allowlist-literal': {
        sql_injection: 'Literal allowlist rejects any value not in the set',
        xss: 'Literal allowlist rejects any value not in the set',
    },
    'auth-jwt-verify': {
        broken_access_control: 'jwt.verify with algorithm pinning rejects forged tokens',
    },
    'auth-session': {
        broken_access_control: 'Session check rejects unauthenticated requests',
    },
};
