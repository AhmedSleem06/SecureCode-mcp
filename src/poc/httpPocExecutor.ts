/**
 * Phase F — HTTP POC executor.
 *
 * Verifies server-side vulnerabilities (SQL injection, open redirect, SSRF,
 * access control) by sending a single HTTP request with the attack payload
 * and checking the response for the exploit signature.
 *
 * This is a thin layer — the existing SandboxRunner handles complex attack
 * scenarios (baseline comparison, multi-request flows, dev server spawning).
 * This executor assumes the dev server is already running and just does a
 * quick payload injection + response check.
 */

import type { PocRequest, PocResult } from './pocTypes';

// ── Exploit signature patterns ──────────────────────────────────────────────

/** SQL error messages that indicate a successful injection. */
const SQL_ERROR_PATTERNS = [
    /SQL syntax.*MySQL/i,
    /Warning.*mysql_/i,
    /PostgreSQL.*ERROR/i,
    /ORA-\d{5}/i,
    /SQLite3?::query/i,
    /Microsoft SQL Server/i,
    /Incorrect syntax near/i,
    /Unclosed quotation mark/i,
    /PG::.*Error/i,
    /psycopg2\.errors/i,
    /SQL syntax error/i,         // General — catches most SQL backends
    /sqlite3\.OperationalError/i,
    /You have an error in your SQL syntax/i,
];

/** Patterns that indicate the response reflected user input without sanitization. */
const XSS_PATTERNS = [
    /<script[^>]*>.*?<\/script>/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /javascript:/i,
];

/** Internal addresses that indicate SSRF. */
const SSRF_INTERNAL_PATTERNS = [
    /169\.254\.169\.254/i,    // AWS metadata
    /127\.0\.0\.1/i,
    /localhost/i,
    /10\.\d+\.\d+\.\d+/i,
    /192\.168\.\d+\.\d+/i,
];

// ── Execution ───────────────────────────────────────────────────────────────

/**
 * Execute a POC via a simple HTTP request.
 *
 * Sends the attack payload to the target endpoint and checks the response
 * for the exploit signature. Returns a PocResult with the verdict.
 */
export async function executeWithHttp(req: PocRequest): Promise<PocResult> {
    const baseUrl = req.endpoint.baseUrl || 'http://127.0.0.1:3000';
    const fullPath = req.endpoint.path.startsWith('/')
        ? req.endpoint.path
        : '/' + req.endpoint.path;
    const url = baseUrl + fullPath;
    const payload = req.payload || '';
    const injectionPoint = req.injectionPoint || 'query';
    const paramName = req.paramName || 'q';
    const method = req.endpoint.method || 'GET';

    try {
        // Build the request based on injection point
        let requestUrl = url;
        const headers: Record<string, string> = {};
        let body: string | undefined;

        if (injectionPoint === 'query') {
            const sep = requestUrl.includes('?') ? '&' : '?';
            requestUrl = `${requestUrl}${sep}${paramName}=${encodeURIComponent(payload)}`;
        } else if (injectionPoint === 'body') {
            body = JSON.stringify({ [paramName]: payload });
            headers['Content-Type'] = 'application/json';
        } else if (injectionPoint === 'header') {
            headers[paramName] = payload;
        } else if (injectionPoint === 'path') {
            // Replace a path parameter with the payload
            requestUrl = url.replace(/:\w+/, encodeURIComponent(payload));
        }

        const init: RequestInit = {
            method,
            headers,
            ...(body ? { body } : {}),
            signal: AbortSignal.timeout(10_000),
        };

        const startTime = Date.now();
        const response = await fetch(requestUrl, init);
        const responseTime = Date.now() - startTime;
        const responseHeaders: Record<string, string> = {};
        response.headers.forEach((v, k) => { responseHeaders[k] = v; });
        const responseBody = await response.text().catch(() => '');

        // ── Check exploit signatures based on vuln type ────────────────

        if (req.vulnType === 'sql_injection' || req.vulnType === 'nosql_injection') {
            // Check for SQL error messages or data leakage
            for (const pattern of SQL_ERROR_PATTERNS) {
                if (pattern.test(responseBody)) {
                    return {
                        exploitable: true,
                        output: responseBody.slice(0, 500),
                        timedOut: false,
                        evidence: `SQL error message detected in response (pattern: ${pattern.source})`,
                        backend: 'http',
                    };
                }
            }
            // Check for unexpected 200 on a malformed query
            if (response.status >= 200 && response.status < 300 && payload.includes("'")) {
                return {
                    exploitable: true,
                    output: responseBody.slice(0, 500),
                    timedOut: false,
                    evidence: `Injection payload accepted (HTTP ${response.status}) — query did not error on the payload`,
                    backend: 'http',
                };
            }
            return {
                exploitable: false,
                output: responseBody.slice(0, 500),
                timedOut: false,
                evidence: `No SQL error or data leakage detected (HTTP ${response.status})`,
                backend: 'http',
            };
        }

        if (req.vulnType === 'xss') {
            // Check if the payload appears unescaped in the response
            if (payload && responseBody.includes(payload)) {
                return {
                    exploitable: true,
                    output: responseBody.slice(0, 500),
                    timedOut: false,
                    evidence: 'Payload reflected unescaped in HTTP response body',
                    backend: 'http',
                };
            }
            for (const pattern of XSS_PATTERNS) {
                if (pattern.test(responseBody)) {
                    return {
                        exploitable: true,
                        output: responseBody.slice(0, 500),
                        timedOut: false,
                        evidence: `XSS pattern detected in response: ${pattern.source}`,
                        backend: 'http',
                    };
                }
            }
            return {
                exploitable: false,
                output: responseBody.slice(0, 500),
                timedOut: false,
                evidence: 'Payload not reflected in response (may be escaped or sanitized)',
                backend: 'http',
            };
        }

        if (req.vulnType === 'open_redirect') {
            // Check the Location header for the redirect target
            const location = responseHeaders['location'] || '';
            if (location && payload && location.includes(payload)) {
                return {
                    exploitable: true,
                    output: `Location: ${location}`,
                    timedOut: false,
                    evidence: `Redirected to ${location} — open redirect confirmed`,
                    backend: 'http',
                };
            }
            if (response.status >= 300 && response.status < 400 && location) {
                return {
                    exploitable: true,
                    output: `Location: ${location}`,
                    timedOut: false,
                    evidence: `HTTP ${response.status} redirect to ${location}`,
                    backend: 'http',
                };
            }
            return {
                exploitable: false,
                timedOut: false,
                evidence: `No redirect detected (HTTP ${response.status}, no Location header)`,
                backend: 'http',
            };
        }

        if (req.vulnType === 'ssrf') {
            // Check if the response indicates an internal request was made
            for (const pattern of SSRF_INTERNAL_PATTERNS) {
                if (pattern.test(responseBody)) {
                    return {
                        exploitable: true,
                        output: responseBody.slice(0, 500),
                        timedOut: false,
                        evidence: `Internal address detected in response: ${pattern.source}`,
                        backend: 'http',
                    };
                }
            }
            return {
                exploitable: false,
                timedOut: false,
                evidence: 'No internal address detected in response',
                backend: 'http',
            };
        }

        if (req.vulnType === 'broken_access_control') {
            // Check for auth bypass: expected 401/403 but got 200
            if (response.status >= 200 && response.status < 300) {
                return {
                    exploitable: true,
                    output: responseBody.slice(0, 500),
                    timedOut: false,
                    evidence: `Access control bypass: got HTTP ${response.status} (expected 401/403)`,
                    backend: 'http',
                };
            }
            return {
                exploitable: false,
                timedOut: false,
                evidence: `Access control held (HTTP ${response.status})`,
                backend: 'http',
            };
        }

        // Generic fallback
        return {
            exploitable: false,
            output: responseBody.slice(0, 500),
            timedOut: false,
            evidence: `No specific signature check for ${req.vulnType} (HTTP ${response.status}, ${responseTime}ms)`,
            backend: 'http',
        };
    } catch (error: any) {
        const timedOut = error.name === 'TimeoutError' || error.name === 'AbortError';
        return {
            exploitable: false,
            error: error.message,
            timedOut,
            evidence: timedOut
                ? 'POC timed out after 10s — the endpoint may not be running'
                : `HTTP request failed: ${error.message}`,
            backend: 'http',
        };
    }
}
