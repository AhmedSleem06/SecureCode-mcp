/**
 * Phase F — POC Executor types.
 *
 * The POC executor verifies whether a Juror VULNERABLE verdict is actually
 * exploitable by running the POC against the live application. It routes
 * to either Lightpanda (DOM-based vulns that need a real browser) or a
 * simple HTTP executor (server-side vulns where raw HTTP suffices).
 *
 * No `isolated-vm` — command injection and prototype pollution are already
 * proven deterministically by the taint tracker (Phase C), and the existing
 * SandboxRunner handles complex attack scenarios. This executor is a thin
 * verification layer for the Juror's POC claims.
 */

/** The target endpoint for the POC. */
export interface PocEndpoint {
    method: string;
    path: string;
    /** Base URL of the running app, e.g. http://127.0.0.1:3000 */
    baseUrl?: string;
}

/** A request to execute a POC. */
export interface PocRequest {
    /** Canonical vulnerability type: xss, sql_injection, open_redirect, etc. */
    vulnType: string;
    /** The POC description from the Juror's `attack_example`. */
    poc: string;
    /** The target endpoint. */
    endpoint: PocEndpoint;
    /** The attack payload to inject (extracted from the POC or provided directly). */
    payload?: string;
    /** What a successful exploit looks like (from the Juror). */
    expectedBehavior?: string;
    /** Where to inject the payload: 'query', 'body', 'path', 'header'. */
    injectionPoint?: 'query' | 'body' | 'path' | 'header';
    /** Parameter name for the injection (e.g. 'q' for ?q=payload). */
    paramName?: string;
}

/** The result of running a POC. */
export interface PocResult {
    /** True if the exploit was confirmed. */
    exploitable: boolean;
    /** What the executor observed. */
    output?: string;
    /** Error message when the executor itself failed. */
    error?: string;
    /** True when the POC timed out. */
    timedOut: boolean;
    /** Why this proves/disproves exploitability. */
    evidence: string;
    /** Replayable PandaScript (when Lightpanda was used). */
    pocScript?: string;
    /** Which backend was used. */
    backend: 'lightpanda' | 'http' | 'none';
}
