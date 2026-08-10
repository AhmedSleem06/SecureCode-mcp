/**
 * Phase F — POC Executor (main entry point).
 *
 * Verifies whether a Juror VULNERABLE verdict is actually exploitable by
 * running the POC against the live application. Routes to the appropriate
 * backend:
 *
 *   - DOM vulns (XSS) → Lightpanda (real browser engine, DOM rendering)
 *   - HTTP vulns (SQLi, SSRF, redirect) → HTTP executor (raw HTTP)
 *   - Non-web vulns (cmd injection, proto pollution) → none (already
 *     proven by the taint tracker / guard evaluator)
 *
 * Lightpanda is optional: if the binary is not installed, DOM POCs return
 * a "not verified" result with install instructions. The existing
 * SandboxRunner handles complex attack scenarios independently.
 *
 * No `isolated-vm`: command injection and prototype pollution are already
 * proven deterministically by the taint tracker (Phase C). The HTTP
 * executor covers server-side vulns. Lightpanda covers DOM vulns. Nothing
 * else needs a sandbox.
 */

import type { PocRequest, PocResult } from './pocTypes';
import { routePoc } from './pocRouter';
import { executeWithLightpanda, isLightpandaAvailable } from './lightpandaExecutor';
import { executeWithHttp } from './httpPocExecutor';

// Re-export types and key functions for consumers
export type { PocRequest, PocResult, PocEndpoint } from './pocTypes';
export { routePoc } from './pocRouter';
export { isLightpandaAvailable } from './lightpandaExecutor';
export { executeWithLightpanda } from './lightpandaExecutor';
export { executeWithHttp } from './httpPocExecutor';

/**
 * Execute a POC against the live application.
 *
 * Routes to the appropriate backend based on the vulnerability type:
 *   - XSS → Lightpanda (if available)
 *   - SQLi, SSRF, redirect → HTTP executor
 *   - Others → none (deterministic analysis already covers them)
 *
 * @param req  the POC request
 * @returns the execution result
 */
export async function executePoc(req: PocRequest): Promise<PocResult> {
    const backend = routePoc(req.vulnType);

    switch (backend) {
        case 'lightpanda':
            return executeWithLightpanda(req);

        case 'http':
            return executeWithHttp(req);

        case 'none':
            return {
                exploitable: false,
                timedOut: false,
                evidence: `POC verification not applicable for ${req.vulnType} — already proven by deterministic analysis (taint tracker / guard evaluator)`,
                backend: 'none',
            };
    }
}

/**
 * Execute multiple POCs in parallel.
 *
 * @param requests  array of POC requests
 * @returns array of results (same order as input)
 */
export async function executePocs(requests: PocRequest[]): Promise<PocResult[]> {
    return Promise.all(requests.map(req => executePoc(req)));
}
