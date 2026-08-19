/**
 * Local test runner — drives execution of LLM-generated verification tests
 * through the verification sandbox.
 *
 * SECURITY MODEL (post-rewrite):
 *   1. `checkTestSafety()` runs first as defense-in-depth. If it blocks,
 *      we return early without spawning anything.
 *   2. `detectSandbox()` returns the best available real isolation backend
 *      (Docker preferred, Deno as a JS/TS-only fallback). If neither is
 *      available, this runner returns `sandbox-unavailable` — it does NOT
 *      fall back to executing the script with host privileges.
 *   3. The sandbox backend executes the script with no network, a
 *      read-only workspace, a tmpfs /tmp, capped CPU/memory/pids, and a
 *      scrubbed env (only NODE_ENV and PATH). The verdict is parsed from
 *      stdout/stderr against `/PASS:/` and `/FAIL:/` markers.
 *
 * The previous implementation spread the full `process.env` into the
 * child and ran via `execFileSync` with no isolation. That allowed
 * prompt-injected content in scanned source to ride into the
 * verify-generate prompt and produce a test that exfiltrated secrets.
 */

import { checkTestSafety } from './testSafety';
import { createEffectMock } from './effectMock';
import {
    detectSandbox,
    type SandboxBackend,
    type SandboxExecuteOptions,
    type SandboxExecuteResult,
} from './verificationSandbox';

export interface LocalTestResult {
    verdict: 'pass' | 'fail' | 'error' | 'timeout' | 'blocked' | 'sandbox-unavailable' | 'cancelled';
    output: string;
    exitCode: number;
    /** Name of the backend that executed the test (e.g. "docker", "deno"). Empty when blocked or unavailable. */
    backend?: string;
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * The message shown when no isolation backend is available. Exported so the
 * agent-scan tool can reuse it in its top-level `verifyHint` (instead of
 * every finding carrying the full text in its `provenReason`).
 *
 * Why this matters: without a sandbox, the verify loop returns INCONCLUSIVE
 * for every high/medium finding. The headline differentiator of Pipeline 2
 * ("exploit-verified, not just LLM-believed") is offline. The user needs to
 * know — in one place, with a copy-pasteable install path — what to do.
 */
export const SANDBOX_UNAVAILABLE_MESSAGE =
    'No verification sandbox backend (Docker or Deno) was detected. ' +
    'Exploit verification was skipped — the finding is reported as INCONCLUSIVE ' +
    'with confidence capped at 75%. To enable exploit-verified findings:\n' +
    '  • Docker (preferred, supports any language): https://docs.docker.com/get-docker\n' +
    '  • Deno (JS/TS only, lighter install):    https://deno.com/#installation';

export async function runLocalTest(
    script: string,
    runner: string,
    workspaceRoot: string,
    options?: {
        setupScript?: string | null;
        timeoutMs?: number;
        signal?: AbortSignal;
        /** Test-only: inject a sandbox backend. Production code leaves this unset. */
        sandboxBackend?: SandboxBackend;
    },
): Promise<LocalTestResult> {
    // 1. Defense-in-depth static check.
    const safety = checkTestSafety(script, workspaceRoot);
    if (!safety.allowed) {
        return { verdict: 'blocked', output: `Test script blocked: ${safety.reason}`, exitCode: -1 };
    }

    if (options?.setupScript) {
        const setupSafety = checkTestSafety(options.setupScript, workspaceRoot);
        if (!setupSafety.allowed) {
            return { verdict: 'blocked', output: `Setup script blocked: ${setupSafety.reason}`, exitCode: -1 };
        }
    }

    // 2. Resolve the sandbox backend. Production: detectSandbox(). Tests: inject.
    const backend = options?.sandboxBackend ?? detectSandbox();
    if (!backend) {
        return {
            verdict: 'sandbox-unavailable',
            output: SANDBOX_UNAVAILABLE_MESSAGE,
            exitCode: -1,
        };
    }

    // 2b. Auto-create effect mock for JS/TS projects (harmless if unused).
    //     Must happen before the sandbox mounts the workspace.
    if (runner !== 'python' && runner !== 'python3') {
        try { createEffectMock(workspaceRoot); } catch {}
    }

    // 3. Execute inside the sandbox.
    const execOpts: SandboxExecuteOptions = {
        script,
        runner,
        workspaceRoot,
        setupScript: options?.setupScript,
        timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        signal: options?.signal,
    };

    const result: SandboxExecuteResult = await backend.execute(execOpts);

    // Preserve the "exited 0 but no PASS/FAIL marker" message — it's a
    // useful signal that the test ran but didn't follow the protocol.
    if (result.verdict === 'error' && result.exitCode === 0) {
        return {
            verdict: 'error',
            output: `${result.output}\nTest exited 0 but did not print PASS: or FAIL:`,
            exitCode: result.exitCode,
            backend: result.backend,
        };
    }

    return {
        verdict: result.verdict,
        output: result.output,
        exitCode: result.exitCode,
        backend: result.backend,
    };
}

/**
 * Run a validated test command (npm test, pytest, etc.) inside the sandbox.
 * Uses command mode — no script file is written; the executable + args are
 * passed directly to the sandbox backend. The sandbox enforces network=none,
 * read-only workspace, and resource limits.
 *
 * Returns the same LocalTestResult shape as runLocalTest, with exit-code-based
 * verdicts (0 = pass, nonzero = fail).
 */
export async function runTestCommand(
    executable: string,
    args: string[],
    workspaceRoot: string,
    options?: {
        timeoutMs?: number;
        signal?: AbortSignal;
        sandboxBackend?: SandboxBackend;
    },
): Promise<LocalTestResult> {
    const backend = options?.sandboxBackend ?? detectSandbox();
    if (!backend) {
        return {
            verdict: 'sandbox-unavailable',
            output: SANDBOX_UNAVAILABLE_MESSAGE,
            exitCode: -1,
        };
    }

    const execOpts: SandboxExecuteOptions = {
        mode: 'command',
        executable,
        args,
        workspaceRoot,
        timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
        signal: options?.signal,
    };

    const result: SandboxExecuteResult = await backend.execute(execOpts);

    return {
        verdict: result.verdict,
        output: result.output,
        exitCode: result.exitCode,
        backend: result.backend,
    };
}
