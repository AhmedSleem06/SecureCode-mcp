/**
 * Shared test runner — the core service for run_tests (both public MCP tool
 * and agent action). Handles:
 *   - Request validation
 *   - Human approval (every execution, no exceptions)
 *   - Sandbox execution via localTestRunner (generated) or runTestCommand (existing)
 *   - Bounded, redacted output
 *
 * Security model:
 *   - Approval is required before every execution — no batch grants, no timed grants.
 *   - The approval hash binds to mode, command/script hash, runner, timeout, workspace.
 *   - No execution occurs if approval is denied or times out.
 *   - No host fallback when no sandbox is available.
 */

import * as crypto from 'crypto';
import { ApprovalBroker } from '../approval/broker';
import { runLocalTest, runTestCommand, type LocalTestResult } from './localTestRunner';
import { validateTestCommand, type ValidatedTestCommand, formatValidatedCommand } from './testCommandPolicy';
import { checkTestSafety } from './testSafety';

const MAX_SCRIPT_SIZE = 64 * 1024;
const MAX_SETUP_SCRIPT_SIZE = 32 * 1024;
const MAX_OUTPUT = 16 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

const SAFE_RUNNERS = new Set(['node', 'tsx', 'bun', 'deno', 'python', 'python3']);

export type RunTestsMode = 'existing' | 'generated';

export interface RunTestsRequest {
    mode: RunTestsMode;

    testFiles?: string[];
    testPattern?: string;
    packageManager?: string;

    script?: string;
    runner?: string;
    setupScript?: string;

    timeoutMs?: number;
}

export type RunTestsStatus =
    | 'passed'
    | 'failed'
    | 'error'
    | 'timeout'
    | 'blocked'
    | 'sandbox-unavailable'
    | 'denied';

export interface RunTestsResult {
    approved: boolean;
    requestId?: string;
    mode: RunTestsMode;
    status: RunTestsStatus;
    exitCode: number;
    output: string;
    backend?: string;
    command?: { executable: string; args: string[] };
    durationMs: number;
}

function sha256Prefix(s: string): string {
    return crypto.createHash('sha256').update(s).digest('hex').substring(0, 16);
}

function truncateOutput(s: string): string {
    if (s.length <= MAX_OUTPUT) return s;
    return s.slice(0, MAX_OUTPUT) + '\n… [truncated]';
}

function mapVerdict(verdict: LocalTestResult['verdict']): RunTestsStatus {
    switch (verdict) {
        case 'pass': return 'passed';
        case 'fail': return 'failed';
        case 'error': return 'error';
        case 'timeout': return 'timeout';
        case 'blocked': return 'blocked';
        case 'sandbox-unavailable': return 'sandbox-unavailable';
        default: return 'error';
    }
}

export interface ValidationFailure {
    ok: false;
    error: string;
}

export function validateRunTestsRequest(req: RunTestsRequest, workspaceRoot: string): { ok: true; command?: ValidatedTestCommand } | ValidationFailure {
    if (!req.mode || (req.mode !== 'existing' && req.mode !== 'generated')) {
        return { ok: false, error: 'mode must be "existing" or "generated"' };
    }

    if (req.mode === 'existing') {
        const result = validateTestCommand({
            packageManager: req.packageManager,
            testFiles: req.testFiles,
            testPattern: req.testPattern,
            timeoutMs: req.timeoutMs,
        }, workspaceRoot);
        if (!result.ok) return { ok: false, error: result.error! };
        return { ok: true, command: result.command };
    }

    // Generated mode
    if (!req.script || req.script.trim().length === 0) {
        return { ok: false, error: 'generated mode requires "script" (non-empty string)' };
    }
    if (req.script.length > MAX_SCRIPT_SIZE) {
        return { ok: false, error: `script too large (max ${MAX_SCRIPT_SIZE} bytes, got ${req.script.length})` };
    }
    if (!req.runner || !SAFE_RUNNERS.has(req.runner)) {
        return { ok: false, error: `runner must be one of: ${[...SAFE_RUNNERS].join(', ')}. Got: ${req.runner || '(none)'}` };
    }
    if (req.setupScript && req.setupScript.length > MAX_SETUP_SCRIPT_SIZE) {
        return { ok: false, error: `setupScript too large (max ${MAX_SETUP_SCRIPT_SIZE} bytes)` };
    }

    const safety = checkTestSafety(req.script, workspaceRoot);
    if (!safety.allowed) {
        return { ok: false, error: `script blocked by safety check: ${safety.reason}` };
    }
    if (req.setupScript) {
        const setupSafety = checkTestSafety(req.setupScript, workspaceRoot);
        if (!setupSafety.allowed) {
            return { ok: false, error: `setupScript blocked by safety check: ${setupSafety.reason}` };
        }
    }

    return { ok: true };
}

function buildApprovalSummary(req: RunTestsRequest, command?: ValidatedTestCommand): string {
    if (req.mode === 'existing' && command) {
        const files = command.selectedFiles.length > 0
            ? `\nFiles: ${command.selectedFiles.join(', ')}`
            : '';
        const pattern = req.testPattern ? `\nPattern: ${req.testPattern}` : '';
        return `Run existing tests in sandbox\nCommand: ${formatValidatedCommand(command)}\nTimeout: ${command.timeoutMs}ms${files}${pattern}`;
    }
    const setupInfo = req.setupScript ? `\nSetup script: ${req.setupScript.length} bytes` : '';
    return `Run generated test script in sandbox\nRunner: ${req.runner}\nScript: ${req.script!.length} bytes (hash ${sha256Prefix(req.script!)})${setupInfo}\nTimeout: ${req.timeoutMs || DEFAULT_TIMEOUT_MS}ms`;
}

function buildOperationParts(req: RunTestsRequest, command?: ValidatedTestCommand): unknown[] {
    if (req.mode === 'existing' && command) {
        return [
            req.mode,
            command.executable,
            command.args,
            command.selectedFiles,
            req.testPattern,
            command.timeoutMs,
        ];
    }
    return [
        req.mode,
        req.runner,
        req.script ? sha256Prefix(req.script) : null,
        req.setupScript ? sha256Prefix(req.setupScript) : null,
        req.timeoutMs || DEFAULT_TIMEOUT_MS,
    ];
}

export async function runTests(
    req: RunTestsRequest,
    workspaceRoot: string,
    options?: {
        signal?: AbortSignal;
        sandboxBackend?: any;
        /** Skip approval — for agent executor internal use only when the broker is managed externally. */
        broker?: ApprovalBroker;
    },
): Promise<RunTestsResult> {
    const startTime = Date.now();
    const validation = validateRunTestsRequest(req, workspaceRoot);
    if (!validation.ok) {
        return {
            approved: false,
            mode: req.mode,
            status: 'denied',
            exitCode: -1,
            output: `Validation error: ${validation.error}`,
            durationMs: Date.now() - startTime,
        };
    }

    const command = validation.command;
    const summary = buildApprovalSummary(req, command);
    const operationParts = buildOperationParts(req, command);

    const ownsBroker = !options?.broker;
    const broker = options?.broker ?? new ApprovalBroker();
    if (ownsBroker) await broker.start();

    try {
        const approval = await broker.requestApproval(
            'securecode.run-tests',
            summary,
            operationParts,
            60_000,
        );

        if (!approval.approved) {
            return {
                approved: false,
                requestId: approval.requestId,
                mode: req.mode,
                status: 'denied',
                exitCode: -1,
                output: `Test execution ${approval.reason}.`,
                durationMs: Date.now() - startTime,
            };
        }

        let testResult: LocalTestResult;
        if (req.mode === 'existing' && command) {
            testResult = await runTestCommand(
                command.executable,
                command.args,
                workspaceRoot,
                {
                    timeoutMs: command.timeoutMs,
                    signal: options?.signal,
                    sandboxBackend: options?.sandboxBackend,
                },
            );
        } else {
            testResult = await runLocalTest(
                req.script!,
                req.runner!,
                workspaceRoot,
                {
                    setupScript: req.setupScript || null,
                    timeoutMs: req.timeoutMs || DEFAULT_TIMEOUT_MS,
                    signal: options?.signal,
                    sandboxBackend: options?.sandboxBackend,
                },
            );
        }

        return {
            approved: true,
            requestId: approval.requestId,
            mode: req.mode,
            status: mapVerdict(testResult.verdict),
            exitCode: testResult.exitCode,
            output: truncateOutput(testResult.output),
            backend: testResult.backend,
            command: command ? { executable: command.executable, args: command.args } : undefined,
            durationMs: Date.now() - startTime,
        };
    } finally {
        if (ownsBroker) await broker.stop();
    }
}
