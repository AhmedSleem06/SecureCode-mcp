/**
 * MCP-side runtime validation of API responses.
 *
 * The API is a trusted service we control, but the wire is untrusted: a
 * misconfigured proxy, a response from a stale API version, or a
 * man-in-the-middle on an unencrypted hop could deliver a malformed
 * response that the MCP would otherwise execute as ground truth. The
 * previous code fed `stepResp.next` directly into `executeAction`'s
 * switch — an unknown action type fell through to a no-op, and a
 * malformed action would either crash or silently produce bad state.
 *
 * This module validates the shape of:
 *   - AgentScanStartResponse
 *   - AgentScanStepResponse (and the embedded AgentScanAction)
 *   - AgentScanToolResponse
 *   - VerifyGenerateResponse (POST /verify/generate)
 *   - VerifyAnalyzeResponse (POST /verify/analyze)
 *
 * On validation failure, the caller treats it as a controlled `spawn_failed`
 * or `degraded` result rather than executing the malformed action.
 *
 * Validation is strict-by-default: unknown fields are ignored (forward-
 * compatible), but required fields and type constraints are enforced.
 * Findings are NOT validated here — the agent loop owns finding validation
 * (validateFinish); we only validate the wire envelope and the action
 * discriminator.
 */

import type {
    AgentScanAction,
    AgentScanStartResponse,
    AgentScanStepResponse,
    AgentScanToolResponse,
} from '../attack/agentScanProtocol';
import type { VerifyGenerateResponse, VerifyAnalyzeResponse } from '../api/types';

export interface ValidationOk<T> { ok: true; value: T; }
export interface ValidationErr { ok: false; error: string; }
export type ValidationResult<T> = ValidationOk<T> | ValidationErr;

function ok<T>(value: T): ValidationOk<T> { return { ok: true, value }; }
function err(error: string): ValidationErr { return { ok: false, error }; }

function isObject(x: unknown): x is Record<string, unknown> {
    return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function isString(x: unknown): x is string { return typeof x === 'string'; }
function isNumber(x: unknown): x is number { return typeof x === 'number' && Number.isFinite(x); }
function isBool(x: unknown): x is boolean { return typeof x === 'boolean'; }
function isOptionalString(x: unknown): x is string | undefined { return x === undefined || x === null || isString(x); }
function isOptionalNumber(x: unknown): x is number | undefined { return x === undefined || x === null || isNumber(x); }

// ── Action validation ───────────────────────────────────────────────────────

const VALID_ACTION_TYPES = new Set([
    'read_file', 'search_code', 'trace_flow', 'trace_flow_cross_file',
    'check_guard', 'check_policy', 'get_endpoints', 'list_imports',
    'list_files', 'call_graph', 'git_blame', 'git_history', 'git_diff',
    'check_dependencies', 'read_config', 'find_definition',
    'find_references', 'find_tests', 'run_tests',
    'finish', 'system_event',
]);

const VALID_ATTACK_TYPES = new Set([
    'sql_injection', 'nosql_injection', 'command_injection', 'xss', 'ssrf',
    'path_traversal', 'open_redirect', 'prototype_pollution',
    'insecure_deserialization', 'broken_access_control',
]);

const VALID_SYSTEM_EVENT_TYPES = new Set(['critique', 'error', 'blocked', 'budget']);
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);

/**
 * Validate an AgentScanAction. Returns the action typed, or an error.
 * Does NOT validate finish.findings deeply — the API's parseAction +
 * validateFinish already did that. We only check the discriminator and
 * the primary fields the MCP executor needs.
 */
export function validateAction(raw: unknown): ValidationResult<AgentScanAction> {
    if (!isObject(raw)) return err('action is not an object');
    const type = raw.type;
    if (!isString(type) || !VALID_ACTION_TYPES.has(type)) {
        return err(`action.type is missing or unknown: ${String(type)}`);
    }

    switch (type) {
        case 'read_file': {
            if (!isString(raw.path) || raw.path.length === 0) {
                return err('read_file requires non-empty string "path"');
            }
            if (!isOptionalNumber(raw.startLine) || !isOptionalNumber(raw.endLine)) {
                return err('read_file startLine/endLine must be numbers or null');
            }
            return ok(raw as unknown as AgentScanAction);
        }
        case 'search_code': {
            if (!isString(raw.pattern) || raw.pattern.length === 0) {
                return err('search_code requires non-empty string "pattern"');
            }
            if (!isOptionalString(raw.glob)) return err('search_code glob must be string or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'trace_flow': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) {
                return err('trace_flow requires non-empty string "filePath"');
            }
            return ok(raw as unknown as AgentScanAction);
        }
        case 'trace_flow_cross_file': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) {
                return err('trace_flow_cross_file requires non-empty string "filePath"');
            }
            if (!isOptionalNumber(raw.maxDepth)) return err('maxDepth must be a number or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'check_guard': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('check_guard requires "filePath"');
            if (!isString(raw.guardName) || raw.guardName.length === 0) return err('check_guard requires "guardName"');
            if (!isString(raw.attackType) || !VALID_ATTACK_TYPES.has(raw.attackType)) {
                return err(`check_guard attackType is not a known AttackType: ${String(raw.attackType)}`);
            }
            return ok(raw as unknown as AgentScanAction);
        }
        case 'check_policy': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('check_policy requires "filePath"');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'get_endpoints': {
            if (!isOptionalString(raw.glob)) return err('get_endpoints glob must be string or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'list_imports': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('list_imports requires "filePath"');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'list_files': {
            if (!isOptionalString(raw.path)) return err('list_files path must be string or null');
            if (!isOptionalString(raw.glob)) return err('list_files glob must be string or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'call_graph': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('call_graph requires "filePath"');
            if (!isOptionalString(raw.functionName)) return err('call_graph functionName must be string or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'git_blame': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('git_blame requires "filePath"');
            if (!isOptionalNumber(raw.startLine)) return err('git_blame startLine must be number or null');
            if (!isOptionalNumber(raw.endLine)) return err('git_blame endLine must be number or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'git_history': {
            if (!isOptionalString(raw.filePath)) return err('git_history filePath must be string or null');
            if (!isOptionalString(raw.functionName)) return err('git_history functionName must be string or null');
            if (!isOptionalNumber(raw.limit)) return err('git_history limit must be number or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'git_diff': {
            if (!isString(raw.baseRef) || raw.baseRef.length === 0) return err('git_diff requires non-empty "baseRef"');
            if (!isOptionalString(raw.headRef)) return err('git_diff headRef must be string or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'check_dependencies':
            return ok(raw as unknown as AgentScanAction);
        case 'read_config': {
            if (!isString(raw.configKind) || !['auth','cors','rate_limit','headers','env','all'].includes(raw.configKind)) {
                return err('read_config requires "configKind" (auth, cors, rate_limit, headers, env, all)');
            }
            return ok(raw as unknown as AgentScanAction);
        }
        case 'find_definition': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('find_definition requires "filePath"');
            if (!isString(raw.symbol) || raw.symbol.length === 0) return err('find_definition requires "symbol"');
            if (!isOptionalNumber(raw.line)) return err('find_definition line must be number or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'find_references': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('find_references requires "filePath"');
            if (!isString(raw.symbol) || raw.symbol.length === 0) return err('find_references requires "symbol"');
            if (!isOptionalNumber(raw.line)) return err('find_references line must be number or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'find_tests': {
            if (!isString(raw.filePath) || raw.filePath.length === 0) return err('find_tests requires "filePath"');
            if (!isOptionalString(raw.symbol)) return err('find_tests symbol must be string or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'run_tests': {
            if (!isString(raw.mode) || (raw.mode !== 'existing' && raw.mode !== 'generated')) {
                return err('run_tests requires "mode" (existing or generated)');
            }
            if (raw.mode === 'existing') {
                if (raw.testFiles !== undefined && raw.testFiles !== null) {
                    if (!Array.isArray(raw.testFiles)) return err('run_tests testFiles must be an array');
                }
                if (!isOptionalString(raw.testPattern)) return err('run_tests testPattern must be string or null');
                if (!isOptionalString(raw.packageManager)) return err('run_tests packageManager must be string or null');
            } else {
                if (!isString(raw.script) || raw.script.length === 0) return err('run_tests generated mode requires "script"');
                if (!isString(raw.runner) || raw.runner.length === 0) return err('run_tests generated mode requires "runner"');
                if (!isOptionalString(raw.setupScript)) return err('run_tests setupScript must be string or null');
            }
            if (!isOptionalNumber(raw.timeoutMs)) return err('run_tests timeoutMs must be number or null');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'finish': {
            if (!Array.isArray(raw.findings)) return err('finish requires "findings" array');
            // Light per-finding check: line must be a positive int, type must be non-empty, severity must be valid.
            for (let i = 0; i < raw.findings.length; i++) {
                const f = raw.findings[i];
                if (!isObject(f)) return err(`finding[${i}] is not an object`);
                if (!isNumber(f.line) || f.line < 1) return err(`finding[${i}].line must be a positive integer`);
                if (!isString(f.type) || f.type.length === 0) return err(`finding[${i}].type must be a non-empty string`);
                if (!isString(f.severity) || !VALID_SEVERITIES.has(f.severity)) {
                    return err(`finding[${i}].severity must be one of critical|high|medium|low`);
                }
                if (!isNumber(f.confidence) || f.confidence < 0 || f.confidence > 100) {
                    return err(`finding[${i}].confidence must be 0-100`);
                }
            }
            if (!isString(raw.summary)) return err('finish requires "summary" string');
            return ok(raw as unknown as AgentScanAction);
        }
        case 'system_event': {
            if (!isString(raw.eventType) || !VALID_SYSTEM_EVENT_TYPES.has(raw.eventType)) {
                return err(`system_event.eventType is missing or unknown: ${String(raw.eventType)}`);
            }
            if (!isString(raw.message) || raw.message.length === 0) {
                return err('system_event requires non-empty "message"');
            }
            return ok(raw as unknown as AgentScanAction);
        }
        default:
            return err(`unhandled action type: ${type}`);
    }
}

// ── Start response ──────────────────────────────────────────────────────────

export function validateStartResponse(raw: unknown): ValidationResult<AgentScanStartResponse> {
    if (!isObject(raw)) return err('start response is not an object');
    if (!isString(raw.runId) || raw.runId.length === 0) return err('start response missing runId');
    if (!isObject(raw.budget)) return err('start response missing budget');
    if (!isNumber(raw.budget.stepsRemaining)) return err('budget.stepsRemaining must be a number');
    if (!isNumber(raw.budget.costSpentUsd)) return err('budget.costSpentUsd must be a number');
    if (!isNumber(raw.budget.costCapUsd)) return err('budget.costCapUsd must be a number');
    if (!isString(raw.refundId) || raw.refundId.length === 0) return err('start response missing refundId');
    // scanCredits optional but if present must be a number
    if (raw.scanCredits !== undefined && !isNumber(raw.scanCredits)) return err('scanCredits must be a number');
    return ok(raw as unknown as AgentScanStartResponse);
}

// ── Step response ───────────────────────────────────────────────────────────

export function validateStepResponse(raw: unknown): ValidationResult<AgentScanStepResponse> {
    if (!isObject(raw)) return err('step response is not an object');
    // next may be null or an action.
    if (raw.next !== null && raw.next !== undefined) {
        const actionResult = validateAction(raw.next);
        if (!actionResult.ok) return err(`step response next: ${actionResult.error}`);
    }
    if (!isNumber(raw.costUsd)) return err('step response costUsd must be a number');
    if (!isNumber(raw.tokens)) return err('step response tokens must be a number');
    if (!isBool(raw.degraded)) return err('step response degraded must be a boolean');
    if (!isBool(raw.costCapped)) return err('step response costCapped must be a boolean');
    if (!isNumber(raw.stepsRemaining)) return err('step response stepsRemaining must be a number');

    // systemEvent optional; if present must be a valid system_event action.
    if (raw.systemEvent !== undefined && raw.systemEvent !== null) {
        const evResult = validateAction(raw.systemEvent);
        if (!evResult.ok) return err(`step response systemEvent: ${evResult.error}`);
        // Additionally, systemEvent must actually be a system_event (not some other action type).
        if (!isObject(raw.systemEvent) || raw.systemEvent.type !== 'system_event') {
            return err('step response systemEvent must have type "system_event"');
        }
    }
    return ok(raw as unknown as AgentScanStepResponse);
}

// ── Tool response ────────────────────────────────────────────────────────────

export function validateToolResponse(raw: unknown): ValidationResult<AgentScanToolResponse> {
    if (!isObject(raw)) return err('tool response is not an object');
    if (!isString(raw.observation)) return err('tool response observation must be a string');
    // Cap observation length so a compromised API can't blow out the transcript.
    const MAX_OBS = 64 * 1024;
    if (raw.observation.length > MAX_OBS) {
        // Truncate rather than reject — the observation is still useful.
        (raw as any).observation = (raw as any).observation.slice(0, MAX_OBS) + '… [truncated by MCP validator]';
    }
    return ok(raw as unknown as AgentScanToolResponse);
}

// ── Verify generate response ───────────────────────────────────────────────
//
// POST /verify/generate returns a test script + runner for local execution.
// The MCP feeds testScript directly into the sandbox, so a malformed response
// can cause unsafe or broken execution. Validate before use.

const VALID_VERIFY_RUNNERS = new Set([
    'node', 'tsx', 'bun', 'deno', 'python', 'python3',
    'pnpm-tsx', 'yarn-tsx',
]);

const MAX_TEST_SCRIPT_BYTES = 64 * 1024;
const MAX_SETUP_SCRIPT_BYTES = 32 * 1024;

export function validateVerifyGenerateResponse(raw: unknown): ValidationResult<VerifyGenerateResponse> {
    if (!isObject(raw)) return err('verify generate response is not an object');
    if (!isBool(raw.canTest)) return err('verify generate response canTest must be a boolean');

    if (raw.canTest) {
        if (!isString(raw.testScript) || raw.testScript.length === 0) {
            return err('verify generate response: canTest=true requires non-empty "testScript"');
        }
        if (raw.testScript.length > MAX_TEST_SCRIPT_BYTES) {
            return err(`verify generate response: testScript too large (${raw.testScript.length} > ${MAX_TEST_SCRIPT_BYTES})`);
        }
        if (!isString(raw.runner) || raw.runner.length === 0) {
            return err('verify generate response: canTest=true requires "runner"');
        }
        if (!VALID_VERIFY_RUNNERS.has(raw.runner)) {
            return err(`verify generate response: runner "${raw.runner}" is not supported (valid: ${[...VALID_VERIFY_RUNNERS].join(', ')})`);
        }
    } else {
        if (!isString(raw.skipReason) || raw.skipReason.length === 0) {
            return err('verify generate response: canTest=false requires non-empty "skipReason"');
        }
    }

    if (raw.setupScript !== undefined && raw.setupScript !== null) {
        if (!isString(raw.setupScript)) return err('verify generate response: setupScript must be a string or null');
        if (raw.setupScript.length > MAX_SETUP_SCRIPT_BYTES) {
            return err(`verify generate response: setupScript too large (${raw.setupScript.length} > ${MAX_SETUP_SCRIPT_BYTES})`);
        }
    }

    if (raw.description !== undefined && raw.description !== null) {
        if (!isString(raw.description)) return err('verify generate response: description must be a string or null');
    }

    if (raw.scanCredits !== undefined && raw.scanCredits !== null) {
        if (!isNumber(raw.scanCredits)) return err('verify generate response: scanCredits must be a number or null');
    }

    if (raw.costUsd !== undefined && raw.costUsd !== null) {
        if (!isNumber(raw.costUsd)) return err('verify generate response: costUsd must be a number or null');
    }

    return ok(raw as unknown as VerifyGenerateResponse);
}

// ── Verify analyze response ────────────────────────────────────────────────
//
// POST /verify/analyze returns a verdict (PROVEN/UNPROVEN/INCONCLUSIVE),
// a reason string, and a shouldRetry flag. The verify loop uses shouldRetry
// to decide whether to generate another test. A malformed response can cause
// infinite retries or a wrong verdict.

const VALID_VERIFY_VERDICTS = new Set(['PROVEN', 'UNPROVEN', 'INCONCLUSIVE']);

export function validateVerifyAnalyzeResponse(raw: unknown): ValidationResult<VerifyAnalyzeResponse> {
    if (!isObject(raw)) return err('verify analyze response is not an object');
    if (!isString(raw.verdict) || !VALID_VERIFY_VERDICTS.has(raw.verdict)) {
        return err(`verify analyze response: verdict must be one of PROVEN|UNPROVEN|INCONCLUSIVE, got "${String(raw.verdict)}"`);
    }
    if (!isString(raw.reason) || raw.reason.length === 0) {
        return err('verify analyze response: reason must be a non-empty string');
    }
    if (!isBool(raw.shouldRetry)) return err('verify analyze response: shouldRetry must be a boolean');

    // PROVEN and UNPROVEN are definitive — retrying makes no sense.
    if ((raw.verdict === 'PROVEN' || raw.verdict === 'UNPROVEN') && raw.shouldRetry === true) {
        return err(`verify analyze response: verdict "${raw.verdict}" cannot have shouldRetry=true (definitive verdict)`);
    }

    if (raw.scanCredits !== undefined && raw.scanCredits !== null) {
        if (!isNumber(raw.scanCredits)) return err('verify analyze response: scanCredits must be a number or null');
    }

    if (raw.costUsd !== undefined && raw.costUsd !== null) {
        if (!isNumber(raw.costUsd)) return err('verify analyze response: costUsd must be a number or null');
    }

    return ok(raw as unknown as VerifyAnalyzeResponse);
}
