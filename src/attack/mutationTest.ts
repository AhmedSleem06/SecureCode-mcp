import * as fs from 'fs';
import * as path from 'path';
import { runLocalTest } from '../utils/localTestRunner';
import { applyMutation, INVALID_MUTATION_DESCRIPTION, normalizeVulnerabilityType } from './mutationOperators';

export interface MutationTestOptions {
    /** The original vulnerable code (the code being tested). */
    vulnerableCode: string;
    /** The test script that should catch the vulnerability. */
    testScript: string;
    /** The runner to use (node, python3, etc.). */
    runner: string;
    /** Workspace root for the sandbox. */
    workspaceRoot: string;
    /** File path of the vulnerable code (absolute or workspace-relative). */
    filePath: string;
    /** Vulnerability type (broken_access_control, sql_injection, etc.). */
    vulnerabilityType: string;
    /** Line number of the vulnerability. */
    line: number;
    /** Import specifier the test script uses to load the vulnerable file. */
    relativeImportPath?: string;
    /** Setup script that ran before the original test. */
    setupScript?: string | null;
    timeoutMs?: number;
    signal?: AbortSignal;
}

export type MutationSkipCause =
    | 'no-operator'
    | 'import-not-found'
    | 'blocked'
    | 'sandbox-unavailable'
    | 'cancelled';

export interface MutationTestResult {
    discriminating: boolean;
    mutatedVerdict: 'pass' | 'fail' | 'error' | 'timeout' | 'not-run';
    reason: string;
    /** Why the mutation was not run. Set only when mutatedVerdict is 'not-run'. */
    skipCause?: MutationSkipCause;
}

const SOURCE_EXT_RE = /\.(ts|tsx|js|jsx|mjs|cjs|mts|cts|py)$/i;

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Rewrite every string-literal occurrence of the target import specifier
 * (with or without a source extension) so it points at the mutated file.
 * Returns null when the test script does not reference the specifier.
 */
export function redirectImportSpecifier(testScript: string, relativeImportPath: string, mutatedSpecifier: string): string | null {
    const base = relativeImportPath.replace(SOURCE_EXT_RE, '');
    const candidates = new Set([base]);
    if (base.startsWith('./')) candidates.add(base.slice(2));

    let rewritten = testScript;
    let replaced = false;
    for (const cand of candidates) {
        const re = new RegExp(`(['"\`])${escapeRegExp(cand)}(?:\\.(?:ts|tsx|js|jsx|mjs|cjs|mts|cts|py))?\\1`, 'g');
        rewritten = rewritten.replace(re, (_m, q: string) => {
            replaced = true;
            return `${q}${mutatedSpecifier}${q}`;
        });
    }
    return replaced ? rewritten : null;
}

const TREE_SITTER_FUNCTION_TYPES = new Set([
    'function_declaration', 'function_expression', 'function', 'arrow_function', 'method_definition',
    'generator_function_declaration', 'generator_function', 'class_static_block',
]);

/**
 * Count syntax problems (parse errors, missing tokens, `return` outside a
 * function) with tree-sitter. Returns null when the grammar is unavailable.
 */
export async function treeSitterSyntaxProblems(code: string, filePath: string): Promise<number | null> {
    const { parseSource, grammarForFile } = await import('../project-map/parserLoader');
    const grammar = grammarForFile(filePath);
    if (grammar === 'unknown' || grammar === 'python') return null;
    const parsed = await parseSource(code, grammar);
    if (!parsed) return null;
    let count = 0;
    const visit = (node: any, inFunction: boolean) => {
        const missing = typeof node.isMissing === 'function' ? node.isMissing() : node.isMissing;
        if (node.type === 'ERROR' || missing) count++;
        if (node.type === 'return_statement' && !inFunction) count++;
        const nested = inFunction || TREE_SITTER_FUNCTION_TYPES.has(node.type);
        for (const child of node.children) visit(child, nested);
    };
    visit(parsed.root, false);
    try { parsed.tree.delete(); } catch { /* best effort */ }
    return count;
}

const FS_BLOCKED_RE = /\b(ENOENT|EACCES|EPERM|ENOTDIR)\b/;

/**
 * Run a mutation test:
 *
 * 1. Apply a security mutation to the vulnerable code (e.g., add an auth guard).
 * 2. Write the mutated code next to the original file so its relative
 *    imports still resolve, and point the test script's import at it.
 * 3. Run the ORIGINAL test script against the mutated (secure) code.
 * 4. If the test PASSES on the original but FAILS on the mutation → discriminating.
 * 5. If the test PASSES on both → non-discriminating (the test doesn't test security).
 * 6. If the test ERRORS on the mutation → INCONCLUSIVE (not discriminating),
 *    except a path-traversal mutation whose run fails with a filesystem
 *    not-found/denied error: the fixed path no longer reaches the target.
 *
 * Never label mutation errors as successful discrimination.
 */
export async function runMutationTest(opts: MutationTestOptions): Promise<MutationTestResult> {
    const mutation = applyMutation(opts.vulnerableCode, opts.vulnerabilityType, opts.line, opts.filePath);

    if (!mutation.mutated) {
        return {
            discriminating: false,
            mutatedVerdict: 'not-run',
            reason: `Mutation test skipped: ${mutation.description}`,
            skipCause: 'no-operator',
        };
    }

    if (mutation.syntaxCheck === 'none' && opts.filePath) {
        const before = await treeSitterSyntaxProblems(opts.vulnerableCode, opts.filePath).catch(() => null);
        const after = before === null ? null : await treeSitterSyntaxProblems(mutation.mutatedCode, opts.filePath).catch(() => null);
        if (before !== null && after !== null && after > before) {
            return {
                discriminating: false,
                mutatedVerdict: 'not-run',
                reason: `Mutation test skipped: ${INVALID_MUTATION_DESCRIPTION}`,
                skipCause: 'no-operator',
            };
        }
    }

    const targetAbs = path.isAbsolute(opts.filePath)
        ? opts.filePath
        : path.join(opts.workspaceRoot, opts.filePath);
    const ext = path.extname(targetAbs) || (opts.runner === 'python3' || opts.runner === 'python' ? '.py' : '.js');
    const stem = path.basename(targetAbs, path.extname(targetAbs));
    const suffix = `${Date.now()}${Math.random().toString(36).slice(2, 6)}`;
    const mutatedName = `${stem}.__scmut_${suffix}${ext}`;
    const mutationFile = path.join(path.dirname(targetAbs), mutatedName);

    const importPath = opts.relativeImportPath || '';
    const importBase = importPath.replace(SOURCE_EXT_RE, '');
    const slash = importBase.lastIndexOf('/');
    const mutatedSpecifier = `${slash >= 0 ? importBase.slice(0, slash + 1) : ''}${mutatedName}`;
    const redirectedScript = importPath
        ? redirectImportSpecifier(opts.testScript, importPath, mutatedSpecifier)
        : null;

    if (!redirectedScript) {
        return {
            discriminating: false,
            mutatedVerdict: 'not-run',
            reason: importPath
                ? `Mutation test skipped: the test script does not import the target via "${importPath}", so it cannot be pointed at the mutated code.`
                : 'Mutation test skipped: no import path for the target file was provided.',
            skipCause: 'import-not-found',
        };
    }

    try {
        fs.writeFileSync(mutationFile, mutation.mutatedCode, 'utf8');

        const result = await runLocalTest(
            redirectedScript,
            opts.runner,
            opts.workspaceRoot,
            {
                setupScript: opts.setupScript ?? null,
                timeoutMs: opts.timeoutMs ?? 30_000,
                signal: opts.signal,
            },
        );

        if (result.verdict === 'pass') {
            return {
                discriminating: false,
                mutatedVerdict: 'pass',
                reason: `Mutation test PASSED — the test does not discriminate between vulnerable and secure code. ${mutation.description}. ${result.output.slice(0, 200)}`,
            };
        }

        if (result.verdict === 'fail') {
            return {
                discriminating: true,
                mutatedVerdict: 'fail',
                reason: `Mutation test FAILED — the test correctly discriminates: ${mutation.description}. ${result.output.slice(0, 200)}`,
            };
        }

        if (result.verdict === 'blocked' || result.verdict === 'sandbox-unavailable' || result.verdict === 'cancelled') {
            return {
                discriminating: false,
                mutatedVerdict: 'not-run',
                reason: `Mutation test not run (${result.verdict}): ${result.output.slice(0, 200)}`,
                skipCause: result.verdict,
            };
        }

        if (
            result.verdict === 'error' &&
            normalizeVulnerabilityType(opts.vulnerabilityType) === 'path_traversal' &&
            FS_BLOCKED_RE.test(result.output)
        ) {
            return {
                discriminating: true,
                mutatedVerdict: 'fail',
                reason: `Mutation test FAILED — attack blocked: the fixed code could not reach the file outside the base directory. ${mutation.description} ${result.output.slice(0, 200)}`,
            };
        }

        return {
            discriminating: false,
            mutatedVerdict: result.verdict === 'timeout' ? 'timeout' : 'error',
            reason: `Mutation test ${result.verdict === 'timeout' ? 'timed out' : 'errored'} — INCONCLUSIVE (not discriminating). ${mutation.description}. ${result.output.slice(0, 200)}`,
        };
    } catch (err: any) {
        return {
            discriminating: false,
            mutatedVerdict: 'error',
            reason: `Mutation test failed to execute: ${err.message || err}`,
        };
    } finally {
        try { fs.unlinkSync(mutationFile); } catch { /* best effort */ }
    }
}
