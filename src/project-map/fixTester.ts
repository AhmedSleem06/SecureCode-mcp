/**
 * Phase H — Fix Regression Tester.
 *
 * Verifies that a fix doesn't break existing behavior or introduce new
 * vulnerabilities by running a differential analysis on the original and
 * fixed code.
 *
 * Algorithm:
 *   1. Syntax check: parse the fixed code — if it doesn't parse, syntaxValid = false
 *   2. Differential analysis: run the AST Sink Finder (Phase B) + Taint Tracker
 *      (Phase C) on both original and fixed code
 *      - Original had a tainted sink + fixed doesn't → fix is effective
 *      - Fixed code has a new tainted sink → newVulnerabilities
 *      - Fixed code has a new sink not in original → newVulnerabilities
 *   3. Functional regression: check if the fix changed the code structure
 *      in ways that could break behavior (removed functions, changed signatures)
 *
 * No runtime execution needed — the POC Executor (Phase F) handles that.
 * The fix tester is purely static: it compares the AST analysis results.
 */

import { parseSource } from './parserLoader';
import { findSinks, SinkFinding } from './sinkFinder';
import { trackTaint, TaintResult } from './taintTracker';
import type { SinkLanguage } from './sinkRegistry';

// ── Types ───────────────────────────────────────────────────────────────────

export interface FixTestResult {
    /** True if the fix passes all checks (syntax valid, no new vulns, effective). */
    passes: boolean;
    /** True if the fixed code parses without syntax errors. */
    syntaxValid: boolean;
    /** True if the fix actually removed the original vulnerability. */
    fixEffective: boolean;
    /** New vulnerabilities introduced by the fix. */
    newVulnerabilities: string[];
    /** Behavioral regressions detected (removed functions, changed signatures). */
    regressions: string[];
    /** Individual test results. */
    tests: { name: string; passed: boolean; error?: string }[];
}

export interface FixTestOptions {
    /** The canonical vulnerability type being fixed (e.g. 'sql_injection'). */
    vulnType?: string;
    /** The line of the original vulnerability. */
    vulnLine?: number;
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Extract function names from source code via AST walk. */
async function extractFunctionNames(
    source: string,
    language: SinkLanguage,
): Promise<Set<string>> {
    const parsed = await parseSource(source, language);
    if (!parsed) return new Set();
    const { root } = parsed;
    const names = new Set<string>();
    const { walk } = await import('./astHelpers');
    const FUNCTION_TYPES = new Set([
        'function_declaration', 'function_definition', 'method_definition',
        'async_function_declaration', 'async_function_definition',
    ]);
    for (const node of walk(root)) {
        if (FUNCTION_TYPES.has(node.type)) {
            const id = node.namedChildren.find(c => c.type === 'identifier');
            if (id) {
                const name = parsed.root.startIndex !== undefined
                    ? source.slice(id.startIndex, id.endIndex)
                    : '';
                if (name) names.add(name);
            }
        }
    }
    return names;
}

/** Compare sink findings between original and fixed code. */
function compareSinks(
    originalSinks: SinkFinding[],
    fixedSinks: SinkFinding[],
    vulnType?: string,
    vulnLine?: number,
): { removed: SinkFinding[]; added: SinkFinding[]; newVulns: string[] } {
    const removed: SinkFinding[] = [];
    const added: SinkFinding[] = [];
    const newVulns: string[] = [];

    // Sinks in original but not in fixed → removed (fix worked)
    for (const orig of originalSinks) {
        const stillExists = fixedSinks.some(
            f => f.line === orig.line && f.canonicalType === orig.canonicalType,
        );
        if (!stillExists) {
            removed.push(orig);
        }
    }

    // Sinks in fixed but not in original → new vulnerabilities
    for (const fixed of fixedSinks) {
        const existedBefore = originalSinks.some(
            o => o.line === fixed.line && o.canonicalType === fixed.canonicalType,
        );
        if (!existedBefore) {
            added.push(fixed);
            newVulns.push(`${fixed.canonicalType} at line ${fixed.line} (${fixed.sink})`);
        }
    }

    return { removed, added, newVulns };
}

/** Compare taint results between original and fixed code. */
function compareTaint(
    originalTaint: TaintResult[],
    fixedTaint: TaintResult[],
    vulnType?: string,
    vulnLine?: number,
): { fixedFlows: TaintResult[]; newFlows: TaintResult[] } {
    const fixedFlows: TaintResult[] = [];
    const newFlows: TaintResult[] = [];

    // Taint flows in original but not in fixed → fixed
    for (const orig of originalTaint) {
        const stillTainted = fixedTaint.some(
            f => f.source === orig.source && f.sink === orig.sink && f.sinkLine === orig.sinkLine,
        );
        if (!stillTainted) {
            fixedFlows.push(orig);
        }
    }

    // Taint flows in fixed but not in original → new vulns
    for (const fixed of fixedTaint) {
        const existedBefore = originalTaint.some(
            o => o.source === fixed.source && o.sink === fixed.sink && o.sinkLine === fixed.sinkLine,
        );
        if (!existedBefore) {
            newFlows.push(fixed);
        }
    }

    return { fixedFlows, newFlows };
}

// ── Main entry point ───────────────────────────────────────────────────────

/**
 * Test a fix by comparing the original and fixed code statically.
 *
 * @param originalCode  the original source code
 * @param fixedCode     the fixed source code
 * @param language      the source language
 * @param options       optional test options (vulnType, vulnLine)
 * @returns the test result
 */
export async function testFix(
    originalCode: string,
    fixedCode: string,
    language: SinkLanguage,
    options?: FixTestOptions,
): Promise<FixTestResult> {
    const tests: { name: string; passed: boolean; error?: string }[] = [];
    const newVulnerabilities: string[] = [];
    const regressions: string[] = [];

    // ── 1. Syntax check ─────────────────────────────────────────────────
    // Tree-sitter is error-recovery: it produces a parse tree even for
    // invalid syntax, inserting ERROR/MISSING nodes. We walk the tree to
    // detect these — parseSource returning non-null does NOT mean the
    // syntax is valid.
    let syntaxValid = true;
    try {
        const parsed = await parseSource(fixedCode, language);
        if (!parsed) {
            syntaxValid = false;
            tests.push({
                name: 'Syntax check',
                passed: false,
                error: 'Fixed code failed to parse (invalid syntax or unsupported language)',
            });
        } else {
            // Walk the tree looking for ERROR/MISSING nodes, and check the
            // root's hasError flag (tree-sitter sets this when error
            // recovery inserted ERROR/MISSING nodes during parsing).
            const { walk } = await import('./astHelpers');
            let hasError = (parsed.root as any).hasError === true;
            if (!hasError) {
                for (const node of walk(parsed.root)) {
                    if (node.type === 'ERROR' || node.type === 'error'
                        || node.type === 'MISSING' || node.type === 'missing') {
                        hasError = true;
                        break;
                    }
                }
            }
            if (hasError) {
                syntaxValid = false;
                tests.push({
                    name: 'Syntax check',
                    passed: false,
                    error: 'Fixed code contains syntax errors (detected ERROR nodes in AST)',
                });
            } else {
                tests.push({ name: 'Syntax check', passed: true });
            }
        }
    } catch (err: any) {
        syntaxValid = false;
        tests.push({
            name: 'Syntax check',
            passed: false,
            error: err.message,
        });
    }

    // If syntax is invalid, we can't do further analysis
    if (!syntaxValid) {
        return {
            passes: false,
            syntaxValid: false,
            fixEffective: false,
            newVulnerabilities: [],
            regressions: [],
            tests,
        };
    }

    // ── 2. Differential sink analysis ────────────────────────────────────
    let originalSinks: SinkFinding[] = [];
    let fixedSinks: SinkFinding[] = [];
    try {
        [originalSinks, fixedSinks] = await Promise.all([
            findSinks(originalCode, language),
            findSinks(fixedCode, language),
        ]);
    } catch (err: any) {
        tests.push({
            name: 'Differential sink analysis',
            passed: false,
            error: `Sink finder failed: ${err.message}`,
        });
    }

    if (originalSinks.length > 0 || fixedSinks.length > 0) {
        const { removed, added, newVulns } = compareSinks(
            originalSinks, fixedSinks, options?.vulnType, options?.vulnLine,
        );

        if (newVulns.length > 0) {
            newVulnerabilities.push(...newVulns);
            tests.push({
                name: 'No new sinks introduced',
                passed: false,
                error: `Fix introduced new sinks: ${newVulns.join(', ')}`,
            });
        } else {
            tests.push({ name: 'No new sinks introduced', passed: true });
        }

        if (removed.length > 0) {
            tests.push({
                name: 'Original sink removed',
                passed: true,
            });
        }
    }

    // ── 3. Differential taint analysis ────────────────────────────────────
    let originalTaint: TaintResult[] = [];
    let fixedTaint: TaintResult[] = [];
    try {
        [originalTaint, fixedTaint] = await Promise.all([
            trackTaint(originalCode, language),
            trackTaint(fixedCode, language),
        ]);
    } catch (err: any) {
        tests.push({
            name: 'Differential taint analysis',
            passed: false,
            error: `Taint tracker failed: ${err.message}`,
        });
    }

    if (originalTaint.length > 0 || fixedTaint.length > 0) {
        const { fixedFlows, newFlows } = compareTaint(
            originalTaint, fixedTaint, options?.vulnType, options?.vulnLine,
        );

        if (newFlows.length > 0) {
            newVulnerabilities.push(
                ...newFlows.map(f => `${f.canonicalType}: ${f.source} → ${f.sink} (line ${f.sinkLine})`),
            );
            tests.push({
                name: 'No new taint flows introduced',
                passed: false,
                error: `Fix introduced new taint flows: ${newFlows.length}`,
            });
        } else {
            tests.push({ name: 'No new taint flows introduced', passed: true });
        }

        if (fixedFlows.length > 0) {
            tests.push({
                name: 'Original taint flow eliminated',
                passed: true,
            });
        }
    }

    // ── 4. Function preservation check ──────────────────────────────────
    try {
        const [origFns, fixedFns] = await Promise.all([
            extractFunctionNames(originalCode, language),
            extractFunctionNames(fixedCode, language),
        ]);

        const removedFns = [...origFns].filter(fn => !fixedFns.has(fn));
        if (removedFns.length > 0) {
            regressions.push(`Functions removed: ${removedFns.join(', ')}`);
            tests.push({
                name: 'No functions removed',
                passed: false,
                error: `Removed: ${removedFns.join(', ')}`,
            });
        } else {
            tests.push({ name: 'No functions removed', passed: true });
        }
    } catch {
        // Best-effort: skip if function extraction fails
    }

    // ── 5. Determine if the fix is effective ─────────────────────────────
    let fixEffective = false;
    if (options?.vulnType) {
        // Check if the specific vulnerability was removed
        const hadVuln = originalSinks.some(s => s.canonicalType === options.vulnType)
            || originalTaint.some(t => t.canonicalType === options.vulnType);
        const stillHasVuln = fixedSinks.some(s => s.canonicalType === options.vulnType)
            || fixedTaint.some(t => t.canonicalType === options.vulnType);
        fixEffective = hadVuln && !stillHasVuln;
    } else {
        // No specific type: fix is effective if any sink/taint was removed
        fixEffective = originalSinks.length > fixedSinks.length
            || originalTaint.length > fixedTaint.length;
    }

    if (fixEffective) {
        tests.push({ name: 'Fix effective (vulnerability removed)', passed: true });
    } else if (options?.vulnType) {
        tests.push({
            name: 'Fix effective (vulnerability removed)',
            passed: false,
            error: `Original ${options.vulnType} vulnerability still present in fixed code`,
        });
    }

    // ── Final verdict ────────────────────────────────────────────────────
    const passes = syntaxValid
        && newVulnerabilities.length === 0
        && (fixEffective || !options?.vulnType);

    return {
        passes,
        syntaxValid,
        fixEffective,
        newVulnerabilities,
        regressions,
        tests,
    };
}
