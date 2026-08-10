/**
 * Phase 4 — confidence scoring + runtime-confirmed upgrade.
 *
 * Centralizes the README's confidence model so Layer 1, Layer 2, the
 * runtime trace merger, and the cache all share one definition.
 *
 * 1.0  — STATIC_LITERAL      (string-literal path, directly-registered middleware)
 * 0.8  — RUNTIME_CONFIRMED   (trace hook observed the relationship)
 * 0.6  — INTRA_FILE_DATAFLOW (resolved from a same-file const/variable)
 * 0.2  — UNRESOLVED          (could not statically resolve; not yet traced)
 * 0.15 — META_PROGRAMMING    (new Function / vm.runIn* / dynamic require)
 * 0.1  — FULLY_UNRESOLVED    (no usable evidence)
 * 0.0  — DYNAMIC_PATTERN     (D1-D10 flagged but un-confirmed)
 */

import { Confidence, EndpointRecord, MiddlewareEntry } from './types';

/**
 * Pick the lowest confidence among the evidence gathered for the record.
 *
 * `pathConfidence` counts as evidence: a route registered at a string-literal
 * path is well-understood even if it has no middleware, params or calls.
 *
 * A record with NO evidence at all — nothing resolved about the path and no
 * relationships — scores FULLY_UNRESOLVED. Scoring it STATIC_LITERAL would
 * report maximum certainty about an endpoint we know nothing about, and this
 * value travels into EndpointContext and on to the AI scan stages.
 */
export function aggregateConfidence(record: EndpointRecord): number {
    const cs: number[] = [];
    if (typeof record.pathConfidence === 'number') cs.push(record.pathConfidence);
    for (const m of record.middleware) cs.push(m.confidence);
    for (const p of record.params) cs.push(p.confidence);
    for (const c of record.callGraph) cs.push(c.confidence);
    if (cs.length === 0) return Confidence.FULLY_UNRESOLVED;
    return Math.min(...cs);
}

/**
 * Map a Layer 2 pattern type to the META_PROGRAMMING confidence the
 * record gets if that pattern is the only evidence for a relationship.
 * (D1-D10 all start at 0.0; once a runtime trace confirms them, they
 * jump to 0.8.)
 */
export function patternMetaConfidence(_patternType: string): number {
    return Confidence.META_PROGRAMMING;
}

/**
 * Upgrade a record's confidence after a runtime trace confirms it.
 * Per the README: confirmed-but-previously-unresolved entries go 0.2 -> 0.8.
 * Records that were META_PROGRAMMING (0.15) also upgrade to 0.8 on confirmation.
 *
 * Absence of evidence (trace ran, endpoint not hit) does NOT downgrade —
 * the spec is explicit: we leave confidence low, we don't mark "absent".
 */
export function applyRuntimeConfirmation(record: EndpointRecord): EndpointRecord {
    const upgraded: EndpointRecord = {
        ...record,
        runtimeConfirmed: true,
        middleware: record.middleware.map(m =>
            m.confidence === Confidence.UNRESOLVED || m.confidence === Confidence.META_PROGRAMMING
                ? { ...m, confidence: Confidence.RUNTIME_CONFIRMED }
                : m
        ),
    };
    upgraded.confidence = aggregateConfidence(upgraded);
    return upgraded;
}

/**
 * Cross-file middleware resolution: given a middleware entry whose
 * sourceFile is unknown (because the import was dynamic or unresolvable),
 * set it to UNRESOLVED confidence. Used by the builder when an import
 * could not be resolved to a file.
 */
export function markUnresolved(entry: MiddlewareEntry): MiddlewareEntry {
    if (entry.sourceFile === '' || entry.sourceFile === '?') {
        return { ...entry, sourceFile: '', confidence: Confidence.UNRESOLVED };
    }
    return entry;
}
