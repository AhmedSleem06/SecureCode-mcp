/**
 * Capability registry — the dispatch point for tiered language support.
 *
 * Determines what analysis capabilities are available for each language:
 *   - Tier 1 ('deep'):     taint, AST, call graph, guards, policy, verify
 *   - Tier 2 ('standard'): AST, call graph, semgrep (no taint, no guard eval)
 *   - Tier 3 ('fallback'): LLM exploration only (read_file, search_code)
 *
 * The confidence clamper (agentScan.ts) consults this to decide whether a
 * finding's confidence should be penalized for not using structural tools.
 * If a capability is unavailable for the language, the agent can't be blamed
 * for not using it — but the confidence ceiling is lower overall.
 *
 * To promote a language to a higher tier, add its sinks/sources/sanitizers
 * and move it to the appropriate set below. The rest of the system adapts
 * automatically.
 */

export type CapabilityTier = 'deep' | 'standard' | 'fallback';

export interface LanguageCapability {
    language: string;
    tier: CapabilityTier;
    /** Taint tracking: trace_flow / trace_flow_cross_file */
    taint: boolean;
    /** Tree-sitter AST parsing available */
    ast: boolean;
    /** Call graph extraction available */
    callGraph: boolean;
    /** Guard function evaluation: check_guard */
    guardCheck: boolean;
    /** Endpoint policy checking: check_policy */
    policyCheck: boolean;
    /** Semgrep integration (Tier 2, not wired yet) */
    semgrep: boolean;
    /** Exploit verification via test execution: verify subagent */
    verify: boolean;
    /** Human-readable label for the UI */
    tierLabel: string;
}

const DEEP_LANGUAGES = new Set([
    'javascript', 'typescript', 'tsx', 'python',
]);

const STANDARD_LANGUAGES = new Set<string>([]);

const TIER_LABELS: Record<CapabilityTier, string> = {
    deep: 'Deep Analysis',
    standard: 'Advanced Analysis',
    fallback: 'Agent Analysis',
};

export function normalizeLanguage(language: string): string {
    const l = (language || '').toLowerCase();
    if (l === 'typescriptreact' || l === 'jsx') return 'tsx' in DEEP_LANGUAGES || 'tsx' in STANDARD_LANGUAGES ? 'tsx' : l;
    if (l === 'javascriptreact') return 'javascript';
    if (l === 'ts') return 'typescript';
    if (l === 'js') return 'javascript';
    if (l === 'py') return 'python';
    return l;
}

export function getCapability(language: string): LanguageCapability {
    const lang = normalizeLanguage(language);
    const tier: CapabilityTier = DEEP_LANGUAGES.has(lang)
        ? 'deep'
        : STANDARD_LANGUAGES.has(lang)
            ? 'standard'
            : 'fallback';

    return {
        language: lang,
        tier,
        taint: tier === 'deep',
        ast: tier === 'deep' || tier === 'standard',
        callGraph: tier === 'deep' || tier === 'standard',
        guardCheck: tier === 'deep',
        policyCheck: tier === 'deep',
        semgrep: tier === 'standard',
        verify: tier === 'deep',
        tierLabel: TIER_LABELS[tier],
    };
}

/**
 * Evidence level tag for a finding, based on what structural tools were
 * actually used during the investigation. The confidence clamper attaches
 * this to each finding so the UI can show how the confidence was derived.
 */
export function evidenceLevelTag(
    usedTaint: boolean,
    usedGuard: boolean,
    usedPolicy: boolean,
    verifyVerdict: string | undefined,
): string {
    const parts: string[] = [];
    if (usedTaint) parts.push('taint-traced');
    if (usedGuard) parts.push('guard-checked');
    if (usedPolicy) parts.push('policy-checked');
    if (verifyVerdict === 'PROVEN') parts.push('verified');
    else if (verifyVerdict === 'UNPROVEN') parts.push('verify-failed');
    else if (verifyVerdict === 'INCONCLUSIVE') parts.push('verify-inconclusive');
    else if (verifyVerdict === 'SKIPPED') parts.push('verify-skipped');
    if (parts.length === 0) return 'llm-only';
    return parts.join('+');
}
