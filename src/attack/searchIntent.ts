/**
 * Search intent normalization — detects when two search_code calls are
 * semantically equivalent even if their patterns differ in ordering or
 * formatting.
 *
 * Without this, the agent can call:
 *   search_code("requireOwner|CurrentWsSessionRole")
 *   search_code("CurrentWsSessionRole|requireOwner")
 *   search_code("requireOwner|CurrentWsSessionRole|isLoopbackHost")
 * ...and each is treated as a "new" search because the raw strings differ.
 *
 * This module normalizes patterns into a canonical form and provides
 * overlap detection so the loop can block equivalent searches.
 */

export function normalizeSearchPattern(pattern: string): string {
    let p = pattern.trim();

    // Remove common regex wrappers that don't change intent
    p = p.replace(/^\(\?:|\)\$$/g, '');

    // Split on | (alternation) into alternatives
    const alternatives = p
        .split('|')
        .map(a => a.trim())
        .filter(a => a.length > 0);

    if (alternatives.length <= 1) {
        return p.toLowerCase();
    }

    // Sort alternatives alphabetically, deduplicate, lowercase
    const unique = [...new Set(alternatives.map(a => a.toLowerCase()))];
    unique.sort();
    return unique.join('|');
}

export function isEquivalentSearchIntent(previous: string, current: string): boolean {
    const prevNorm = normalizeSearchPattern(previous);
    const currNorm = normalizeSearchPattern(current);

    if (prevNorm === currNorm) return true;

    // Check if one is a subset of the other (all alternatives of the
    // smaller pattern are present in the larger one)
    const prevTerms = prevNorm.split('|').filter(t => t.length > 0);
    const currTerms = currNorm.split('|').filter(t => t.length > 0);

    const prevSet = new Set(prevTerms);
    const currSet = new Set(currTerms);

    // If current is a subset of previous, it's equivalent (already searched)
    const currSubsetOfPrev = [...currSet].every(t => prevSet.has(t));
    if (currSubsetOfPrev) return true;

    // If previous is a subset of current, the current adds nothing new
    const prevSubsetOfCurr = [...prevSet].every(t => currSet.has(t));
    if (prevSubsetOfCurr) return true;

    return false;
}
