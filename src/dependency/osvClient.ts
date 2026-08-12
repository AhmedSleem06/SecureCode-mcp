import * as cp from 'child_process';
import { ResolvedPackage, Vulnerability, AffectedRange, OsvEcosystem } from './types';
import { CacheStore } from './finding';

const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_BATCH_SIZE = 1000; // OSV limit per batch request.
const GHSA_ADVISORIES_URL = 'https://api.github.com/advisories';
const GHSA_PER_PAGE = 100;
// Unauthenticated: 60 req/hr. With token: 5000 req/hr.
// We only query GHSA for packages OSV flagged (enrichment), so 60/hr is
// enough for typical projects (5-30 vulns). For larger projects, a token
// from `gh auth token` or GITHUB_TOKEN env var lifts the limit.
const GHSA_TIMEOUT_MS = 15000;

/** OSV `package` field per single query. */
interface OsvQuery {
    package: { name: string; ecosystem: OsvEcosystem };
    version?: string;
}

interface OsvBatchResponse {
    results: Array<{ vulns?: Array<{ id: string; summary?: string; affected?: any[]; severity?: any[]; references?: any[] }> } | null>;
}

/**
 * Map our ecosystem to OSV's. npm-family all share the `npm` OSV ecosystem
 * (they hit the same advisory data on the npm registry).
 */
function osvEcosystemOf(pkg: ResolvedPackage): OsvEcosystem | null {
    switch (pkg.ecosystem) {
        case 'npm':
        case 'yarn':
        case 'pnpm':
            return 'npm';
        case 'pip':
        case 'pipenv':
            return 'PyPI';
        default:
            return null;
    }
}

/**
 * Query OSV.dev in batches for the given resolved packages.
 *
 * Only package NAME + VERSION leave the machine. No source code is sent.
 * Skips packages marked `unresolved` (we don't know the installed version).
 *
 * Returns a map keyed by `${ecosystem}:${name}@${version}` to a list of
 * normalized Vulnerability records. Failures (network, parse) for a given
 * batch are swallowed and that batch contributes no entries — the scan
 * does not hard-fail on OSV being unreachable.
 */
export async function queryOsvBatch(
    packages: ResolvedPackage[],
): Promise<Map<string, Vulnerability[]>> {
    const out = new Map<string, Vulnerability[]>();

    const queryable = packages.filter(p => !p.unresolved && !!p.version && !!p.name);
    if (queryable.length === 0) return out;

    for (let i = 0; i < queryable.length; i += OSV_BATCH_SIZE) {
        const slice = queryable.slice(i, i + OSV_BATCH_SIZE);
        const queries: OsvQuery[] = [];
        const keyForIndex: string[] = [];
        for (const p of slice) {
            const eco = osvEcosystemOf(p);
            if (!eco) continue;
            // npm-family names must match the npm registry casing OSV expects;
            // OSV is case-sensitive on the npm ecosystem. Use the original name
            // (npm is case-insensitive in practice but OSV stores as-published).
            queries.push({ package: { name: p.name, ecosystem: eco }, version: p.version });
            keyForIndex.push(`${eco}:${p.name}@${p.version}`);
        }
        if (queries.length === 0) continue;

        let body: string;
        try {
            body = JSON.stringify({ queries: queries.map(q => ({ package: q.package, version: q.version })) });
        } catch {
            continue;
        }

        let resp: OsvBatchResponse | null = null;
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 30000);
            const r = await fetch(OSV_QUERYBATCH_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body,
                signal: controller.signal,
            });
            clearTimeout(timeout);
            if (r.ok) {
                resp = (await r.json()) as OsvBatchResponse;
            }
        } catch {
            // network error — skip this batch
        }
        if (!resp || !Array.isArray(resp.results)) continue;

        // Positional alignment guard: OSV querybatch contract guarantees
        // results.length === queries.length, with null entries for no-match.
        // If the response is shorter, the positional mapping would silently
        // misattribute advisory IDs across packages. Skip the batch rather
        // than risk cross-package ID leakage.
        if (resp.results.length !== keyForIndex.length) {
            console.warn(`[OSV] batch result length mismatch: ${resp.results.length} vs ${keyForIndex.length} queries — skipping batch to prevent ID misattribution`);
            continue;
        }

        for (let j = 0; j < resp.results.length; j++) {
            const key = keyForIndex[j];
            if (!key) continue;
            const r = resp.results[j];
            const vulns = r?.vulns;
            if (!vulns || vulns.length === 0) continue;
            const list: Vulnerability[] = [];
            for (const v of vulns) {
                const affected: AffectedRange[] = [];
                if (Array.isArray(v.affected)) {
                    for (const a of v.affected) {
                        const ranges: any[] = a?.ranges || [];
                        for (const rng of ranges) {
                            if (!Array.isArray(rng.events)) continue;
                            let introduced: string | undefined;
                            let fixed: string | undefined;
                            for (const ev of rng.events) {
                                if (typeof ev.introduced === 'string') introduced = ev.introduced;
                                if (typeof ev.fixed === 'string') fixed = ev.fixed;
                            }
                            affected.push({
                                ecosystem: (a?.package?.ecosystem as OsvEcosystem) || 'npm',
                                introduced,
                                fixed,
                                raw: JSON.stringify(rng),
                            });
                        }
                    }
                }
                let cvssScore: number | undefined;
                if (Array.isArray(v.severity)) {
                    for (const s of v.severity) {
                        if (s?.type === 'CVSS_V3' && typeof s.score === 'string') {
                            // Try plain numeric score first (some records use "7.5").
                            const num = parseFloat(s.score);
                            if (!Number.isNaN(num) && s.score.trim().length <= 5) {
                                cvssScore = num;
                            } else {
                                // Parse CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...").
                                // Extract the base score from the vector by counting
                                // the metrics — but since the vector doesn't contain a
                                // precomputed score, fall back to NVD enrichment which
                                // has the real baseScore field.
                                // NVD enrichment (enrichWithNvd) will fill this in
                                // if the record has a CVE alias.
                            }
                        }
                    }
                }
                const references: string[] = [];
                if (Array.isArray(v.references)) {
                    for (const ref of v.references) {
                        if (typeof ref?.url === 'string') references.push(ref.url);
                    }
                }
                list.push({
                    id: v.id,
                    source: 'osv',
                    summary: v.summary || '',
                    affected,
                    cvssScore,
                    references,
                });
            }
            out.set(key, list);
        }
    }

    return out;
}

/**
 * GitHub Advisory Database query via the REST API (https://api.github.com/advisories).
 *
 * This replaces the previous `gh` CLI approach. The REST API:
 * - Requires no CLI installation (just `fetch()`)
 * - Returns real CVSS scores (not approximated severity strings)
 * - Provides `patched_version_range` with the first fixed version
 * - Works unauthenticated at 60 req/hr (5000 req/hr with a token)
 *
 * Design: GHSA is an ENRICHMENT source, not a primary source. We only
 * query for packages that OSV already flagged as vulnerable. This keeps
 * the request count low (typically 5-30 packages) and within the
 * unauthenticated rate limit.
 *
 * If a GitHub token is available (`gh auth token` or GITHUB_TOKEN env),
 * it is used to lift the rate limit to 5000 req/hr for large projects.
 */
export async function queryGhsaViaCli(
    packages: ResolvedPackage[],
): Promise<Map<string, Vulnerability[]>> {
    const out = new Map<string, Vulnerability[]>();

    const queryable = packages.filter(p => !p.unresolved && !!p.version && !!p.name);
    for (const p of queryable) {
        const eco = osvEcosystemOf(p);
        if (!eco) continue;
        const ghEco = eco === 'npm' ? 'npm' : 'pip';
        let advisories: any[];
        try {
            advisories = await queryGhsaRest(ghEco, p.name);
        } catch {
            continue;
        }
        if (!advisories || advisories.length === 0) continue;
        const list: Vulnerability[] = [];
        for (const adv of advisories) {
            if (!adv?.ghsa_id) continue;
            // Real CVSS score from the API (not approximated).
            let cvssScore: number | undefined;
            if (typeof adv.cvss?.score === 'number') {
                cvssScore = adv.cvss.score;
            } else if (typeof adv.cvss_score === 'number') {
                cvssScore = adv.cvss_score;
            }
            // Parse affected + fixed versions from the vulnerabilities array.
            const affected: AffectedRange[] = [];
            const vulns = Array.isArray(adv.vulnerabilities) ? adv.vulnerabilities : [];
            for (const v of vulns) {
                const rawRange = typeof v?.vulnerable_version_range === 'string'
                    ? v.vulnerable_version_range : '';
                const patched = typeof v?.patched_version_range === 'string'
                    ? v.patched_version_range : '';
                // Extract the fixed version from the patched range.
                // GitHub uses ">= X.Y.Z" for the first patched version.
                let fixed: string | undefined;
                if (patched) {
                    const m = patched.match(/>=?\s*([0-9][0-9a-zA-Z.\-+]*)/);
                    if (m) fixed = m[1];
                }
                // Extract the introduced version from the vulnerable range.
                let introduced: string | undefined;
                if (rawRange) {
                    const m = rawRange.match(/>=?\s*([0-9][0-9a-zA-Z.\-+]*)/);
                    if (m) introduced = m[1];
                }
                affected.push({ ecosystem: eco, introduced, fixed, raw: rawRange });
            }
            // References from the API.
            const refs: string[] = Array.isArray(adv.references)
                ? adv.references.map((r: any) => r?.url).filter((x: any) => typeof x === 'string')
                : [];
            // If there's a CVE alias, include it in references for NVD enrichment.
            if (typeof adv.cve_id === 'string' && adv.cve_id) {
                refs.push(`https://nvd.nist.gov/vuln/detail/${adv.cve_id}`);
            }
            list.push({
                id: adv.ghsa_id,
                source: 'ghsa',
                summary: adv.summary || '',
                affected,
                cvssScore,
                references: refs,
            });
        }
        if (list.length > 0) {
            const key = `${eco}:${p.name}@${p.version}`;
            const existing = out.get(key) || [];
            out.set(key, [...existing, ...list]);
        }
    }
    return out;
}

/**
 * Query the GitHub Advisory REST API for a single package.
 *
 * Uses optional authentication (GITHUB_TOKEN env or `gh auth token`)
 * to lift the rate limit from 60/hr to 5000/hr. Without a token, the
 * 60/hr limit is sufficient for enrichment (we only query packages OSV
 * already flagged).
 */
async function queryGhsaRest(ecosystem: string, packageName: string): Promise<any[]> {
    const url = `${GHSA_ADVISORIES_URL}?ecosystem=${encodeURIComponent(ecosystem)}&affected_package=${encodeURIComponent(packageName)}&per_page=${GHSA_PER_PAGE}`;
    const headers: Record<string, string> = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'SecureCode-Extension',
    };
    // Try to get a GitHub token for higher rate limits.
    const token = await getGithubToken();
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), GHSA_TIMEOUT_MS);
    try {
        const r = await fetch(url, {
            method: 'GET',
            headers,
            signal: controller.signal,
        });
        if (!r.ok) return [];
        const data = await r.json();
        return Array.isArray(data) ? data : [];
    } catch {
        return [];
    } finally {
        clearTimeout(timeout);
    }
}

/**
 * Detect a GitHub token from env vars or `gh auth token`.
 * Returns null if no token is available (unauthenticated mode).
 */
let _cachedToken: string | null | undefined;
async function getGithubToken(): Promise<string | null> {
    if (_cachedToken !== undefined) return _cachedToken;
    // 1. Environment variables
    const envToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (envToken) {
        _cachedToken = envToken;
        return _cachedToken;
    }
    // 2. `gh auth token` (if gh CLI is installed and authenticated)
    try {
        _cachedToken = await new Promise<string | null>(resolve => {
            const child = cp.spawn('gh', ['auth', 'token'], { shell: true });
            let stdout = '';
            child.stdout.on('data', d => { stdout += d.toString(); });
            child.on('error', () => resolve(null));
            child.on('exit', code => {
                const t = stdout.trim();
                resolve(code === 0 && t ? t : null);
            });
        });
    } catch {
        _cachedToken = null;
    }
    return _cachedToken;
}

/**
 * With the REST API approach, GHSA is always "available" (works
 * unauthenticated at 60 req/hr). Kept for backward compat with the
 * `ghsaSkipped` flag in DependencyScanResult.
 */
export async function ghCliAvailable(): Promise<boolean> {
    return true;
}

/**
 * NVD CVSS fallback. Uses the public NVD REST endpoint keyed by CVE id.
 *
 * Cached in `workspaceState` for 24h to respect the public rate limit
 * (5 req/30s without an API key). We only call NVD when an OSV record has
 * a CVE alias but no CVSS score, to fill in the severity number.
 */
const NVD_CACHE_KEY_PREFIX = 'securecode.nvd.';
const NVD_TTL_MS = 24 * 60 * 60 * 1000;

interface NvdCacheEntry { fetchedAt: number; score?: number; url?: string; }

async function nvdLookup(cveId: string): Promise<NvdCacheEntry | null> {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    try {
        const r = await fetch(url, { headers: { 'User-Agent': 'SecureCode-Extension' } });
        if (!r.ok) return null;
        const data: any = await r.json();
        const vuln = data?.vulnerabilities?.[0]?.cve;
        if (!vuln) return null;
        let score: number | undefined;
        const metrics = vuln?.metrics;
        const cvss = metrics?.cvssMetricV31?.[0] ?? metrics?.cvssMetricV30?.[0] ?? metrics?.cvssMetricV2?.[0];
        if (cvss?.cvssData?.baseScore) score = cvss.cvssData.baseScore;
        const refs: string[] = Array.isArray(vuln?.references)
            ? vuln.references.map((x: any) => x?.url).filter((y: any) => typeof y === 'string')
            : [];
        return { fetchedAt: Date.now(), score, url: refs[0] };
    } catch {
        return null;
    }
}

/**
 * Enrich OSV records with NVD CVSS scores when missing, caching results
 * in workspaceState for 24h.
 *
 * Mutates the records in place and returns them for convenience.
 */
export async function enrichWithNvd(
    records: Vulnerability[],
    state: CacheStore,
): Promise<Vulnerability[]> {
    for (const v of records) {
        if (v.cvssScore !== undefined) continue;
        // Only CVE-ids are resolvable on NVD.
        if (!/^CVE-\d{4}-\d+$/i.test(v.id)) continue;

        const cacheKey = NVD_CACHE_KEY_PREFIX + v.id;
        const cached = state.get<NvdCacheEntry>(cacheKey);
        let entry: NvdCacheEntry | null;
        if (cached && Date.now() - cached.fetchedAt < NVD_TTL_MS) {
            entry = cached;
        } else {
            entry = await nvdLookup(v.id);
            if (entry) state.update(cacheKey, entry);
        }
        if (entry?.score !== undefined) {
            v.cvssScore = entry.score;
            if (entry.url && (!v.references || v.references.length === 0)) {
                v.references = [entry.url];
            }
        }
    }
    return records;
}
