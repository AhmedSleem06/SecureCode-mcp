import { ScanFinding, CacheStore } from './finding';
import { ResolvedPackage, Vulnerability, Ecosystem } from './types';
import { findLockfiles, parseLockfile, resolveAll, WorkspaceLockfiles } from './resolver';
import { queryOsvBatch, queryGhsaViaCli, enrichWithNvd, ghCliAvailable } from './osvClient';
import { computeMinSafeVersion, upgradeSuggestion } from './minSafeVersion';
import { computeExploitPriority, priorityLabel } from './exploitPriority';
import {
    checkLicenses,
    LicensePolicyMode,
    LicenseFinding,
} from './licensePolicy';

export interface DependencyScanOptions {
    /** Workspace root to scan recursively for lockfiles. */
    workspaceRoot: string;
    /** VS Code memento (workspaceState) for NVD CVSS caching. */
    state: CacheStore;
    /** License policy mode (off | warn | error). Default 'warn'. */
    licensePolicy?: LicensePolicyMode;
    /** Whether to also query GitHub Advisory via `gh` CLI. Default true (skips gracefully if gh absent). */
    useGhsa?: boolean;
}

export interface DependencyScanResult {
    /** ScanFinding-shaped records (source: 'dependency'), ready for the unified panel. */
    findings: ScanFinding[];
    /** Raw matched vulnerabilities keyed by `${ecosystem}:${name}@${version}` (for diagnostics). */
    matches: Map<string, Vulnerability[]>;
    /** Number of packages scanned (excluding unresolved). */
    packageCount: number;
    /** Number of packages marked unresolved (unpinned requirements.txt, etc.). */
    unresolvedCount: number;
    /** Parsed lockfile paths. */
    lockfiles: string[];
    /** All resolved packages (for Apply affordance lookups). */
    packages: ResolvedPackage[];
    /** True when GHSA enrichment was skipped because `gh` is not installed. */
    ghsaSkipped?: boolean;
}

/**
 * Run the full dependency vulnerability check.
 *
 * Pipeline:
 *   1. Find lockfiles in the workspace.
 *   2. Parse each one (returns the full resolved transitive tree).
 *   3. Resolve + dedupe across lockfiles (npm-family collapses; pip-family collapses).
 *   4. Batch-query OSV.dev (name + version only — no source code leaves the machine).
 *   5. Optionally enrich with GHSA via `gh` CLI (graceful skip if absent).
 *   6. Fill in missing CVSS via NVD (24h workspaceState cache).
 *   7. Compute min-safe-version for each matched vulnerable package.
 *   8. Run license policy check (default 'warn') against the project license.
 *   9. Produce ScanFinding[] records with source: 'dependency' and a
 *      dependency{...} block carrying everything the Apply affordance needs.
 *
 * No AI calls, no API changes. OSV and NVD are the only network egress, and
 * only package names + versions go to them.
 */
export async function scanDependencies(opts: DependencyScanOptions): Promise<DependencyScanResult> {
    const policy: LicensePolicyMode = opts.licensePolicy ?? 'warn';
    const useGhsa = opts.useGhsa !== false;

    // Map an Ecosystem to its OSV family name. npm-family collapses to 'npm',
    // pip-family collapses to 'PyPI'.
    const ecosystemFamilyOf = (e: Ecosystem): 'npm' | 'PyPI' =>
        e === 'pip' || e === 'pipenv' ? 'PyPI' : 'npm';

    // 1. Find lockfiles.
    const found: WorkspaceLockfiles = findLockfiles(opts.workspaceRoot);
    const lockfilePaths = [
        ...found.npm, ...found.yarn, ...found.pnpm, ...found.pipenv, ...found.pip,
    ];

    // 2. Parse.
    const parsed = lockfilePaths
        .map(parseLockfile)
        .filter((p): p is NonNullable<typeof p> => p !== null);

    // 3. Resolve + dedupe.
    const packages = resolveAll(parsed);
    const unresolved = packages.filter(p => p.unresolved);
    const queryable = packages.filter(p => !p.unresolved);

    // 4. OSV batch.
    const osvMap = await queryOsvBatch(queryable);

    // 5. GHSA via REST API (best-effort enrichment).
    // Only query packages that OSV flagged as vulnerable — GHSA is an
    // enrichment source, not a primary source. This keeps the request
    // count low (typically 5-30 packages) and within the 60 req/hr
    // unauthenticated GitHub rate limit.
    let ghsaMap = new Map<string, Vulnerability[]>();
    let ghsaSkipped = false;
    if (useGhsa) {
        // Collect packages that OSV found vulnerabilities for.
        const osvFlagged = queryable.filter(p => {
            const fam = ecosystemFamilyOf(p.ecosystem);
            const key = `${fam}:${p.name}@${p.version}`;
            return osvMap.has(key);
        });
        if (osvFlagged.length > 0) {
            if (await ghCliAvailable()) {
                try {
                    ghsaMap = await queryGhsaViaCli(osvFlagged);
                } catch {
                    // ignore — OSV data already includes GHSA records most of the time.
                }
            } else {
                ghsaSkipped = true;
            }
        }
    }

    // 6. Merge OSV + GHSA per package key, dedupe by vuln id, track provenance.
    const matches = new Map<string, Vulnerability[]>();
    const allKeys = new Set<string>([...osvMap.keys(), ...ghsaMap.keys()]);
    for (const key of allKeys) {
        const osvList = osvMap.get(key) || [];
        const ghsaList = ghsaMap.get(key) || [];
        const merged: Vulnerability[] = [];
        const seenIds = new Map<string, Set<string>>();
        for (const v of [...osvList, ...ghsaList]) {
            const existing = seenIds.get(v.id);
            if (existing) {
                existing.add(v.source);
                continue;
            }
            const sources = new Set<string>([v.source]);
            seenIds.set(v.id, sources);
            merged.push({ ...v, sources: [v.source] });
        }
        for (const v of merged) {
            const srcs = seenIds.get(v.id);
            if (srcs) v.sources = Array.from(srcs) as any;
        }
        await enrichWithNvd(merged, opts.state);
        for (const v of merged) {
            if (!v.sources || v.sources.length === 0) v.sources = [v.source];
        }
        matches.set(key, merged);
    }

    // 7. Compute min-safe-version and build vulnerability findings.
    const findings: ScanFinding[] = [];

    // For each package with vulnerabilities, produce ONE rolled-up finding
    // (not one per CVE) to keep the sidebar readable. The dependency block
    // carries the worst CVE id + the min-safe-version; the message carries
    // the upgrade suggestion.

    // Sort: highest CVSS first so the most severe is the "rolled-up" id.
    for (const pkg of queryable) {
        const fam = ecosystemFamilyOf(pkg.ecosystem);
        const key = `${fam}:${pkg.name}@${pkg.version}`;
        const vulns = matches.get(key);
        if (!vulns || vulns.length === 0) continue;

        const sortedVulns = vulns.slice().sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
        const worst = sortedVulns[0];
        const minSafe = computeMinSafeVersion(pkg, sortedVulns);

        const priority = computeExploitPriority(sortedVulns, pkg);
        const sevLabel = priorityLabel(priority.score);
        const severity: 'ERROR' | 'WARNING' = priority.score >= 50 ? 'ERROR' : 'WARNING';

        const vulnCount = sortedVulns.length;
        const cveList = sortedVulns.map(v => v.id).slice(0, 5).join(', ');
        const sourceTag = priority.sourceCount >= 2 ? ` [confirmed by ${priority.sourceCount} sources]` : '';
        const exploitTag = priority.knownExploited ? ' [KEV — known exploited]' : priority.exploitAvailable ? ' [exploit available]' : '';
        const priorityTag = ` [priority: ${sevLabel}]`;
        const message = minSafe
            ? `${upgradeSuggestion(pkg, minSafe)} — ${vulnCount} vulnerable ${vulnCount === 1 ? 'advisory' : 'advisories'}: ${cveList}${sourceTag}${exploitTag}${priorityTag}`
            : `${pkg.name}@${pkg.version} has ${vulnCount} vulnerable ${vulnCount === 1 ? 'advisory' : 'advisories'} with NO known fix: ${cveList}${sourceTag}${exploitTag}${priorityTag}`;

        findings.push({
            check_id: `dep.${worst.id}`,
            severity,
            message,
            start: { line: 1, col: 1 },
            end: { line: 1, col: 1 },
            source: 'dependency',
            dependency: {
                ecosystem: pkg.ecosystem,
                name: pkg.name,
                installedVersion: pkg.version,
                fixedVersion: minSafe,
                license: pkg.license,
                manifestPath: pkg.manifestPath,
                unresolved: pkg.unresolved,
                sourceCount: priority.sourceCount,
                confirmedBy: priority.confirmedBy,
                exploitPriority: priority.score,
                knownExploited: priority.knownExploited,
                exploitAvailable: priority.exploitAvailable,
                epssPercentile: priority.epssPercentile,
                isDirect: priority.isDirect,
                advisoryCount: vulnCount,
            },
        });
    }

    // Unresolved requirements.txt entries -> a single warning per package
    // so the user knows why those weren't queried against OSV.
    for (const pkg of unresolved) {
        findings.push({
            check_id: `dep.unresolved.${pkg.name}`,
            severity: 'WARNING',
            message: `Cannot resolve ${pkg.name} version from ${pkg.manifestPath || 'requirements'} (pin it with == or use a lockfile) — skipped from OSV scan`,
            start: { line: 1, col: 1 },
            end: { line: 1, col: 1 },
            source: 'dependency',
            dependency: {
                ecosystem: pkg.ecosystem,
                name: pkg.name,
                installedVersion: pkg.version || '',
                license: pkg.license,
                manifestPath: pkg.manifestPath,
                unresolved: true,
            },
        });
    }

    // 8. License policy.
    // Use the most permissive-looking projectLicense discovered across lockfiles
    // (the first one — typically package.json's). If there are multiple projects,
    // license findings are produced per-package and the policy is conservative.
    let projectLicense: string | undefined;
    for (const lf of parsed) {
        if (lf.projectLicense) {
            projectLicense = lf.projectLicense;
            break;
        }
    }
    const licenseFindings = checkLicenses(packages, projectLicense, policy);
    for (const lf of licenseFindings) {
        findings.push(licenseFindingToScanFinding(lf));
    }

    return {
        findings,
        matches,
        packageCount: queryable.length,
        unresolvedCount: unresolved.length,
        lockfiles: lockfilePaths,
        packages,
        ...(ghsaSkipped ? { ghsaSkipped: true } : {}),
    };
}

function licenseFindingToScanFinding(lf: LicenseFinding): ScanFinding {
    return {
        check_id: `dep.license.${lf.package.name}`,
        severity: lf.severity === 'ERROR' ? 'ERROR' : 'WARNING',
        message: lf.reason,
        start: { line: 1, col: 1 },
        end: { line: 1, col: 1 },
        source: 'dependency',
        dependency: {
            ecosystem: lf.package.ecosystem,
            name: lf.package.name,
            installedVersion: lf.package.version,
            license: lf.license,
            manifestPath: lf.package.manifestPath,
            unresolved: lf.package.unresolved,
        },
    };
}
