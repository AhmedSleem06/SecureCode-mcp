/**
 * Shared types for the dependency vulnerability checker (Phase 2).
 *
 * No source code is ever sent anywhere — only package name + version strings
 * leave the machine, to OSV.dev (free, no key) and GitHub Advisory REST API
 * (free, no key for 60 req/hr; 5000 req/hr with optional token). NVD is an
 * optional CVSS fallback.
 */

/** Ecosystems we can parse a lockfile for. */
export type Ecosystem = 'npm' | 'yarn' | 'pnpm' | 'pip' | 'pipenv';

/** OSV ecosystem identifier used in OSV.dev API payloads. */
export type OsvEcosystem = 'npm' | 'PyPI';

/**
 * A single resolved dependency as extracted from a lockfile.
 * For npm/yarn/pnpm this is a transitive entry straight out of the lockfile
 * (so the resolver does not need to hit the network). For requirements.txt
 * without a Pipfile.lock, entries may be marked `unresolved` instead of
 * fetching a registry.
 */
export interface ResolvedPackage {
    ecosystem: Ecosystem;
    /** Package name as the registry knows it (PyPI names are normalized to lower). */
    name: string;
    /** Resolved version (semver for JS, PEP 440-ish for Python). */
    version: string;
    /** SPDX license identifier when available from lockfile/metadata, else undefined. */
    license?: string;
    /** Path to the manifest this entry came from (for Apply affordance). */
    manifestPath?: string;
    /**
     * True when the version could not be resolved locally (e.g. requirements.txt
     * pin like `>=1.0` with no lockfile). These are reported as "unresolved"
     * findings rather than queried against OSV (since we don't know the version).
     */
    unresolved?: boolean;
    /** Direct dependency (declared in manifest) vs transitive (resolved from lockfile). */
    direct?: boolean;
}

/** Output of a lockfile parser. */
export interface ParsedLockfile {
    ecosystem: Ecosystem;
    /** Path to the lockfile that was parsed. */
    lockfilePath: string;
    /** Path to the manifest the lockfile corresponds to (package.json, requirements.txt, ...). */
    manifestPath?: string;
    /** All resolved packages, direct + transitive. */
    packages: ResolvedPackage[];
    /** SPDX license of the project itself, if discoverable (npm package.json `license`). */
    projectLicense?: string;
}

/** An affected version range as returned by OSV / GHSA. */
export interface AffectedRange {
    /** OSV ecosystem ('npm' | 'PyPI'). */
    ecosystem: OsvEcosystem;
    /** Lower bound of the affected range, inclusive (optional). */
    introduced?: string;
    /** Upper bound of the affected range, exclusive (the "first fixed" version). */
    fixed?: string;
    /** Raw range string for diagnostics. */
    raw?: string;
}

/** A vulnerability record normalized from OSV / GHSA / NVD. */
export interface Vulnerability {
    /** OSV id (OSV-...) or GHSA id (GHSA-...) or CVE id (CVE-...). */
    id: string;
    /** Source the record came from. Kept for backward compat; `sources` is the
     *  authoritative provenance list (may contain multiple entries after merge). */
    source: 'osv' | 'ghsa' | 'nvd';
    /** All sources that confirmed this vulnerability (after merge). */
    sources: Array<'osv' | 'ghsa' | 'nvd'>;
    /** One-line summary. */
    summary: string;
    /** List of affected version ranges. */
    affected: AffectedRange[];
    /** CVSS v3 base score 0-10 when known (NVD or OSV severity). */
    cvssScore?: number;
    /** URLs for the user to read more. */
    references?: string[];
    /** EPSS percentile 0-100 when available (exploit probability). */
    epssPercentile?: number;
    /** True if listed in CISA Known Exploited Vulnerabilities catalog. */
    knownExploited?: boolean;
    /** True when a public proof-of-concept or exploit is referenced. */
    exploitAvailable?: boolean;
    /** Published date (ISO) when available. */
    published?: string;
}

/** A vulnerability matched to a resolved package. */
export interface MatchedVulnerability {
    /** The resolved package that is vulnerable. */
    package: ResolvedPackage;
    /** Vulnerabilities affecting `package.version`. */
    vulnerabilities: Vulnerability[];
    /** Smallest version bump that exits all affected ranges, when computable. */
    minSafeVersion?: string;
}
