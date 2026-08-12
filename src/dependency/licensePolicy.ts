import { ResolvedPackage } from './types';
import spdxCorrect = require('spdx-correct');

/**
 * Normalize a license string to a canonical SPDX id when possible.
 * e.g. "GPLv3" -> "GPL-3.0-only", "Apache 2.0" -> "Apache-2.0".
 * Returns the original string (trimmed) if spdx-correct can't normalize it,
 * so the copyleft prefix matcher still gets a chance to flag obvious cases.
 */
function normalizeSpdx(license: string | undefined): string | undefined {
    if (!license) return undefined;
    const trimmed = license.trim();
    if (!trimmed) return undefined;
    try {
        const corrected = spdxCorrect(trimmed);
        return corrected || trimmed;
    } catch {
        return trimmed;
    }
}

/**
 * SPDX license policy.
 *
 * Default behavior (matching the `secureCode.licensePolicy` setting):
 *   - "off":    no license findings are produced.
 *   "warn":     produce a WARNING-severity finding for copyleft licenses
 *               (GPL/AGPL/LGPL/Mozilla/Eclipse/Commons-Clause/CC-BY-NC, etc.)
 *               in projects that look proprietary (no license field, or a
 *               non-OSI/non-copyleft license field).
 *   "error":    same, but ERROR severity.
 *
 * The "looks proprietary" test is conservative: if the project's own
 * `projectLicense` is missing or is a permissive/proprietary-ish license
 * (MIT, ISC, Apache-2.0, BSD-*, UNLICENSED, proprietary, or absent), then
 * a copyleft transitive dep is flagged. If the project itself is GPL,
 * GPL deps are fine and not flagged.
 */

export type LicensePolicyMode = 'off' | 'warn' | 'error';

/**
 * Copyleft / restrictive SPDX identifiers (and well-known non-OSI ones)
 * that we flag in proprietary-looking projects. Matched case-insensitively
 * against the SPDX id's case-insensitive prefix.
 */
const COPYLEFT_PREFIXES = [
    'GPL-', 'AGPL-', 'LGPL-', 'MPL-', 'EPL-', 'CDDL-', 'CPL-',
    'CC-BY-NC', 'CC-BY-SA', 'CC-BY-ND', 'COMMONS-CLAUSE',
    'BUSL-', 'SSPL-', 'RSAL-', 'JSON', 'EUPL-',
];

/** Permissive / proprietary-looking licenses where a copyleft dep is flagged. */
const PERMISSIVE_OR_PROPRIETARY = new Set([
    'MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD',
    'Unlicense', 'UNLICENSED', 'SEE LICENSE IN LICENSE', 'SEE-LICENSE-IN-LICENSE',
    'PROPRIETARY', 'COMMERCIAL',
]);

export interface LicenseFinding {
    package: ResolvedPackage;
    /** SPDX license id (or the raw string if not SPDX-valid). */
    license: string;
    /** True when the license matches a copyleft/restrictive prefix. */
    copyleft: boolean;
    /** Why this package was flagged. */
    reason: string;
    /** Severity the caller should use. */
    severity: 'ERROR' | 'WARNING' | 'INFO';
}

/**
 * Project-level license classifier: does it look proprietary?
 *   - No license field -> yes (likely proprietary).
 *   - A permissive license (MIT, ISC, Apache-2.0, BSD, ...) -> yes (the
 *     presence of copyleft deps creates a conflict).
 *   - A copyleft license -> no (GPL deps in a GPL project are fine).
 */
export function projectLooksProprietary(projectLicense: string | undefined): boolean {
    const norm = normalizeSpdx(projectLicense);
    if (!norm) return true;
    if (PERMISSIVE_OR_PROPRIETARY.has(norm.toUpperCase())) return true;
    // Copyleft-looking project license -> not proprietary.
    const up = norm.toUpperCase();
    if (COPYLEFT_PREFIXES.some(p => up.startsWith(p))) return false;
    // Anything else -> treat as proprietary to be safe.
    return true;
}

/** Does a SPDX/license string match a copyleft/restrictive prefix? */
export function isCopyleft(license: string | undefined): boolean {
    const norm = normalizeSpdx(license);
    if (!norm) return false;
    const up = norm.toUpperCase();
    return COPYLEFT_PREFIXES.some(p => up.startsWith(p));
}

/**
 * Produce license findings for copyleft dependencies under the configured policy.
 *
 * `projectLicense` is the project's own SPDX string (from package.json/Pipfile);
 * undefined when not discoverable.
 *
 * Returns one LicenseFinding per copyleft package when:
 *   - policy !== 'off', AND
 *   - the project looks proprietary, AND
 *   - the package has a license string that matches a copyleft prefix.
 *
 * Packages with no license at all are NOT flagged here (we can't tell), and
 * packages with non-copyleft licenses are not flagged. This is the
 * GPL-in-a-commercial-project detector from the spec.
 */
export function checkLicenses(
    packages: ResolvedPackage[],
    projectLicense: string | undefined,
    policy: LicensePolicyMode,
): LicenseFinding[] {
    if (policy === 'off') return [];
    if (!projectLooksProprietary(projectLicense)) return [];

    const out: LicenseFinding[] = [];
    const severity: 'ERROR' | 'WARNING' = policy === 'error' ? 'ERROR' : 'WARNING';
    for (const p of packages) {
        if (!p.license) continue;
        if (!isCopyleft(p.license)) continue;
        const normalized = normalizeSpdx(p.license) || p.license;
        out.push({
            package: p,
            license: normalized,
            copyleft: true,
            reason: `Copyleft license "${normalized}" on "${p.name}" conflicts with this project's ${
                projectLicense ? `"${projectLicense}"` : 'unspecified'
            } license.`,
            severity,
        });
    }
    return out;
}
