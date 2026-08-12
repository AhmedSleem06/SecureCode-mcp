/**
 * Shared file filtering for batch scanning and project map building.
 *
 * Extracted from mapBuilder.ts so both the project map and the batch scan
 * tool use the same ignore + secret-file filtering. The secret-file list
 * is ported from the extension's secretFiles.ts to prevent batch scans
 * from uploading .env contents or private keys.
 */
import * as fs from 'fs';
import * as path from 'path';

// ── .securecodeignore ─────────────────────────────────────────────────────

/** Read .securecodeignore and return a set of glob patterns to skip. */
export function readSecurecodeIgnore(root: string): Set<string> {
    const patterns = new Set<string>();
    try {
        const ignorePath = path.join(root, '.securecodeignore');
        if (fs.existsSync(ignorePath)) {
            const content = fs.readFileSync(ignorePath, 'utf8');
            for (const line of content.split('\n')) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#')) continue;
                patterns.add(trimmed);
            }
        }
    } catch { /* best effort */ }
    return patterns;
}

/** Check if a relative path matches any ignore pattern (simple glob). */
export function isIgnored(relPath: string, patterns: Set<string>): boolean {
    for (const pattern of patterns) {
        if (pattern.endsWith('/')) {
            if (relPath.startsWith(pattern) || relPath.startsWith(pattern.replace(/\/$/, '/'))) return true;
        }
        if (relPath === pattern) return true;
        if (!pattern.includes('.') && relPath.startsWith(pattern + '/')) return true;
    }
    return false;
}

// ── Secret file filtering ────────────────────────────────────────────────

const SECRET_BASENAMES = new Set([
    '.env',
    '.env.local',
    '.env.development',
    '.env.production',
    '.env.test',
    '.env.staging',
    '.env.dev',
    '.env.prod',
    'id_rsa',
    'id_rsa.pub',
    'id_dsa',
    'id_ecdsa',
    'id_ed25519',
    '.npmrc',
    '.pypirc',
    '.netrc',
    '.htpasswd',
    'credentials',
    'credentials.json',
    'serviceaccount.json',
    'gcloud-service-key.json',
    'azure.json',
]);

const SECRET_EXTENSIONS = new Set([
    '.pem', '.key', '.p12', '.pfx', '.jks', '.keystore',
    '.ppk', '.ovpn', '.crt', '.cer', '.der',
]);

/** Returns true if the filename looks like a secret/credential file. */
export function isSecretFileName(filePath: string): boolean {
    const base = path.basename(filePath).toLowerCase();
    if (SECRET_BASENAMES.has(base)) return true;
    if (/^\.env\.[\w.-]+$/.test(base)) return true;
    const ext = path.extname(base).toLowerCase();
    if (SECRET_EXTENSIONS.has(ext)) return true;
    return false;
}

// ── Shared skip directories ──────────────────────────────────────────────

export const SKIP_DIRS = new Set([
    'node_modules', '.git', 'dist', 'build', '.next', '.nuxt', '.output',
    'coverage', '.cache', '.turbo', '.parcel-cache', '__pycache__',
    '.venv', 'venv', 'env', '.env', '.securecode', '.vscode', '.idea',
]);
