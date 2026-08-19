/**
 * Security config discovery — finds and parses security-relevant config
 * files in the workspace so the agent can reason about ACTUAL config
 * instead of guessing from prompt rules.
 *
 * Replaces the system prompt's hardcoded FP-suppression rules ("config-gated
 * rate limits are not vulnerabilities") with a tool that lets the agent
 * check the config and reason about what it finds.
 *
 * Security rules:
 *   - For .env files, return key NAMES and set/unset status only — never values
 *   - Prefer .env.example over real .env
 *   - All paths workspace-confined via resolveWorkspacePath
 *   - Output truncated to 16KB
 */

import * as fs from 'fs';
import * as path from 'path';
import { resolveWorkspacePath } from './files';

export type ConfigKind = 'auth' | 'cors' | 'rate_limit' | 'headers' | 'env' | 'all';

interface ConfigFile {
    path: string;
    kind: string;
    description: string;
}

const CONFIG_PATTERNS: { file: string; kind: ConfigKind; description: string }[] = [
    { file: '.env.example', kind: 'env', description: 'Environment variable template (safe to show keys)' },
    { file: '.env', kind: 'env', description: 'Environment variables (KEYS ONLY — values redacted)' },
    { file: '.env.local', kind: 'env', description: 'Local environment overrides (KEYS ONLY)' },
    { file: '.env.production', kind: 'env', description: 'Production environment (KEYS ONLY)' },
    { file: 'helmet.config.js', kind: 'headers', description: 'Helmet security headers config' },
    { file: 'helmet.config.ts', kind: 'headers', description: 'Helmet security headers config' },
    { file: 'cors.config.js', kind: 'cors', description: 'CORS configuration' },
    { file: 'cors.config.ts', kind: 'cors', description: 'CORS configuration' },
    { file: 'next.config.js', kind: 'headers', description: 'Next.js config (may contain headers/CSP)' },
    { file: 'next.config.ts', kind: 'headers', description: 'Next.js config (may contain headers/CSP)' },
    { file: 'next.config.mjs', kind: 'headers', description: 'Next.js config (may contain headers/CSP)' },
    { file: 'express-rate-limit.config.js', kind: 'rate_limit', description: 'Express rate limit config' },
    { file: 'rate-limit.config.js', kind: 'rate_limit', description: 'Rate limit config' },
    { file: 'rate-limit.config.ts', kind: 'rate_limit', description: 'Rate limit config' },
];

function findConfigFiles(workspaceRoot: string, kind: ConfigKind): ConfigFile[] {
    const out: ConfigFile[] = [];

    for (const pattern of CONFIG_PATTERNS) {
        if (kind !== 'all' && pattern.kind !== kind) continue;

        const candidates = [
            path.join(workspaceRoot, pattern.file),
            path.join(workspaceRoot, 'config', pattern.file),
            path.join(workspaceRoot, 'src', pattern.file),
        ];

        for (const candidate of candidates) {
            if (fs.existsSync(candidate)) {
                const rel = path.relative(workspaceRoot, candidate).replace(/\\/g, '/');
                out.push({ path: rel, kind: pattern.kind, description: pattern.description });
                break;
            }
        }
    }

    return out;
}

function redactEnvValues(content: string): string {
    return content
        .split('\n')
        .map(line => {
            const trimmed = line.trim();
            if (trimmed.startsWith('#') || trimmed === '') return line;
            const eqIdx = line.indexOf('=');
            if (eqIdx === -1) return line;
            const key = line.slice(0, eqIdx).trim();
            const isSecret = /SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL/i.test(key);
            if (isSecret) return `${key}=REDACTED`;
            return `${key}=set`;
        })
        .join('\n');
}

function parseConfigFile(filePath: string, workspaceRoot: string): string {
    const abs = resolveWorkspacePath(workspaceRoot, filePath);
    const content = fs.readFileSync(abs, 'utf8');
    const ext = path.extname(filePath).toLowerCase();

    if (filePath.includes('.env')) {
        return redactEnvValues(content);
    }

    if (ext === '.js' || ext === '.ts' || ext === '.mjs' || ext === '.json') {
        return content.slice(0, 12000);
    }

    return content.slice(0, 12000);
}

function searchInlineConfig(workspaceRoot: string, kind: ConfigKind): { file: string; snippet: string; line: number }[] {
    const out: { file: string; snippet: string; line: number }[] = [];
    const patterns: { regex: string; kind: ConfigKind; label: string }[] = [
        { regex: 'helmet\\s*\\(', kind: 'headers', label: 'helmet() call' },
        { regex: 'cors\\s*\\(', kind: 'cors', label: 'cors() call' },
        { regex: 'rateLimit\\s*\\(', kind: 'rate_limit', label: 'rateLimit() call' },
        { regex: 'rate-limit', kind: 'rate_limit', label: 'rate-limit import' },
        { regex: 'express-rate-limit', kind: 'rate_limit', label: 'express-rate-limit import' },
        { regex: 'Content-Security-Policy|contentSecurityPolicy|CSP', kind: 'headers', label: 'CSP header' },
        { regex: 'HSTS|strict-Transport-Security', kind: 'headers', label: 'HSTS header' },
        { regex: 'X-Frame-Options|xFrameOptions', kind: 'headers', label: 'X-Frame-Options' },
        { regex: 'X-Content-Type-Options|xContentTypeOptions', kind: 'headers', label: 'X-Content-Type-Options' },
    ];

    for (const p of patterns) {
        if (kind !== 'all' && p.kind !== kind) continue;
        try {
            const { searchCode } = require('../utils/searchCode');
            const result = searchCode(workspaceRoot, p.regex, '*.{js,ts,mjs,jsx,tsx}');
            if (result && result.hits) {
                for (const hit of result.hits.slice(0, 3)) {
                    out.push({
                        file: hit.path,
                        snippet: hit.text.slice(0, 200),
                        line: hit.line,
                    });
                }
            }
        } catch { /* best-effort */ }
    }

    return out;
}

export async function readSecurityConfig(
    workspaceRoot: string,
    kind: ConfigKind = 'all',
): Promise<string> {
    const configFiles = findConfigFiles(workspaceRoot, kind);
    const inlineConfigs = searchInlineConfig(workspaceRoot, kind);

    if (configFiles.length === 0 && inlineConfigs.length === 0) {
        return `No ${kind === 'all' ? '' : kind + ' '}security config files found. The project may not have explicit security config — check if it relies on framework defaults or environment variables.`;
    }

    const lines: string[] = [`Security config (${kind === 'all' ? 'all' : kind}):`];

    if (configFiles.length > 0) {
        lines.push('', 'Config files:');
        for (const cf of configFiles.slice(0, 10)) {
            lines.push(`  ${cf.path} — ${cf.description}`);
            try {
                const content = parseConfigFile(cf.path, workspaceRoot);
                lines.push('  ```');
                for (const line of content.split('\n').slice(0, 40)) {
                    lines.push(`  ${line}`);
                }
                if (content.split('\n').length > 40) {
                    lines.push('  ... (truncated)');
                }
                lines.push('  ```');
            } catch (e: any) {
                lines.push(`  (error reading: ${e.message})`);
            }
        }
    }

    if (inlineConfigs.length > 0) {
        lines.push('', 'Inline config found in source:');
        for (const ic of inlineConfigs.slice(0, 10)) {
            lines.push(`  ${ic.file}:${ic.line}`);
            lines.push(`    ${ic.snippet}`);
        }
    }

    lines.push('');
    lines.push('Use this evidence to determine if a security control is actually configured before reporting it as a vulnerability. A missing config file does not mean the control is absent — check inline config too.');

    return lines.join('\n');
}
