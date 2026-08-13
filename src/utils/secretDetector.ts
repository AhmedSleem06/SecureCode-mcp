/**
 * Secret/PII detector — ported from api/src/utils/redact.ts.
 *
 * Returns line-numbered findings instead of redacting. Used by the
 * scan-secrets MCP tool for standalone secret scanning without AI.
 */

export interface SecretFinding {
    line: number;
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    match: string;
}

interface SecretPattern {
    re: RegExp;
    type: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
    { type: 'jwt', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
    { type: 'private_key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
    { type: 'openai_key', re: /sk-[A-Za-z0-9]{20,}/g },
    { type: 'aws_key_id', re: /AKIA[0-9A-Z]{16}/g },
    { type: 'github_pat', re: /ghp_[A-Za-z0-9]{36}/g },
    { type: 'stripe_key', re: /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g },
    { type: 'slack_token', re: /xox[abpr]-[A-Za-z0-9-]{10,}/g },
    { type: 'google_api_key', re: /AIza[A-Za-z0-9_-]{35}/g },
    { type: 'env_secret', re: /((?:DATABASE_URL|DB_PASSWORD|DB_HOST|REDIS_URL|SECRET_KEY|PRIVATE_KEY|ENCRYPTION_KEY|JWT_SECRET)\s*=\s*)["']?[A-Za-z0-9+/=_:.-]{6,}["']?/gi },
    { type: 'connection_string', re: /([a-z][a-z0-9+.-]*:\/\/)[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@/gi },
    { type: 'credential_assignment', re: /((?:password|secret|api[_-]?key|token)["']?\s*[:=]\s*)["'][^"']{4,}["']/gi },
    { type: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
    { type: 'credit_card', re: /\b(?:\d[ -]*?){13,16}\b/g },
];

const SEVERITY_MAP: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM'> = {
    jwt: 'CRITICAL',
    private_key: 'CRITICAL',
    openai_key: 'CRITICAL',
    aws_key_id: 'CRITICAL',
    github_pat: 'CRITICAL',
    stripe_key: 'CRITICAL',
    slack_token: 'HIGH',
    google_api_key: 'HIGH',
    env_secret: 'HIGH',
    connection_string: 'HIGH',
    credential_assignment: 'HIGH',
    email: 'MEDIUM',
    credit_card: 'HIGH',
};

export function detectSecrets(code: string): SecretFinding[] {
    if (!code || code.length === 0) return [];
    const lines = code.split('\n');
    const findings: SecretFinding[] = [];
    const seen = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { re, type } of SECRET_PATTERNS) {
            re.lastIndex = 0;
            const matches = line.match(re);
            if (matches && matches.length > 0) {
                const key = `${i + 1}:${type}`;
                if (seen.has(key)) continue;
                seen.add(key);
                findings.push({
                    line: i + 1,
                    type,
                    severity: SEVERITY_MAP[type] ?? 'MEDIUM',
                    match: matches[0].substring(0, 80),
                });
            }
        }
    }
    return findings;
}
