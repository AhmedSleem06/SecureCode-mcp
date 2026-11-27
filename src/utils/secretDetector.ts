export interface SecretFinding {
    line: number;
    type: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    match: string;
    testFile?: boolean;
}

interface PatternRule {
    id: string;
    re: RegExp;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    multiline?: boolean;
    validate?: (match: string, fullContent: string) => boolean;
}

const PLACEHOLDER_VALUES = new Set([
    'changeme', 'change-me', 'change_me', 'your-key-here', 'your_key_here',
    'your-secret-here', 'your_secret_here', 'xxx', 'xxxx', 'xxxxxxxx',
    'example', 'test', 'TODO', 'FIXME', 'placeholder', 'replace-me',
    'replace_me', 'insert-here', 'insert_here', 'dummy', 'sample',
    'changethis', 'secret', 'password', 'mysecret',
    'unset', 'none', 'null', 'undefined', 'dev', 'development',
    'production', 'staging', 'test', 'local', 'empty',
]);

function isPlaceholder(val: string): boolean {
    const clean = val.replace(/^['"`]+|['"`]+$/g, '').trim();
    if (PLACEHOLDER_VALUES.has(clean.toLowerCase())) return true;
    if (/^<[^>]+>$/.test(clean)) return true;
    if (/^\$\{[^}]+\}$/.test(clean)) return true;
    if (/^%[^%]+%$/.test(clean)) return true;
    if (/^your[_-]/.test(clean.toLowerCase())) return true;
    return false;
}

function shannonEntropy(s: string): number {
    if (s.length === 0) return 0;
    const freq = new Map<string, number>();
    for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
    let entropy = 0;
    for (const count of freq.values()) {
        const p = count / s.length;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function luhnCheck(digits: string): boolean {
    const nums = digits.replace(/\D/g, '');
    if (nums.length < 13 || nums.length > 19) return false;
    let sum = 0;
    let alt = false;
    for (let i = nums.length - 1; i >= 0; i--) {
        let n = parseInt(nums[i], 10);
        if (alt) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        alt = !alt;
    }
    return sum % 10 === 0;
}

function isEnvLookup(value: string): boolean {
    const trimmed = value.trim().replace(/^['"`]+|['"`]+$/g, '').trim();
    return /^process\.env\.\w+$/.test(trimmed)
        || /^os\.environ\b/.test(trimmed)
        || /^ENV\[/.test(trimmed)
        || /^getenv\(/.test(trimmed);
}

const SECRET_VAR_NAMES = /(?:SECRET|PRIVATE|CREDENTIAL|SIGNING|SALT|WEBHOOK_SECRET|_KEY|_TOKEN|PASSWORD|PASSWD|PASS|PWD|AUTH)/i;
const NON_SECRET_SUFFIXES = /(?:_URL|_URI|_FILE|_PATH|_DIR|_HOST|_PORT|_MODE|_ENV|_SERVER|_ORDER|_NAME|_REGION|_LEVEL|_FORMAT|_TIMEOUT|_LIMIT|_SIZE|_COUNT|_INDEX|_BASE|_ROOT|_HOME|_PREFIX|_SUFFIX|_TYPE|_VERSION|_LANG|_LOCALE|_DOMAIN|_SCHEME|_PROTO|_SERVICE|_TABLE|_BUCKET|_QUEUE|_TOPIC|_ENDPOINT|_DRIVER|_POOL|_INTERVAL|_ENABLED|_DISABLED)$/i;

function isSecretVarName(envExpr: string): boolean {
    const varName = envExpr.replace(/^process\.env\./, '').replace(/^os\.environ.*['"](\w+).*$/, '$1');
    if (NON_SECRET_SUFFIXES.test(varName)) return false;
    return SECRET_VAR_NAMES.test(varName);
}

function isUrlOrPath(val: string): boolean {
    if (/^https?:\/\//i.test(val)) return true;
    if (/^ftp:\/\//i.test(val)) return true;
    if (/^\/[a-z]/i.test(val) && /[/.]/.test(val)) return true;
    if (/^[a-z]:\\/i.test(val)) return true;
    if (/\.(com|org|net|io|dev|ai|tech|app|co)\b/i.test(val) && !/@/.test(val)) return true;
    return false;
}

function isUrlWithoutCredentials(val: string): boolean {
    if (/^https?:\/\//i.test(val) || /^ftp:\/\//i.test(val)) {
        return !/\/\/[^/]+:[^/]+@/.test(val);
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(val)) {
        return !/\/\/[^/]+:[^/]+@/.test(val);
    }
    return false;
}

function isIdentifierLike(val: string): boolean {
    if (/^[a-z][a-zA-Z]*$/.test(val) && val.length < 30) return true;
    if (/^[a-z]+(-[a-z]+){1,5}$/.test(val)) return true;
    if (/^[a-z][a-z0-9]*(_[a-z0-9]+)+$/i.test(val) && !/\d{3,}/.test(val) && val.length < 30) return true;
    if (/^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)+$/.test(val)) return true;
    return false;
}

function isInsideTemplateLiteral(line: string, matchIndex: number): boolean {
    const before = line.substring(0, matchIndex);
    let inTemplate = false;
    for (let i = 0; i < before.length; i++) {
        if (before[i] === '`') inTemplate = !inTemplate;
    }
    return inTemplate;
}

const WELL_KNOWN_PLACEHOLDER_CREDS = new Set([
    'pass', 'password', 'user:pass', 'user:password', 'username:password',
    'admin:admin', 'foo:bar', 'xxx', 'test', 'example',
]);

const PATTERNS: PatternRule[] = [
    {
        id: 'private_key',
        re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
        severity: 'CRITICAL',
        multiline: true,
    },
    {
        id: 'aws_key_id',
        re: /(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])/g,
        severity: 'CRITICAL',
    },
    {
        id: 'aws_secret_key',
        re: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g,
        severity: 'CRITICAL',
    },
    {
        id: 'openai_key',
        re: /sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}/g,
        severity: 'CRITICAL',
        validate: (match) => {
            if (/^sk-ant-/i.test(match)) return false;
            if (/^sk_(?:live|test)_/.test(match)) return false;
            return match.length >= 24;
        },
    },
    {
        id: 'anthropic_key',
        re: /sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'github_pat',
        re: /ghp_[A-Za-z0-9]{36,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'github_fine_grained',
        re: /github_pat_[A-Za-z0-9_]{20,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'github_oauth',
        re: /gh[ous]_[A-Za-z0-9]{36,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'stripe_key',
        re: /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/g,
        severity: 'CRITICAL',
        validate: (match) => match.length >= 24,
    },
    {
        id: 'stripe_webhook_secret',
        re: /whsec_[A-Za-z0-9]{10,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'sendgrid_key',
        re: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'slack_webhook',
        re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
        severity: 'HIGH',
    },
    {
        id: 'slack_token',
        re: /xox[abpr]-[A-Za-z0-9-]{10,}/g,
        severity: 'HIGH',
    },
    {
        id: 'jwt',
        re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'google_api_key',
        re: /AIza[A-Za-z0-9_-]{35}/g,
        severity: 'HIGH',
    },
    {
        id: 'npm_token',
        re: /npm_[A-Za-z0-9]{30,}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'twilio_key',
        re: /SK[0-9a-fA-F]{32}/g,
        severity: 'CRITICAL',
    },
    {
        id: 'connection_string',
        re: /([a-z][a-z0-9+.-]*:\/\/)[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+!@#$^&*()-]{3,}@[A-Za-z0-9.-]+/gi,
        severity: 'HIGH',
        validate: (match) => {
            const passwordMatch = match.match(/:\/\/([^:]+):([^@]+)@/);
            if (!passwordMatch) return false;
            const user = passwordMatch[1];
            const pw = passwordMatch[2];
            const combo = `${user}:${pw}`;
            if (WELL_KNOWN_PLACEHOLDER_CREDS.has(pw.toLowerCase())) return false;
            if (WELL_KNOWN_PLACEHOLDER_CREDS.has(combo.toLowerCase())) return false;
            if (isPlaceholder(pw)) return false;
            return pw.length >= 4 && shannonEntropy(pw) > 1.5;
        },
    },
    {
        id: 'credit_card',
        re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
        severity: 'HIGH',
        validate: (match) => luhnCheck(match),
    },
    {
        id: 'fallback_secret',
        re: /(?:process\.env\.([A-Z_]+)|os\.environ(?:\.get)?\(['"](\w+)['"]\))\s*(?:\|\||[?]{2}|\bor\b)\s*['"]([^'"]{4,})['"]/g,
        severity: 'HIGH',
        validate: (match) => {
            const envMatch = match.match(/process\.env\.([A-Z_]+)/);
            const varName = envMatch ? envMatch[1] : '';
            if (varName && NON_SECRET_SUFFIXES.test(varName)) return false;
            if (varName && !SECRET_VAR_NAMES.test(varName)) return false;
            const valMatch = match.match(/(?:\|\||[?]{2}|\bor\b)\s*['"]([^'"]+)['"]/);
            if (!valMatch) return false;
            const val = valMatch[1];
            if (isPlaceholder(val)) return false;
            if (isUrlOrPath(val)) return false;
            if (isIdentifierLike(val)) return false;
            if (/^[A-Z][a-zA-Z0-9]*(-[A-Z][a-zA-Z0-9]*)*$/.test(val)) return false;
            return shannonEntropy(val) > 2.5;
        },
    },
    {
        id: 'credential_assignment',
        re: /(?:password|secret|api[_-]?key|token|auth[_-]?token|access[_-]?token)["']?\s*[:=]\s*['"]([^'"]{4,})['"]/gi,
        severity: 'HIGH',
        validate: (match, fullContent) => {
            const valMatch = match.match(/[:=]\s*['"]([^'"]+)['"]/);
            if (!valMatch) return false;
            const val = valMatch[1];
            if (isPlaceholder(val)) return false;
            if (isEnvLookup(val)) return false;
            if (/^process\.env\b/.test(val)) return false;
            if (isIdentifierLike(val)) return false;
            if (isUrlOrPath(val)) return false;
            if (/^\w+\(/.test(val)) return false;
            const keyMatch = match.match(/^(\w+)/i);
            if (keyMatch) {
                const keyVal = keyMatch[1].toLowerCase();
                if (keyVal === val.toLowerCase()) return false;
            }
            return shannonEntropy(val) > 3.0;
        },
    },
    {
        id: 'generic_secret',
        re: /(?:SECRET|PRIVATE_KEY|CREDENTIAL|SIGNING|AUTH_?KEY|MASTER_KEY|ENCRYPTION_KEY)["']?\s*[=:]\s*["']([^'"]{6,})["']/gi,
        severity: 'MEDIUM',
        validate: (match, fullContent) => {
            const valMatch = match.match(/[=:]\s*["']([^'"]+)["']/);
            if (!valMatch) return false;
            const val = valMatch[1];
            if (isPlaceholder(val)) return false;
            if (isEnvLookup(val)) return false;
            if (/^process\.env\b/.test(val)) return false;
            if (/^\w+\(/.test(val)) return false;
            if (isIdentifierLike(val)) return false;
            if (isUrlOrPath(val)) return false;
            const keyMatch = match.match(/^(\w+)/i);
            if (keyMatch) {
                const keyVal = keyMatch[1].toLowerCase();
                if (keyVal === val.toLowerCase().replace(/[_-]/g, '')) return false;
            }
            return shannonEntropy(val) > 3.5;
        },
    },
    {
        id: 'env_file_secret',
        re: /^(?:export\s+)?([A-Z][A-Z0-9_]{2,})[=:](['"]?)([^\s'"]{4,})\2\s*$/gm,
        severity: 'HIGH',
        validate: (match) => {
            const m = match.match(/^(?:export\s+)?([A-Z][A-Z0-9_]{2,})[=:](['"]?)([^\s'"]+)\2\s*$/);
            if (!m) return false;
            const varName = m[1];
            const val = m[3];
            if (!isSecretVarName(varName)) return false;
            if (!val || val.length < 4) return false;
            if (isPlaceholder(val)) return false;
            if (isEnvLookup(val)) return false;
            if (isUrlWithoutCredentials(val)) return false;
            if (/^\/[a-z]/i.test(val) && /[/.]/.test(val)) return false;
            if (/^[a-z]:\\/i.test(val)) return false;
            return shannonEntropy(val) > 2.0;
        },
    },
    {
        id: 'google_service_account',
        re: /"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
        severity: 'CRITICAL',
        multiline: true,
    },
    {
        id: 'supabase_service_role',
        re: /(?:SUPABASE_SERVICE_ROLE_KEY|service_role)\s*[=:]\s*['"]?(eyJ[A-Za-z0-9_.-]{50,})/g,
        severity: 'CRITICAL',
    },
];

const ENV_LOOKUP_PATTERN = /^(?:const|let|var|export)\s+\w+\s*=\s*process\.env\.\w+\s*;?\s*$/;
const FIELD_NAME_ONLY_PATTERN = /(?:req\.body\.\w+|req\.query\.\w+|req\.params\.\w+|params\.\w+|body\.\w+)/;

export function detectSecrets(code: string, options?: { includePii?: boolean; fileName?: string }): SecretFinding[] {
    if (!code || code.length === 0) return [];

    const findings: SecretFinding[] = [];
    const seen = new Set<string>();
    const lines = code.split('\n');

    for (const rule of PATTERNS) {
        if (rule.multiline) {
            rule.re.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = rule.re.exec(code)) !== null) {
                const lineNum = code.substring(0, m.index).split('\n').length;
                const key = `${lineNum}:${rule.id}`;
                if (seen.has(key)) continue;
                if (rule.validate && !rule.validate(m[0], code)) continue;
                seen.add(key);
                findings.push({
                    line: lineNum,
                    type: rule.id,
                    severity: rule.severity,
                    match: m[0].substring(0, 80),
                });
            }
        } else {
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                rule.re.lastIndex = 0;
                let m: RegExpExecArray | null;
                while ((m = rule.re.exec(line)) !== null) {
                    const key = `${i + 1}:${rule.id}`;
                    if (seen.has(key)) continue;

                    if (rule.id === 'credential_assignment' || rule.id === 'generic_secret') {
                        if (ENV_LOOKUP_PATTERN.test(line.trim())) continue;
                        if (FIELD_NAME_ONLY_PATTERN.test(line) && !line.includes("'") && !line.includes('"')) continue;
                        if (isInsideTemplateLiteral(line, m.index)) continue;
                        if (/^\s*\/\//.test(line) || /^\s*\*/.test(line) || /^\s*\/\*/.test(line)) continue;
                    }

                    if (rule.validate && !rule.validate(m[0], code)) continue;
                    seen.add(key);
                    findings.push({
                        line: i + 1,
                        type: rule.id,
                        severity: rule.severity,
                        match: m[0].substring(0, 80),
                    });
                }
            }
        }
    }

    if (options?.includePii) {
        const emailRe = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
        for (let i = 0; i < lines.length; i++) {
            emailRe.lastIndex = 0;
            const m = lines[i].match(emailRe);
            if (m) {
                const key = `${i + 1}:email`;
                if (!seen.has(key)) {
                    seen.add(key);
                    findings.push({
                        line: i + 1,
                        type: 'email',
                        severity: 'LOW',
                        match: m[0].substring(0, 80),
                    });
                }
            }
        }
    }

    return deduplicateFindings(findings);
}

const GENERIC_TYPES = new Set([
    'env_file_secret', 'credential_assignment', 'generic_secret', 'fallback_secret',
]);

function deduplicateFindings(findings: SecretFinding[]): SecretFinding[] {
    const byLine = new Map<number, SecretFinding[]>();
    for (const f of findings) {
        const list = byLine.get(f.line) || [];
        list.push(f);
        byLine.set(f.line, list);
    }
    const result: SecretFinding[] = [];
    for (const group of byLine.values()) {
        const specific = group.filter(f => !GENERIC_TYPES.has(f.type));
        if (specific.length > 0) {
            for (const f of group) {
                if (GENERIC_TYPES.has(f.type)) {
                    const coveredBySpecific = specific.some(s =>
                        f.match.includes(s.match.substring(0, 12)) ||
                        s.match.includes(f.match.substring(0, 12))
                    );
                    if (coveredBySpecific) continue;
                }
                result.push(f);
            }
        } else {
            result.push(...group);
        }
    }
    return result;
}
