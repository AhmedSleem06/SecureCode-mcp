/**
 * Mutation operators — apply security fixes to vulnerable code to create
 * a "secure mutation." The mutation test then checks whether the test
 * script can distinguish between the original (vulnerable) code and the
 * mutated (secure) code.
 *
 * A discriminating test PASSES on the vulnerable code and FAILS on the
 * secure mutation. This proves the test is actually testing the security
 * property, not just exercising the code path.
 *
 * Operators must only reference identifiers that already appear on the
 * target line (or are guarded with `typeof`), otherwise the mutation throws
 * a ReferenceError and the test errors instead of failing.
 */

export type VulnerabilityType =
    | 'broken_access_control'
    | 'missing_auth'
    | 'missing_ownership'
    | 'sql_injection'
    | 'path_traversal'
    | 'command_injection'
    | 'xss'
    | 'ssrf'
    | 'ssti'
    | 'missing_input_validation'
    | 'secrets_in_source'
    | 'hardcoded_secret'
    | 'code_injection'
    | 'generic';

export interface MutationResult {
    mutated: boolean;
    mutatedCode: string;
    description: string;
}

const TYPE_ALIASES: Record<string, VulnerabilityType> = {
    hardcoded_secret: 'secrets_in_source',
    hardcoded_secrets: 'secrets_in_source',
    hardcoded_credentials: 'secrets_in_source',
    hardcoded_password: 'secrets_in_source',
    eval_injection: 'code_injection',
    unsafe_eval: 'code_injection',
    insecure_eval: 'code_injection',
    remote_code_execution: 'code_injection',
    rce: 'code_injection',
    os_command_injection: 'command_injection',
    reflected_xss: 'xss',
    stored_xss: 'xss',
    directory_traversal: 'path_traversal',
};

const NEARBY_OFFSETS = [0, -1, 1, -2, 2];

const SHELL_SAFE = `.replace(/[^A-Za-z0-9_.\\/=:@,+-]/g, '')`;
const SHELL_SAFE_CMD = `.replace(/[^A-Za-z0-9_.\\/=:@,+ -]/g, '')`;
const HTML_ESCAPE = `.replace(/[&<>"'\`]/g, (c) => '&#' + c.charCodeAt(0) + ';')`;
const PATH_SAFE = `.replace(/\\.\\.[\\/\\\\]?/g, '').replace(/^[\\/\\\\]+/, '')`;
const BASENAME = `.replace(/^.*[\\/\\\\]/, '')`;

function indentOf(line: string): string {
    return (line.match(/^\s*/) || [''])[0];
}

/** Split a call's argument list at top-level commas. */
function splitArgs(argText: string): string[] {
    const args: string[] = [];
    let depth = 0;
    let quote: string | null = null;
    let cur = '';
    for (let i = 0; i < argText.length; i++) {
        const ch = argText[i];
        if (quote) {
            cur += ch;
            if (ch === '\\') { cur += argText[++i] ?? ''; continue; }
            if (ch === quote) quote = null;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') { quote = ch; cur += ch; continue; }
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        if (ch === ')' || ch === ']' || ch === '}') depth--;
        if (ch === ',' && depth === 0) { args.push(cur); cur = ''; continue; }
        cur += ch;
    }
    args.push(cur);
    return args;
}

/**
 * Find a call `name(` on the line and return the index range of its
 * argument text (between the parens), or null when unbalanced.
 */
function findCallArgs(line: string, nameRe: RegExp): { start: number; end: number } | null {
    const re = new RegExp(nameRe.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(line)) !== null) {
        const open = m.index + m[0].length - 1;
        if (line[open] !== '(') continue;
        let depth = 0;
        let quote: string | null = null;
        for (let i = open; i < line.length; i++) {
            const ch = line[i];
            if (quote) {
                if (ch === '\\') { i++; continue; }
                if (ch === quote) quote = null;
                continue;
            }
            if (ch === '"' || ch === "'" || ch === '`') { quote = ch; continue; }
            if (ch === '(') depth++;
            if (ch === ')') {
                depth--;
                if (depth === 0) return { start: open + 1, end: i };
            }
        }
    }
    return null;
}

function isStringLiteral(expr: string): boolean {
    const t = expr.trim();
    return /^(['"])(?:\\.|(?!\1).)*\1$/.test(t) || (/^`[^`]*`$/.test(t) && !t.includes('${'));
}

function sanitizeInterpolations(line: string, filter: string): string {
    return line.replace(/`[^`]*`/g, (tpl) =>
        tpl.replace(/\$\{([^{}]+)\}/g, (_m, expr: string) => `\${String(${expr.trim()})${filter}}`),
    );
}

function wrapFirstArg(line: string, nameRe: RegExp, wrap: (arg: string) => string): string {
    const range = findCallArgs(line, nameRe);
    if (!range) return line;
    const args = splitArgs(line.slice(range.start, range.end));
    if (args.length === 0 || !args[0].trim() || isStringLiteral(args[0])) return line;
    const lead = (args[0].match(/^\s*/) || [''])[0];
    args[0] = lead + wrap(args[0].trim());
    return line.slice(0, range.start) + args.join(',') + line.slice(range.end);
}

function replaceAtNearbyLine(
    lines: string[],
    lineIdx: number,
    mutateLine: (line: string) => string,
): string[] | null {
    for (const off of NEARBY_OFFSETS) {
        const idx = lineIdx + off;
        if (idx < 0 || idx >= lines.length) continue;
        const original = lines[idx];
        const mutatedLine = mutateLine(original);
        if (mutatedLine !== original) {
            const mutated = [...lines];
            mutated[idx] = mutatedLine;
            return mutated;
        }
    }
    return null;
}

function denyGuard(indent: string, message: string): string {
    return `${indent}if (typeof res !== 'undefined' && res && typeof res.status === 'function') { const __scR = res.status(403); return __scR && typeof __scR.json === 'function' ? __scR.json({ error: '${message}' }) : (__scR && typeof __scR.send === 'function' ? __scR.send('${message}') : __scR); } else { return null; }`;
}

function mutateCommandLine(line: string): string {
    const execCall = /\b(?:exec|execSync|spawn|spawnSync|execa|execaCommand|execaCommandSync|execFile|execFileSync)\s*\(/;
    let out = sanitizeInterpolations(line, SHELL_SAFE);
    if (out !== line) return out;
    if (!execCall.test(line)) return line;
    const range = findCallArgs(line, execCall);
    if (!range) return line;
    const args = splitArgs(line.slice(range.start, range.end));
    const first = args[0] ?? '';
    if (!first.trim() || isStringLiteral(first)) return line;
    let newFirst: string;
    if (first.includes('+')) {
        newFirst = first.replace(/\+\s*([A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*|\[[^\]]+\])*)/g, (_m, expr: string) => `+ String(${expr})${SHELL_SAFE}`);
    } else {
        const lead = (first.match(/^\s*/) || [''])[0];
        newFirst = `${lead}String(${first.trim()})${SHELL_SAFE_CMD}`;
    }
    if (newFirst === first) return line;
    args[0] = newFirst;
    out = line.slice(0, range.start) + args.join(',') + line.slice(range.end);
    return out;
}

function mutateXssLine(line: string): string {
    if (/\.(?:send|write|end|render)\s*\(|innerHTML|outerHTML|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|`/.test(line)) {
        const viaTemplate = sanitizeInterpolations(line, HTML_ESCAPE);
        if (viaTemplate !== line) return viaTemplate;
    }
    const sinkCall = /(?:\.(?:send|write|end)|document\.write(?:ln)?)\s*\(/;
    const viaCall = wrapFirstArg(line, sinkCall, (arg) => `String(${arg})${HTML_ESCAPE}`);
    if (viaCall !== line) return viaCall;
    const assign = line.replace(/(\.(?:innerHTML|outerHTML)\s*=\s*)([^;]+)(;?)/, (_m, lhs: string, rhs: string, semi: string) =>
        `${lhs}String(${rhs.trim()})${HTML_ESCAPE}${semi}`);
    return assign;
}

function mutatePathLine(line: string): string {
    const joinCall = /(?:\bpath\.|(?<![\w$.]))(?:join|resolve|normalize)\s*\(/;
    const range = findCallArgs(line, joinCall);
    if (range) {
        const args = splitArgs(line.slice(range.start, range.end));
        let changed = false;
        for (let i = args.length > 1 ? 1 : 0; i < args.length; i++) {
            const a = args[i];
            if (!a.trim() || isStringLiteral(a) || /^\s*__dirname\s*$/.test(a)) continue;
            const lead = (a.match(/^\s*/) || [''])[0];
            args[i] = `${lead}String(${a.trim()})${PATH_SAFE}`;
            changed = true;
        }
        if (changed) return line.slice(0, range.start) + args.join(',') + line.slice(range.end);
    }
    const fsCall = /\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|stat|statSync|access|accessSync|open|openSync|sendFile|download)\s*\(/;
    const viaFs = wrapFirstArg(line, fsCall, (arg) => `String(${arg})${BASENAME}`);
    if (viaFs !== line) return viaFs;
    return sanitizeInterpolations(line, PATH_SAFE);
}

function extractRequestArg(line: string): string | null {
    const call = /\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request|head))?|got(?:\.(?:get|post))?|request|needle|superagent\.(?:get|post)|(?:http|https)\.(?:get|request))\s*\(/;
    const range = findCallArgs(line, call);
    if (!range) return null;
    const first = splitArgs(line.slice(range.start, range.end))[0]?.trim();
    if (!first || isStringLiteral(first)) return null;
    return first;
}

function extractInputExpr(line: string): string | null {
    const req = line.match(/\breq(?:uest)?\.(?:body|query|params)(?:\.[A-Za-z_$][\w$]*|\[['"][^'"]+['"]\])?/);
    if (req) return req[0];
    if (/\binput\b/.test(line)) return 'input';
    return null;
}

function mutateSecretLine(line: string): string {
    const envRef = `(() => { try { return process.env.SECRET_KEY; } catch { return undefined; } })()`;
    let out = line
        .replace(/['"][^'"]*(?:sk-|sk_live_|ghp_|xox[bp]-|AKIA|password|secret|token|apiKey|api_key)[^'"]*['"]/gi, envRef)
        .replace(/=\s*['"][a-f0-9]{32,}['"]/gi, `= ${envRef}`);
    if (out !== line) return out;
    out = line.replace(
        /(\b[\w$]*(?:secret|password|passwd|token|api_?key|apikey|jwt|private_?key|credential)[\w$]*['"]?\s*[:=]\s*)(['"`])[^'"`]+\2/i,
        (_m, lhs: string) => `${lhs}${envRef}`,
    );
    return out;
}

function mutateEvalLine(line: string): string {
    return line
        .replace(/\beval\s*\(/g, 'String(')
        .replace(/\bnew\s+Function\s*\(/g, '((..._scArgs) => () => undefined)(')
        .replace(/\bvm\.runIn(?:New|This)?Context\s*\(/g, '((c, ..._scRest) => String(c))(')
        .replace(/\b(setTimeout|setInterval)\s*\(\s*(['"`])/g, '$1(() => {}, 0, $2');
}

/**
 * Apply a mutation operator for the given vulnerability type to the
 * vulnerable code. Returns the mutated (secure) code or `mutated: false`
 * if no operator is available.
 */
export function applyMutation(
    code: string,
    vulnerabilityType: string,
    line: number,
): MutationResult {
    const lines = code.split('\n');
    const lineIdx = Math.max(0, Math.min(line - 1, lines.length - 1));
    const targetLine = lines[lineIdx];
    const type = (TYPE_ALIASES[vulnerabilityType] ?? vulnerabilityType) as VulnerabilityType;

    const lineReplace = (mutateLine: (l: string) => string, description: string, missing: string): MutationResult => {
        const mutated = replaceAtNearbyLine(lines, lineIdx, mutateLine);
        if (!mutated) return { mutated: false, mutatedCode: code, description: missing };
        return { mutated: true, mutatedCode: mutated.join('\n'), description };
    };

    switch (type) {
        case 'broken_access_control':
        case 'missing_auth': {
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, denyGuard(indentOf(targetLine), 'forbidden'));
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added authentication/authorization guard (deny with 403) before the vulnerable line',
            };
        }

        case 'missing_ownership': {
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, denyGuard(indentOf(targetLine), 'not owner'));
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added ownership check (deny non-owner with 403) before the vulnerable line',
            };
        }

        case 'sql_injection':
            return lineReplace(
                (l) => l
                    .replace(/`([^`]*\$\{[^}]+\}[^`]*)`/g, '?')
                    .replace(/'([^']*\+[^']*)'/g, '?')
                    .replace(/"\s*\+\s*\w+\s*\+"/g, '?'),
                'Replaced SQL string interpolation with parameter placeholders',
                'No SQL interpolation found to mutate',
            );

        case 'path_traversal':
            return lineReplace(
                mutatePathLine,
                'Stripped path traversal sequences from user-controlled path segments (path traversal blocked)',
                'No path construction or file access found to mutate',
            );

        case 'command_injection':
            return lineReplace(
                mutateCommandLine,
                'Stripped shell metacharacters from values interpolated into the command',
                'No command injection pattern found to mutate',
            );

        case 'xss':
            return lineReplace(
                mutateXssLine,
                'HTML-escaped user-controlled output before it is rendered',
                'No HTML output sink found to mutate',
            );

        case 'ssrf': {
            for (const off of NEARBY_OFFSETS) {
                const idx = lineIdx + off;
                if (idx < 0 || idx >= lines.length) continue;
                const arg = extractRequestArg(lines[idx]);
                if (!arg) continue;
                const guard = `${indentOf(lines[idx])}if (/^(localhost|127\\.|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.|169\\.254\\.|0\\.|\\[?::1\\]?$|\\[?f[cd])/i.test(new URL(String(${arg}), 'http://invalid.invalid').hostname)) { throw new Error('SSRF blocked'); }`;
                const mutated = [...lines];
                mutated.splice(idx, 0, guard);
                return {
                    mutated: true,
                    mutatedCode: mutated.join('\n'),
                    description: 'Added private/loopback host blocklist before the outbound request (SSRF blocked)',
                };
            }
            return { mutated: false, mutatedCode: code, description: 'No outbound request with a dynamic URL found to mutate' };
        }

        case 'ssti':
            return lineReplace(
                (l) => l
                    .replace(/ejs\.render\(/g, 'String(')
                    .replace(/\brender\(/g, 'renderText('),
                'Replaced template rendering with safe string output',
                'No SSTI pattern found to mutate',
            );

        case 'missing_input_validation': {
            const expr = extractInputExpr(targetLine);
            if (!expr) {
                return { mutated: false, mutatedCode: code, description: 'No input expression found on the target line to validate' };
            }
            const guard = `${indentOf(targetLine)}if (!${expr} || typeof ${expr} !== 'string' || ${expr}.length > 1000) { throw new Error('invalid input'); }`;
            const mutated = [...lines];
            mutated.splice(lineIdx, 0, guard);
            return {
                mutated: true,
                mutatedCode: mutated.join('\n'),
                description: 'Added input validation guard',
            };
        }

        case 'secrets_in_source':
            return lineReplace(
                mutateSecretLine,
                'Replaced hardcoded secret with environment variable reference',
                'No hardcoded secret found to mutate',
            );

        case 'code_injection':
            return lineReplace(
                mutateEvalLine,
                'Replaced dynamic code evaluation with inert string handling',
                'No eval/new Function/vm call found to mutate',
            );

        default:
            return {
                mutated: false,
                mutatedCode: code,
                description: `No mutation operator available for vulnerability type: ${vulnerabilityType}`,
            };
    }
}
