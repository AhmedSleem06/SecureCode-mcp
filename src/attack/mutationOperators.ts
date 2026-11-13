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

import * as path from 'path';
import * as vm from 'vm';

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

export type MutationSyntaxCheck = 'typescript' | 'vm' | 'none';

export interface MutationResult {
    mutated: boolean;
    mutatedCode: string;
    description: string;
    /** Parser that validated the mutated code; 'none' when no parser applied. */
    syntaxCheck?: MutationSyntaxCheck;
}

export const INVALID_MUTATION_DESCRIPTION = 'Mutation produced invalid code — skipped';

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

function denyGuard(indent: string, message: string, resName = 'res'): string {
    const r = resName;
    return `${indent}if (typeof ${r} !== 'undefined' && ${r} && typeof ${r}.status === 'function') { const __scR = ${r}.status(403); return __scR && typeof __scR.json === 'function' ? __scR.json({ error: '${message}' }) : (__scR && typeof __scR.send === 'function' ? __scR.send('${message}') : __scR); } else if (typeof ${r} !== 'undefined' && ${r} && typeof ${r}.end === 'function') { ${r}.statusCode = 403; return ${r}.end('${message}'); } else { return null; }`;
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
    const envRef = `(() => { try { return process.env.SECRET_KEY ?? ''; } catch { return ''; } })()`;
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

const REGEX_PREFIX_WORDS = new Set(['return', 'typeof', 'case', 'in', 'of', 'new', 'delete', 'void', 'throw', 'yield', 'await', 'instanceof', 'else', 'do']);
const REGEX_PREFIX_CHARS = '(,=:[!&|?{};+-*%<>~^';

/**
 * Replace string, template, comment and regex contents with spaces (newlines
 * kept) so braces and parens in the result are real code structure.
 */
function maskCode(code: string): string {
    const out = code.split('');
    const n = code.length;
    const blank = (from: number, to: number) => {
        for (let k = from; k < to && k < n; k++) if (out[k] !== '\n' && out[k] !== '\r') out[k] = ' ';
    };
    const tplDepths: number[] = [];
    let depth = 0;
    let inTemplate = false;
    let lastSig = '';
    let lastWord = '';
    let i = 0;
    while (i < n) {
        const ch = code[i];
        if (inTemplate) {
            if (ch === '\\') { blank(i, i + 2); i += 2; continue; }
            if (ch === '`') { blank(i, i + 1); i++; inTemplate = false; lastSig = 'a'; lastWord = ''; continue; }
            if (ch === '$' && code[i + 1] === '{') { blank(i, i + 2); i += 2; tplDepths.push(depth); inTemplate = false; lastSig = '{'; continue; }
            blank(i, i + 1); i++; continue;
        }
        if (/\s/.test(ch)) { i++; continue; }
        if (ch === '/' && code[i + 1] === '/') {
            let k = i; while (k < n && code[k] !== '\n') k++;
            blank(i, k); i = k; continue;
        }
        if (ch === '/' && code[i + 1] === '*') {
            const end = code.indexOf('*/', i + 2);
            const k = end < 0 ? n : end + 2;
            blank(i, k); i = k; continue;
        }
        if (ch === '"' || ch === "'") {
            let k = i + 1;
            while (k < n && code[k] !== ch && code[k] !== '\n') k += code[k] === '\\' ? 2 : 1;
            blank(i, k + 1); i = k + 1; lastSig = 'a'; lastWord = ''; continue;
        }
        if (ch === '`') { blank(i, i + 1); i++; inTemplate = true; continue; }
        if (ch === '/') {
            const regexAllowed = lastSig === '' || REGEX_PREFIX_CHARS.includes(lastSig) || REGEX_PREFIX_WORDS.has(lastWord);
            if (regexAllowed) {
                let k = i + 1;
                let inClass = false;
                while (k < n && code[k] !== '\n') {
                    const c = code[k];
                    if (c === '\\') { k += 2; continue; }
                    if (c === '[') inClass = true;
                    else if (c === ']') inClass = false;
                    else if (c === '/' && !inClass) break;
                    k++;
                }
                if (k < n && code[k] === '/') {
                    k++;
                    while (k < n && /[A-Za-z]/.test(code[k])) k++;
                    blank(i, k); i = k; lastSig = 'a'; lastWord = ''; continue;
                }
            }
            lastSig = '/'; lastWord = ''; i++; continue;
        }
        if (/[A-Za-z_$\d]/.test(ch)) {
            let k = i; while (k < n && /[\w$]/.test(code[k])) k++;
            lastWord = code.slice(i, k); lastSig = code[k - 1]; i = k; continue;
        }
        if (ch === '{') depth++;
        if (ch === '}') {
            if (tplDepths.length > 0 && tplDepths[tplDepths.length - 1] === depth) {
                tplDepths.pop(); blank(i, i + 1); i++; inTemplate = true; continue;
            }
            depth--;
        }
        lastSig = ch; lastWord = ''; i++;
    }
    return out.join('');
}

interface FunctionSpan {
    sigStart: number;
    bodyOpen: number;
    bodyClose: number;
    params: string[];
    returnAnnotation: string;
}

const CONTROL_WORDS = new Set(['if', 'for', 'while', 'switch', 'catch', 'with', 'return', 'typeof', 'await', 'yield', 'new', 'in', 'of', 'else', 'do']);

function skipWsBack(s: string, j: number): number {
    while (j >= 0 && /\s/.test(s[j])) j--;
    return j;
}

function matchBack(s: string, closeIdx: number, open: string, close: string): number {
    let d = 0;
    for (let j = closeIdx; j >= 0; j--) {
        if (s[j] === close) d++;
        else if (s[j] === open) { d--; if (d === 0) return j; }
    }
    return -1;
}

function paramNames(paramsText: string): string[] {
    return splitArgs(paramsText).map((p) => {
        const t = p.trim()
            .replace(/^(?:@[\w$.]+(?:\([^)]*\))?\s*)+/, '')
            .replace(/^(?:(?:public|private|protected|readonly|override)\s+)+/, '')
            .replace(/^\.\.\./, '');
        const m = t.match(/^([A-Za-z_$][\w$]*)/);
        return m ? m[1] : '';
    });
}

function functionHead(s: string, open: number): Omit<FunctionSpan, 'bodyOpen' | 'bodyClose'> | null {
    let j = skipWsBack(s, open - 1);
    if (j < 0) return null;
    let arrow = false;
    if (s[j] === '>' && s[j - 1] === '=') { arrow = true; j = skipWsBack(s, j - 2); }
    let returnAnnotation = '';
    if (s[j] !== ')') {
        const seg = s.slice(Math.max(0, j - 300), j + 1);
        const ann = seg.match(/\)(\s*:\s*[^(){};=]*[^(){};=\s])$/);
        if (ann) {
            returnAnnotation = ann[1];
            j -= ann[1].length;
        } else if (arrow) {
            const id = seg.match(/(?:^|[^\w$.])([A-Za-z_$][\w$]*)$/);
            if (!id || CONTROL_WORDS.has(id[1])) return null;
            return { sigStart: j - id[1].length + 1, params: [id[1]], returnAnnotation: '' };
        } else {
            return null;
        }
    }
    const po = matchBack(s, j, '(', ')');
    if (po < 0) return null;
    const params = paramNames(s.slice(po + 1, j));
    if (arrow) return { sigStart: po, params, returnAnnotation };
    let k = skipWsBack(s, po - 1);
    if (s[k] === '>') {
        const lt = matchBack(s, k, '<', '>');
        if (lt < 0) return null;
        k = skipWsBack(s, lt - 1);
    }
    const word = s.slice(Math.max(0, k - 200), k + 1).match(/([A-Za-z_$][\w$]*)$/);
    if (!word || CONTROL_WORDS.has(word[1])) return null;
    return { sigStart: k - word[1].length + 1, params, returnAnnotation };
}

function findFunctionSpans(masked: string): FunctionSpan[] {
    const spans: FunctionSpan[] = [];
    const stack: number[] = [];
    for (let i = 0; i < masked.length; i++) {
        const ch = masked[i];
        if (ch === '{') stack.push(i);
        else if (ch === '}' && stack.length > 0) {
            const open = stack.pop()!;
            const head = functionHead(masked, open);
            if (!head) continue;
            spans.push({ ...head, bodyOpen: open, bodyClose: i });
        }
    }
    return spans;
}

function lineStartsOf(code: string): number[] {
    const starts = [0];
    for (let i = 0; i < code.length; i++) if (code[i] === '\n') starts.push(i + 1);
    return starts;
}

function lineAt(starts: number[], index: number): number {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (starts[mid] <= index) lo = mid; else hi = mid - 1;
    }
    return lo;
}

const RESPONSE_PARAMS = new Set(['res', 'reply', 'response']);

function responseParam(fn: FunctionSpan): string | null {
    const named = fn.params.find((p) => RESPONSE_PARAMS.has(p));
    if (named) return named;
    if ((fn.params[0] === 'req' || fn.params[0] === 'request') && fn.params[1]) return fn.params[1];
    return null;
}

function returnsBoolean(fn: FunctionSpan, masked: string, spans: FunctionSpan[]): boolean {
    if (/^\s*:\s*(?:Promise\s*<\s*)?boolean\s*>?\s*$/.test(fn.returnAnnotation)) return true;
    let body = masked.slice(fn.bodyOpen + 1, fn.bodyClose);
    for (const inner of spans) {
        if (inner === fn || inner.sigStart <= fn.bodyOpen || inner.bodyClose >= fn.bodyClose) continue;
        const a = inner.sigStart - fn.bodyOpen - 1;
        const b = inner.bodyClose - fn.bodyOpen;
        body = body.slice(0, a) + ' '.repeat(b - a) + body.slice(b);
    }
    return /\breturn\s+(?:true|false)\b/.test(body);
}

function insertAtBodyStart(code: string, masked: string, starts: number[], fn: FunctionSpan, statement: (indent: string) => string): string {
    const lines = code.split('\n');
    const openLine = lineAt(starts, fn.bodyOpen);
    const closeLine = lineAt(starts, fn.bodyClose);
    const lineEnd = openLine + 1 < starts.length ? starts[openLine + 1] - 1 : code.length;
    if (closeLine === openLine || masked.slice(fn.bodyOpen + 1, lineEnd).trim() !== '') {
        return code.slice(0, fn.bodyOpen + 1) + ' ' + statement('') + code.slice(fn.bodyOpen + 1);
    }
    let indent = indentOf(lines[openLine]) + '    ';
    for (let l = openLine + 1; l < closeLine; l++) {
        if (lines[l].trim()) { indent = indentOf(lines[l]); break; }
    }
    const mutated = [...lines];
    mutated.splice(openLine + 1, 0, statement(indent) + (lines[openLine].endsWith('\r') ? '\r' : ''));
    return mutated.join('\n');
}

function mutateAccessControl(code: string, lineIdx: number, message: string, what: string): MutationResult {
    const masked = maskCode(code);
    const starts = lineStartsOf(code);
    const spans = findFunctionSpans(masked);
    const enclosing = spans
        .filter((fn) => lineAt(starts, fn.sigStart) <= lineIdx && lineIdx <= lineAt(starts, fn.bodyClose))
        .sort((a, b) => (a.bodyClose - a.sigStart) - (b.bodyClose - b.sigStart));
    if (enclosing.length === 0) {
        return { mutated: false, mutatedCode: code, description: 'Finding line is not inside a function — no safe access-control mutation' };
    }
    const inner = enclosing[0];
    const innerRes = responseParam(inner);
    if (!innerRes && returnsBoolean(inner, masked, spans)) {
        return {
            mutated: true,
            mutatedCode: insertAtBodyStart(code, masked, starts, inner, (indent) => `${indent}return false;`),
            description: `Added ${what} (deny by returning false) at the start of the enclosing function`,
        };
    }
    for (const fn of enclosing) {
        const resName = responseParam(fn);
        if (!resName) continue;
        return {
            mutated: true,
            mutatedCode: insertAtBodyStart(code, masked, starts, fn, (indent) => denyGuard(indent, message, resName)),
            description: `Added ${what} (deny with 403) at the start of the enclosing handler`,
        };
    }
    return { mutated: false, mutatedCode: code, description: 'No safe access-control mutation for this function shape' };
}

const JS_EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const VM_EXTS = new Set(['', '.js', '.cjs']);

let typescriptModule: any | null | undefined;

function loadTypeScript(): any | null {
    if (typescriptModule === undefined) {
        try {
            typescriptModule = require('typescript');
        } catch {
            typescriptModule = null;
        }
    }
    return typescriptModule;
}

function typescriptProblems(ts: any, code: string, ext: string): { count: number; first: string } {
    const kind = ext === '.tsx' ? ts.ScriptKind.TSX
        : ext === '.jsx' ? ts.ScriptKind.JSX
            : ext === '.ts' || ext === '.mts' || ext === '.cts' ? ts.ScriptKind.TS
                : ts.ScriptKind.JS;
    const sf = ts.createSourceFile(`mutated${ext || '.js'}`, code, ts.ScriptTarget.Latest, true, kind);
    const diags: any[] = sf.parseDiagnostics ?? [];
    let count = diags.length;
    let first = diags.length > 0 ? ts.flattenDiagnosticMessageText(diags[0].messageText, ' ') : '';
    const visit = (node: any, inFunction: boolean) => {
        if (node.kind === ts.SyntaxKind.ReturnStatement && !inFunction) {
            count++;
            if (!first) first = `return statement outside a function (line ${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1})`;
        }
        const nested = inFunction || ts.isFunctionLike(node) || ts.isClassStaticBlockDeclaration(node);
        ts.forEachChild(node, (child: any) => visit(child, nested));
    };
    visit(sf, false);
    return { count, first };
}

function vmProblem(code: string): string | null {
    try {
        new vm.Script(code, { filename: 'mutated.js' });
        return null;
    } catch (err: any) {
        return String(err?.message || err);
    }
}

function checkMutationSyntax(original: string, mutated: string, filePath?: string): { checker: MutationSyntaxCheck; invalid: boolean; detail: string } {
    const ext = filePath ? path.extname(filePath).toLowerCase() : '';
    if (ext && !JS_EXTS.has(ext)) return { checker: 'none', invalid: false, detail: '' };
    const ts = loadTypeScript();
    if (ts) {
        const before = typescriptProblems(ts, original, ext);
        const after = typescriptProblems(ts, mutated, ext);
        return { checker: 'typescript', invalid: after.count > before.count, detail: after.first };
    }
    if (VM_EXTS.has(ext) && vmProblem(original) === null) {
        const problem = vmProblem(mutated);
        return { checker: 'vm', invalid: problem !== null, detail: problem ?? '' };
    }
    return { checker: 'none', invalid: false, detail: '' };
}

export function normalizeVulnerabilityType(vulnerabilityType: string): string {
    return TYPE_ALIASES[vulnerabilityType] ?? vulnerabilityType;
}

/**
 * Apply a mutation operator for the given vulnerability type to the
 * vulnerable code. Returns the mutated (secure) code or `mutated: false`
 * if no operator is available or the mutated code does not parse.
 */
export function applyMutation(
    code: string,
    vulnerabilityType: string,
    line: number,
    filePath?: string,
): MutationResult {
    const result = mutateSource(code, vulnerabilityType, line);
    if (!result.mutated) return result;
    const check = checkMutationSyntax(code, result.mutatedCode, filePath);
    if (check.invalid) {
        return {
            mutated: false,
            mutatedCode: code,
            description: `${INVALID_MUTATION_DESCRIPTION}${check.detail ? `: ${check.detail}` : ''}`,
            syntaxCheck: check.checker,
        };
    }
    return { ...result, syntaxCheck: check.checker };
}

function mutateSource(
    code: string,
    vulnerabilityType: string,
    line: number,
): MutationResult {
    const lines = code.split('\n');
    const lineIdx = Math.max(0, Math.min(line - 1, lines.length - 1));
    const targetLine = lines[lineIdx];
    const type = normalizeVulnerabilityType(vulnerabilityType) as VulnerabilityType;

    const lineReplace = (mutateLine: (l: string) => string, description: string, missing: string): MutationResult => {
        const mutated = replaceAtNearbyLine(lines, lineIdx, mutateLine);
        if (!mutated) return { mutated: false, mutatedCode: code, description: missing };
        return { mutated: true, mutatedCode: mutated.join('\n'), description };
    };

    switch (type) {
        case 'broken_access_control':
        case 'missing_auth':
            return mutateAccessControl(code, lineIdx, 'forbidden', 'authentication/authorization guard');

        case 'missing_ownership':
            return mutateAccessControl(code, lineIdx, 'not owner', 'ownership check');

        case 'sql_injection':
            return lineReplace(
                (l) => l
                    .replace(/`([^`]*\$\{[^}]+\}[^`]*)`/g, (tpl) => tpl.replace(/\$\{[^}]+\}/g, '?'))
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
