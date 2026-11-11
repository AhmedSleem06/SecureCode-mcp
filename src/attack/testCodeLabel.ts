/**
 * Flags read_file observations whose code is test-only (test files, or
 * test helpers such as `static readonly layerTest = (` inside a prod
 * class) so the agent does not cite test defaults as production behaviour.
 */

const TEST_PATH = /(^|\/)(__tests__|__mocks__|tests?|specs?|fixtures?|mocks?|e2e|testdata)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)(test_[^/]*|[^/]*_test|conftest)\.py$|_test\.go$/i;

const JS_DECL = /^\s*(?:export\s+)?(?:default\s+)?(?:(?:public|private|protected|static|readonly|async|abstract|override|declare|get|set)\s+)*(?:(?:const|let|var|function\*?|class)\s+)?\*?([A-Za-z_$][\w$]*)\s*(?:[=(:<]|extends\b)/;
const PY_DECL = /^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)/;
const JS_TOP_LEVEL = /^(?:export\s+)?(?:default\s+)?(?:declare\s+)?(?:abstract\s+)?(?:async\s+)?(?:function|class|const|let|var|interface|type|enum)\b/;
const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*|#)/;

const HELPER_WORD = '(?:Test|Mock|Fake|Stub|Fixture)';
const TEST_NAME_PREFIX = new RegExp(`^(?:(?:mock|fake|stub|fixture)s?|${HELPER_WORD}s?|(?:make|create|build|setup|setUp|with)${HELPER_WORD}s?)(?:[A-Z_$\\d]|$)|^test_`);
const TEST_NAME_SUFFIX = new RegExp(`[a-z\\d]${HELPER_WORD}$|For(?:Test|Tests|Testing)$`);
const PREDICATE_PREFIX = /^(?:is|has|should|can|enable|disable|skip|allow|use)[A-Z]/;

const MAX_LOOKBACK = 400;

export function isTestPath(relPath: string): boolean {
    return TEST_PATH.test(relPath.replace(/\\/g, '/'));
}

export function isTestHelperName(name: string): boolean {
    if (TEST_NAME_PREFIX.test(name)) return true;
    return TEST_NAME_SUFFIX.test(name) && !PREDICATE_PREFIX.test(name);
}

function codeOf(line: string): string {
    return line
        .replace(/\\./g, '')
        .replace(/'[^']*'|"[^"]*"|`[^`]*`/g, '')
        .replace(/\/\/.*$/, '');
}

function bracketDelta(line: string): number {
    let delta = 0;
    for (const ch of codeOf(line)) {
        if (ch === '{' || ch === '(' || ch === '[') delta++;
        else if (ch === '}' || ch === ')' || ch === ']') delta--;
    }
    return delta;
}

function continuesExpression(line: string, next: string | undefined): boolean {
    return /(=>|=|\?\?|\?|&&|\|\|)\s*$/.test(codeOf(line).trimEnd()) || /^\s*\??\./.test(next ?? '');
}

function indentOf(line: string): number {
    return line.length - line.trimStart().length;
}

function testDeclName(line: string | undefined, python: boolean): string | null {
    if (line === undefined || COMMENT_LINE.test(line)) return null;
    const m = line.match(python ? PY_DECL : JS_DECL);
    return m && isTestHelperName(m[1]) ? m[1] : null;
}

function jsEncloses(lines: string[], declIdx: number, targetIdx: number): boolean {
    let balance = 0;
    for (let j = declIdx; j < targetIdx; j++) {
        balance += bracketDelta(lines[j] ?? '');
        if (balance < 0 || (balance === 0 && !continuesExpression(lines[j] ?? '', lines[j + 1]))) return false;
    }
    return true;
}

function pyEncloses(lines: string[], declIdx: number, targetIdx: number): boolean {
    const declIndent = indentOf(lines[declIdx]);
    for (let j = declIdx + 1; j <= targetIdx; j++) {
        const l = lines[j] ?? '';
        if (l.trim() === '') continue;
        if (indentOf(l) <= declIndent) return false;
    }
    return true;
}

function opensBlock(lines: string[], idx: number, python: boolean): boolean {
    return python ? /:\s*(#.*)?$/.test(lines[idx]) : bracketDelta(lines[idx]) > 0 || continuesExpression(lines[idx], lines[idx + 1]);
}

/**
 * Returns a one-line label when the read starting at `startLine` (1-based)
 * is test-only code, or when the read range (up to `endLine`) contains the
 * start of a test helper. Returns null for production code.
 */
export function testOnlyLabel(relPath: string, lines: string[], startLine: number, endLine?: number): string | null {
    if (isTestPath(relPath)) return '[TEST-ONLY CODE: test file — not production behaviour]';
    const python = /\.py$/i.test(relPath);
    const startIdx = Math.max(0, startLine - 1);

    for (let i = startIdx; i >= Math.max(0, startIdx - MAX_LOOKBACK); i--) {
        const name = testDeclName(lines[i], python);
        if (name && (i === startIdx || (python ? pyEncloses(lines, i, startIdx) : jsEncloses(lines, i, startIdx)))) {
            return `[TEST-ONLY CODE: inside ${name} (line ${i + 1}) — not production behaviour]`;
        }
        if (i < startIdx && (python ? /^\S/.test(lines[i] ?? '') && !COMMENT_LINE.test(lines[i]) && !/^@/.test(lines[i]) : JS_TOP_LEVEL.test(lines[i] ?? ''))) break;
    }

    const lastIdx = Math.min(lines.length, endLine ?? lines.length) - 1;
    for (let i = startIdx + 1; i <= lastIdx; i++) {
        const name = testDeclName(lines[i], python);
        if (name && opensBlock(lines, i, python)) {
            return `[CONTAINS TEST-ONLY CODE: ${name} starts at line ${i + 1} — code inside it is not production behaviour]`;
        }
    }
    return null;
}
