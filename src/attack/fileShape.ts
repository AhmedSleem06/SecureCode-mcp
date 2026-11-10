/**
 * File-shape heuristics: decide whether a source file only declares types
 * (interfaces, type aliases, ambient declarations, tag-only classes) and has
 * no implementation worth scanning on its own.
 */

export interface FileShapeBoundary {
    name: string;
    startLine: number;
    endLine: number;
}

const OPEN = new Set(['(', '{', '[']);
const CLOSE = new Set([')', '}', ']']);
const CONTINUE_AFTER = new Set(['=', ',', '|', '&', '.', '(', '<', ':', '?', '+', '-', '*', '/', '%', '!', '{', '[']);
const CONTINUE_BEFORE = new Set(['.', ',', '|', '&', '=', ')', ']', '}', '>', '?', ':', '+', '*', '/', '%']);
const STATEMENT_KEYWORDS = /\b(return|await|yield|throw)\b|\b(if|for|while|switch)\s*\(/;
const TAG_CALL_INITIALIZER = /^(Context|ServiceMap|Data|Schema)\.[A-Za-z]+\s*(<[\s\S]*>)?\s*(\(\s*(""\s*)?\)\s*)+$/;

function stripCommentsAndStrings(src: string): string {
    let out = '';
    let i = 0;
    while (i < src.length) {
        const ch = src[i];
        const next = src[i + 1];
        if (ch === '/' && next === '/') {
            while (i < src.length && src[i] !== '\n') i++;
            continue;
        }
        if (ch === '/' && next === '*') {
            i += 2;
            while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
                if (src[i] === '\n') out += '\n';
                i++;
            }
            i += 2;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
            const quote = ch;
            i++;
            while (i < src.length && src[i] !== quote) {
                if (src[i] === '\\') i++;
                else if (quote !== '`' && src[i] === '\n') break;
                i++;
            }
            i++;
            out += '""';
            continue;
        }
        out += ch;
        i++;
    }
    return out;
}

function lastSignificantChar(text: string): string {
    const trimmed = text.trimEnd();
    return trimmed.length > 0 ? trimmed[trimmed.length - 1] : '';
}

function nextSignificantChar(src: string, from: number): string {
    for (let i = from; i < src.length; i++) {
        if (!/\s/.test(src[i])) return src[i];
    }
    return '';
}

function splitStatements(src: string): string[] {
    const statements: string[] = [];
    let depth = 0;
    let current = '';
    const push = () => {
        const trimmed = current.trim();
        if (trimmed.length > 0) statements.push(trimmed);
        current = '';
    };
    for (let i = 0; i < src.length; i++) {
        const ch = src[i];
        if (OPEN.has(ch)) depth++;
        else if (CLOSE.has(ch)) depth = Math.max(0, depth - 1);
        if (depth === 0 && ch === ';') {
            push();
            continue;
        }
        if (depth === 0 && ch === '\n') {
            const last = lastSignificantChar(current);
            const upcoming = nextSignificantChar(src, i + 1);
            const endsWithKeyword = /\b(extends|implements|from|as|in|of|typeof|keyof|new|export|import|declare|type|interface|class)\s*$/.test(current);
            if (last && !CONTINUE_AFTER.has(last) && !CONTINUE_BEFORE.has(upcoming) && !endsWithKeyword) {
                push();
                continue;
            }
        }
        current += ch;
    }
    push();
    return statements;
}

function topLevelGroups(text: string, open: string, close: string): Array<{ start: number; end: number }> {
    const groups: Array<{ start: number; end: number }> = [];
    let depth = 0;
    let groupStart = -1;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (OPEN.has(ch)) {
            if (depth === 0 && ch === open) groupStart = i;
            depth++;
        } else if (CLOSE.has(ch)) {
            depth = Math.max(0, depth - 1);
            if (depth === 0 && ch === close && groupStart >= 0) {
                groups.push({ start: groupStart, end: i });
                groupStart = -1;
            }
        }
    }
    return groups;
}

function hasTopLevelChar(text: string, target: string): boolean {
    let depth = 0;
    for (const ch of text) {
        if (OPEN.has(ch)) {
            if (depth === 0 && ch === target) return true;
            depth++;
        } else if (CLOSE.has(ch)) {
            depth = Math.max(0, depth - 1);
        } else if (depth === 0 && ch === target) {
            return true;
        }
    }
    return false;
}

function lastBlockBody(statement: string): string | null {
    if (!statement.endsWith('}')) return null;
    const groups = topLevelGroups(statement, '{', '}');
    const last = groups[groups.length - 1];
    if (!last || last.end !== statement.length - 1) return null;
    return statement.slice(last.start + 1, last.end);
}

function isClassBodyDeclarative(body: string): boolean {
    for (const member of splitStatements(body)) {
        const m = member.replace(/=>/g, '->');
        if (hasTopLevelChar(m, '=')) return false;
        if (/^static\s*\{/.test(m)) {
            const block = lastBlockBody(m);
            if (block && block.trim().length > 0) return false;
            continue;
        }
        if (hasTopLevelChar(m, '(') && m.endsWith('}')) {
            const block = lastBlockBody(m);
            if (block !== null && block.trim().length > 0) return false;
        }
    }
    return true;
}

type StatementKind = 'type' | 'neutral' | 'runtime';

function classifyStatement(raw: string): StatementKind {
    let s = raw.trim();
    if (s === '""') return 'neutral';
    if (/^import\s*\(/.test(s) || /^import\s*\.\s*meta/.test(s)) return 'runtime';
    if (/^import\s*""/.test(s)) return 'runtime';
    if (/^import\b/.test(s)) return 'neutral';
    if (/^export\s*\*/.test(s) || /^export\s+type\s*\*/.test(s) || /^export\s+(type\s+)?\{/.test(s) || /^export\s*\{/.test(s)) return 'neutral';
    if (/^export\s*=/.test(s) || /^export\s+as\s+namespace\b/.test(s)) return 'neutral';

    s = s.replace(/^export\s+/, '');
    if (/^default\s+/.test(s)) {
        s = s.replace(/^default\s+/, '');
        if (!/^(abstract\s+class|class|interface)\b/.test(s)) return 'runtime';
    }
    if (/^declare\b/.test(s)) return 'type';
    if (/^interface\b/.test(s)) return 'type';
    if (/^type\s+[A-Za-z_$]/.test(s)) return 'type';

    if (/^(abstract\s+)?class\b/.test(s)) {
        const body = lastBlockBody(s);
        if (body === null) return 'runtime';
        return isClassBodyDeclarative(body) ? 'type' : 'runtime';
    }

    if (/^(async\s+)?function\b/.test(s)) {
        if (!s.endsWith('}')) return 'neutral';
        const body = lastBlockBody(s);
        return body !== null && body.trim().length === 0 ? 'neutral' : 'runtime';
    }

    if (/^(namespace|module)\s/.test(s)) {
        const body = lastBlockBody(s);
        if (body === null) return 'runtime';
        return isDeclarationBlock(body) ? 'type' : 'runtime';
    }

    if (/^(const|let|var)\s/.test(s) && !/^const\s+enum\b/.test(s)) {
        const match = /^(const|let|var)\s+[A-Za-z_$][\w$]*\s*(:[^=]*)?=\s*([\s\S]*)$/.exec(s);
        if (match && TAG_CALL_INITIALIZER.test(match[3].trim())) return 'type';
        return 'runtime';
    }

    return 'runtime';
}

function isDeclarationBlock(src: string): boolean {
    let typeStatements = 0;
    for (const statement of splitStatements(src)) {
        const kind = classifyStatement(statement);
        if (kind === 'runtime') return false;
        if (kind === 'type') typeStatements++;
    }
    return typeStatements > 0;
}

/**
 * True when the file only declares types: imports, interfaces, type aliases,
 * `declare` statements, type re-exports, and tag-only classes such as
 * Effect `ServiceMap.Service<...>()("tag") {}` declarations. Any function or
 * method body with statements, variable initializer, enum, or top-level
 * expression (e.g. `app.listen()`) makes it false.
 */
export function detectDeclarationOnly(content: string, functionBoundaries?: FileShapeBoundary[] | null): boolean {
    if (!content || content.trim().length === 0) return false;
    if (functionBoundaries && functionBoundaries.length > 0) {
        const lines = content.split('\n');
        for (const fn of functionBoundaries) {
            const text = stripCommentsAndStrings(lines.slice(Math.max(0, fn.startLine - 1), fn.endLine).join('\n'));
            if (STATEMENT_KEYWORDS.test(text)) return false;
        }
    }
    try {
        return isDeclarationBlock(stripCommentsAndStrings(content));
    } catch {
        return false;
    }
}
