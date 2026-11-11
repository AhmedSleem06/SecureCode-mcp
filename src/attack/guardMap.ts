const GUARD_PATTERN = /\b((?:require|assert|ensure|check|verify|authorize|can|is|has)(?:[A-Z]\w*?)?(?:Owner|Admin|Auth\w*|Role|Permission|Session|Access|Allowed|Authorized)\w*)\b/g;

const MAX_IDENTIFIERS = 12;
const MAX_LINES_PER_IDENTIFIER = 30;
const HEADER = 'Authorization checks used in this file:';

interface GuardUse {
    name: string;
    count: number;
    lines: number[];
}

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isDefinition(line: string, name: string): boolean {
    const n = escapeRegExp(name);
    return new RegExp(`\\bfunction\\s*\\*?\\s*${n}\\b`).test(line)
        || new RegExp(`\\bdef\\s+${n}\\b`).test(line)
        || new RegExp(`\\b(?:const|let|var)\\s+${n}\\b`).test(line)
        || new RegExp(`\\b(?:const|let|var)\\s+\\{[^}]*\\b${n}\\b[^}]*\\}\\s*=`).test(line)
        || new RegExp(`^\\s*${n}\\s*:\\s*(?:async\\b|function\\b|\\(|[A-Za-z_$][\\w$]*\\s*=>)`).test(line)
        || new RegExp(`^\\s*(?:(?:export|public|private|protected|static|async|readonly)\\s+)*${n}\\s*(?:<[^>]*>)?\\([^)]*\\)\\s*(?::[^{=]*)?\\{\\s*$`).test(line);
}

export function buildGuardMap(code: string, maxChars = 1500): string {
    const uses = new Map<string, GuardUse>();
    const lines = code.split('\n');
    let inBlockComment = false;
    let inImport = false;

    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const trimmed = raw.trim();

        if (inBlockComment) {
            if (trimmed.includes('*/')) inBlockComment = false;
            continue;
        }
        if (trimmed.startsWith('/*')) {
            if (!trimmed.includes('*/')) inBlockComment = true;
            continue;
        }
        if (/^(?:\/\/|\*|#)/.test(trimmed)) continue;

        if (inImport) {
            if (/[})]/.test(trimmed)) inImport = false;
            continue;
        }
        if (/^(?:import|from)\b/.test(trimmed) || /^export\s+(?:type\s+)?(?:\{|\*)/.test(trimmed)) {
            if (/[{(,]\s*$/.test(trimmed)) inImport = true;
            continue;
        }

        const lineText = raw.replace(/\/\/.*$/, '');
        GUARD_PATTERN.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = GUARD_PATTERN.exec(lineText)) !== null) {
            const name = m[1];
            if (isDefinition(lineText, name)) continue;
            let use = uses.get(name);
            if (!use) {
                use = { name, count: 0, lines: [] };
                uses.set(name, use);
            }
            use.count++;
            const lineNo = i + 1;
            if (use.lines[use.lines.length - 1] !== lineNo) use.lines.push(lineNo);
        }
    }

    if (uses.size === 0) return '';

    const sorted = [...uses.values()].sort((a, b) =>
        b.count - a.count || a.lines[0] - b.lines[0] || a.name.localeCompare(b.name));
    const shown = sorted.slice(0, MAX_IDENTIFIERS);
    const rendered = shown.map(u => {
        const at = u.lines.slice(0, MAX_LINES_PER_IDENTIFIER).join(', ');
        const more = u.lines.length > MAX_LINES_PER_IDENTIFIER ? ', …' : '';
        return `${u.name}: used at ${at}${more} (${u.count} use${u.count === 1 ? '' : 's'})`;
    });
    if (sorted.length > shown.length) rendered.push(`… ${sorted.length - shown.length} more`);

    let out = HEADER;
    for (const line of rendered) {
        const next = `${out}\n${line}`;
        if (next.length <= maxChars) {
            out = next;
            continue;
        }
        const room = maxChars - out.length - 2;
        if (room >= 20) out = `${out}\n${line.slice(0, room)}…`;
        break;
    }
    return out === HEADER ? '' : out;
}
