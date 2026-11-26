import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { discoverEndpoints } from '../project-map/endpointDiscovery';
import { extractFunctionBoundaries, type FunctionBoundary } from '../attack/agentScanExecutor';
import { trackTaint, type TaintResult } from '../project-map/taintTracker';
import { trackTaintCrossFile, type CrossFileTaintResult } from '../project-map/crossFileTaintTracker';
import { findSinks, type SinkFinding } from '../project-map/sinkFinder';
import { evaluateGuards, type AttackType } from '../project-map/guardEvaluator';
import { buildGuardMap } from '../attack/guardMap';
import { isTestPath } from '../attack/testCodeLabel';
import { getRelatedFilesForFile } from '../project-map/mapContext';
import { findReferences } from '../project-map/symbolIndex';
import { resolveSpec } from '../project-map/relatedFiles';
import { grammarForFile } from '../project-map/parserLoader';
import { TAINT_SOURCES } from '../project-map/taintSources';
import { searchCode } from '../utils/searchCode';
import type { SinkLanguage } from '../project-map/sinkRegistry';
import type {
    ConnectedRelation,
    FileInventory,
    InventoryConnectedFile,
    InventoryEntryPoint,
    InventoryFlow,
    InventoryGuard,
    InventoryInput,
    InventorySink,
} from './types';

export type {
    FileInventory,
    InventoryEntryPoint,
    InventoryInput,
    InventorySink,
    InventoryGuard,
    InventoryConnectedFile,
    InventoryFlow,
} from './types';

export const INVENTORY_LIST_CAP = 200;
export const INVENTORY_CONNECTED_CAP = 25;

const STEP_TIMEOUT_MS = 2500;
const MAX_RANGE_LINES = 600;
const MAX_GUARD_EVALS = 15;
const MAX_REFERENCE_SYMBOLS = 3;

const ATTACK_TYPES: ReadonlySet<string> = new Set<AttackType>([
    'sql_injection', 'nosql_injection', 'command_injection', 'xss', 'ssrf', 'path_traversal',
    'open_redirect', 'prototype_pollution', 'insecure_deserialization', 'broken_access_control',
]);

const LIFECYCLE_EVENTS = new Set([
    'connection', 'connect', 'message', 'close', 'error', 'disconnect', 'disconnecting', 'open',
    'upgrade', 'listening', 'end', 'data', 'request', 'headers', 'ping', 'pong', 'ready',
]);

const SKIP_DIRS = new Set([
    'node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.nuxt', '.securecode',
    '.venv', 'venv', '__pycache__', '.turbo', '.cache', 'vendor', 'target',
]);
const CODE_EXT = /\.(?:ts|tsx|js|jsx|mjs|cjs|py)$/i;

interface Ctx {
    workspaceRoot: string;
    abs: string;
    rel: string;
    content: string;
    lines: string[];
    grammar: ReturnType<typeof grammarForFile>;
    failed: string[];
    truncated: string[];
    timings: Record<string, number>;
}

interface RawEntry {
    kind: InventoryEntryPoint['kind'];
    name: string;
    line: number;
    endLine: number;
    method?: string;
    path?: string;
    framework?: string;
    middleware?: string[];
    handlerParam?: string;
}

async function withTimeout<T>(p: Promise<T>, ms: number, fallback: T): Promise<{ value: T; timedOut: boolean }> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<{ value: T; timedOut: boolean }>(resolve => {
        timer = setTimeout(() => resolve({ value: fallback, timedOut: true }), ms);
        timer.unref?.();
    });
    try {
        return await Promise.race([p.then(value => ({ value, timedOut: false })), timeout]);
    } finally {
        if (timer) clearTimeout(timer);
    }
}

async function step<T>(ctx: Ctx, name: string, fallback: T, fn: () => Promise<T>, ms = STEP_TIMEOUT_MS): Promise<T> {
    const started = Date.now();
    try {
        const r = await withTimeout(fn().catch(() => { ctx.failed.push(name); return fallback; }), ms, fallback);
        if (r.timedOut) ctx.failed.push(`${name} (timeout)`);
        return r.value;
    } catch {
        ctx.failed.push(name);
        return fallback;
    } finally {
        ctx.timings[name] = Date.now() - started;
    }
}

function timed<T>(ctx: Ctx, name: string, fallback: T, fn: () => T): T {
    const started = Date.now();
    try {
        return fn();
    } catch {
        ctx.failed.push(name);
        return fallback;
    } finally {
        ctx.timings[name] = Date.now() - started;
    }
}

function toPosix(p: string): string {
    return p.replace(/\\/g, '/');
}

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isCommentLine(line: string): boolean {
    return /^\s*(?:\/\/|\/\*|\*|#(?!!))/.test(line);
}

function clip(s: string, max = 200): string {
    const t = s.trim().replace(/\s+/g, ' ');
    return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function findRangeEnd(lines: string[], startIdx: number, python: boolean): number {
    if (python) {
        const indent = lines[startIdx].match(/^\s*/)?.[0].length ?? 0;
        let last = startIdx;
        for (let i = startIdx + 1; i < lines.length && i - startIdx < MAX_RANGE_LINES; i++) {
            const l = lines[i];
            if (!l.trim()) continue;
            const ind = l.match(/^\s*/)?.[0].length ?? 0;
            if (ind <= indent && !/^\s*[)\]}]/.test(l)) break;
            last = i;
        }
        return last + 1;
    }
    let depth = 0;
    let opened = false;
    let inStr: string | null = null;
    let inBlock = false;
    const limit = Math.min(lines.length, startIdx + MAX_RANGE_LINES);
    for (let i = startIdx; i < limit; i++) {
        const l = lines[i];
        for (let j = 0; j < l.length; j++) {
            const c = l[j];
            if (inBlock) {
                if (c === '*' && l[j + 1] === '/') { inBlock = false; j++; }
                continue;
            }
            if (inStr) {
                if (c === '\\') { j++; continue; }
                if (c === inStr) inStr = null;
                continue;
            }
            if (c === '/' && l[j + 1] === '/') break;
            if (c === '/' && l[j + 1] === '*') { inBlock = true; j++; continue; }
            if (c === '"' || c === "'" || c === '`') { inStr = c; continue; }
            if (c === '(' || c === '{' || c === '[') { depth++; opened = true; }
            else if (c === ')' || c === '}' || c === ']') {
                depth--;
                if (depth < 0) return i + 1;
            }
        }
        if (inStr === "'" || inStr === '"') inStr = null;
        if (depth <= 0 && !inStr && !inBlock) {
            const trimmed = l.replace(/\/\/.*$/, '').trimEnd();
            if (/(?:=>|[=+\-*/?:&|,(]|\breturn)$/.test(trimmed) && !(opened && /,$/.test(trimmed))) continue;
            return i + 1;
        }
    }
    return limit;
}

function relPathOf(workspaceRoot: string, filePath: string): { abs: string; rel: string } {
    const abs = path.resolve(workspaceRoot || '.', filePath);
    let rel = toPosix(path.relative(workspaceRoot || '.', abs));
    if (!rel || rel.startsWith('../') || path.isAbsolute(rel)) rel = toPosix(filePath);
    return { abs, rel };
}

// ── Entry points ────────────────────────────────────────────────────────────

const HTTP_VERBS = 'get|post|put|patch|delete|del|all|options|head';
const HTTP_CALL_RE = new RegExp(
    `\\b([A-Za-z_$][\\w$]*)\\.(${HTTP_VERBS})\\s*\\(\\s*(['"\`])([^'"\`]*)\\3`,
);
const HTTP_RECEIVER_RE = /^(?:app|api|server|fastify|hono|koa|routes?|router|\w*(?:Router|router|App|app|Routes|routes|Api|api))$/;
const NEXT_RE = /^\s*export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/;
const DECORATOR_RE = /^\s*@(?:([A-Za-z_]\w*)\.)?(get|post|put|patch|delete|route|api_route|Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:(['"`])([^'"`]*)\3)?/;
const EFFECT_RE = /Http(?:ApiEndpoint|Router)\.(get|post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\2(?:\s*,\s*(['"`])([^'"`]*)\4)?/;
const DJANGO_RE = /^\s*(?:re_)?path\s*\(\s*r?(['"])([^'"]*)\1\s*,\s*([\w.]+)/;
const RPC_COMPUTED_RE = /^\s*\[\s*([A-Za-z_$][\w$]*(?:\.[\w$]+)+)\s*\]\s*:\s*(?:async\s+)?(?:\(\s*([^)]*)\)|function\b\s*\*?\s*\(\s*([^)]*)\)|([\w$]+)\s*=>|[\w$.]+\s*\()/;
const IPC_RE = /\b(ipcMain|ipcRenderer|contextBridge)\.(handle|handleOnce|on|once|exposeInMainWorld)\s*\(\s*(['"`])([^'"`]+)\3/;
const ON_RE = /\b([A-Za-z_$][\w$]*)\.(on|once|handle|register|method|addMethod|expose|subscribe|addEventListener|process|consume)\s*\(\s*(['"`])([^'"`]+)\3/;
const RPC_RECEIVER_RE = /(?:router|rpc|server|bus|channel|methods|handlers|io|socket|ws|wss|client|peer|conn|connection|nsp|namespace|ipc)$/i;
const TRPC_RE = /^\s*([A-Za-z_$][\w$]*)\s*:\s*(?:publicProcedure|protectedProcedure|adminProcedure|\w*[Pp]rocedure)\b/;
const TABLE_HEADER_RE = /\b([A-Za-z_$][\w$]*(?:handlers?|Handlers?|methods|Methods|rpc|Rpc|RPC|procedures|Procedures|actions|Actions|commands|Commands|routes|Routes|resolvers|Resolvers))\s*(?::[^=]*)?=\s*(?:\w+\s*\(\s*)?\{\s*$/;
const TABLE_KEY_ARROW_RE = /^(\s*)(?:(['"])([\w.:/-]+)\2|([A-Za-z_$][\w$]*))\s*:\s*(?:async\s+)?(?:\(\s*([^)]*)\)|([\w$]+))\s*=>/;
const TABLE_KEY_METHOD_RE = /^(\s*)(?:async\s+)?\*?\s*([A-Za-z_$][\w$]*)\s*\(\s*([^)]*)\)\s*(?::[^{]*)?\{\s*$/;
const EXPORT_FN_RE = /^\s*export\s+(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/;
const EXPORT_CONST_RE = /^\s*export\s+(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.*)$/;
const EXPORT_CLASS_RE = /^\s*export\s+(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/;
const EXPORTS_PROP_RE = /^\s*(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=/;
const MODULE_EXPORTS_RE = /^\s*module\.exports\s*=\s*(?:\{([^}]*)\}?|([A-Za-z_$][\w$]*)\s*;?\s*$)/;
const EXPORT_LIST_RE = /^\s*export\s*\{([^}]*)\}\s*;?\s*$/;
const PY_DEF_RE = /^(?:async\s+)?def\s+([A-Za-z]\w*)\s*\(/;
const PY_CLASS_RE = /^class\s+([A-Za-z]\w*)/;
const CLI_COMMAND_RE = /\.command\s*\(\s*(['"`])([^'"`]+)\1/;
const CLI_MAIN_RE = /\brequire\.main\s*===?\s*module\b|__name__\s*==\s*['"]__main__['"]/;
const CLI_ARGV_RE = /\bprocess\.argv\b|\bsys\.argv\b|\bargparse\.ArgumentParser\s*\(|\byargs\s*\(|\bnew\s+Command\s*\(/;
const LAMBDA_RE = /^\s*(?:export\s+(?:const|async\s+function|function)\s+handler\b|(?:module\.)?exports\.handler\s*=)/;
const CRON_RE = /\b(?:cron|schedule|nodeCron)\.schedule\s*\(\s*(['"`])([^'"`]+)\1/;

function firstParamName(params: string | undefined): string | undefined {
    if (!params) return undefined;
    const p = params.trim();
    if (!p) return undefined;
    if (p.startsWith('{')) return p.split(':')[0].replace(/[{}\s]/g, '').split(',')[0] || undefined;
    const m = p.match(/^([A-Za-z_$][\w$]*)/);
    return m ? m[1] : undefined;
}

function handlerParamFromLine(line: string, afterIdx: number): string | undefined {
    const rest = line.slice(afterIdx);
    const m = rest.match(/(?:async\s+)?(?:function\s*\*?\s*[\w$]*\s*)?\(\s*([^)]*)\)\s*(?:=>|\{)/) ?? rest.match(/,\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/);
    return firstParamName(m?.[1]);
}

function routeMiddleware(text: string): { middleware: string[]; handler?: string } {
    const afterPath = text.replace(/^[^(]*\(\s*(['"`])[^'"`]*\1\s*/, '');
    const args: string[] = [];
    let depth = 0;
    let cur = '';
    for (const c of afterPath) {
        if (c === '(' || c === '{' || c === '[') depth++;
        if (c === ')' || c === '}' || c === ']') {
            if (depth === 0) { args.push(cur); cur = ''; break; }
            depth--;
        }
        if (c === ',' && depth === 0) { args.push(cur); cur = ''; continue; }
        cur += c;
    }
    if (cur.trim()) args.push(cur);
    const clean = args.map(a => a.trim()).filter(Boolean);
    const out: string[] = [];
    let handler: string | undefined;
    for (let i = 0; i < clean.length; i++) {
        const a = clean[i];
        const m = a.match(/^([A-Za-z_$][\w$.]*)(?:\s*\(.*\))?$/s);
        if (!m || /=>|\bfunction\b/.test(a)) continue;
        const isLast = i === clean.length - 1;
        if (isLast && !/\(/.test(a)) { handler = m[1]; continue; }
        out.push(m[1]);
    }
    return { middleware: out, handler };
}

function collectEntries(ctx: Ctx, boundaries: FunctionBoundary[]): RawEntry[] {
    const { lines } = ctx;
    const python = ctx.grammar === 'python';
    const out: RawEntry[] = [];
    const byLine = new Set<string>();
    const push = (e: Omit<RawEntry, 'endLine'> & { endLine?: number }) => {
        const key = `${e.kind}:${e.line}:${e.name}`;
        if (byLine.has(key)) return;
        byLine.add(key);
        out.push({ ...e, endLine: e.endLine ?? findRangeEnd(lines, e.line - 1, python) });
    };
    const boundaryEnd = (name: string, line: number): number | undefined => {
        const b = boundaries.find(x => x.name === name && x.startLine >= line && x.startLine <= line + 1);
        return b?.endLine;
    };
    const httpLines = new Set<number>();

    const tables: { start: number; end: number; indent: number | null }[] = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (isCommentLine(line)) continue;
        if (TABLE_HEADER_RE.test(line)) {
            tables.push({ start: i + 1, end: findRangeEnd(lines, i, false), indent: null });
        }
    }

    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (isCommentLine(raw)) continue;
        const line = raw.replace(/\s\/\/.*$/, '');
        const ln = i + 1;
        let m: RegExpMatchArray | null;

        if ((m = line.match(HTTP_CALL_RE)) && HTTP_RECEIVER_RE.test(m[1])) {
            const method = m[2].toUpperCase() === 'DEL' ? 'DELETE' : m[2].toUpperCase();
            const mw = routeMiddleware(line.slice(m.index ?? 0));
            push({
                kind: 'http', name: `${method === 'ALL' ? '*' : method} ${m[4]}`, line: ln,
                method: method === 'ALL' ? '*' : method, path: m[4], framework: 'express',
                middleware: mw.middleware.length ? mw.middleware : undefined,
                handlerParam: handlerParamFromLine(line, (m.index ?? 0) + m[0].length),
            });
            httpLines.add(ln);
            continue;
        }
        if ((m = line.match(NEXT_RE))) {
            push({ kind: 'http', name: m[1], line: ln, method: m[1], path: '', framework: 'nextjs', endLine: boundaryEnd(m[1], ln), handlerParam: handlerParamFromLine(line, m[0].length) });
            httpLines.add(ln);
            continue;
        }
        if ((m = line.match(EFFECT_RE))) {
            const p = m[5] ?? m[3];
            push({ kind: 'http', name: `${m[1].toUpperCase()} ${p}`, line: ln, method: m[1].toUpperCase(), path: p, framework: 'effect' });
            httpLines.add(ln);
            continue;
        }
        if ((m = line.match(DECORATOR_RE)) && (m[1] || /^[A-Z]/.test(m[2]))) {
            const verb = m[2].toLowerCase();
            const methodsMatch = line.match(/methods\s*=\s*\[([^\]]*)\]/);
            const method = verb === 'route' || verb === 'api_route'
                ? (methodsMatch ? methodsMatch[1].replace(/['"\s]/g, '').toUpperCase() : '*')
                : verb === 'all' ? '*' : verb.toUpperCase();
            let defIdx = i + 1;
            while (defIdx < lines.length && defIdx < i + 6 && !/^\s*(?:async\s+)?(?:def|function)\b|^\s*(?:public\s+|private\s+|async\s+)*[A-Za-z_$][\w$]*\s*\(/.test(lines[defIdx])) defIdx++;
            const defLine = lines[defIdx] ?? '';
            const fn = defLine.match(/(?:def|function)\s+([A-Za-z_]\w*)|^\s*(?:public\s+|private\s+|async\s+)*([A-Za-z_$][\w$]*)\s*\(/);
            const end = defIdx < lines.length ? findRangeEnd(lines, defIdx, python) : ln;
            push({
                kind: 'http', name: `${method} ${m[4] ?? ''}`.trim(), line: ln, method, path: m[4] ?? '',
                framework: python ? 'python' : 'nestjs', endLine: end,
                handlerParam: fn ? (fn[1] ?? fn[2]) : undefined,
            });
            httpLines.add(ln);
            for (let k = i; k <= defIdx; k++) httpLines.add(k + 1);
            continue;
        }
        if (python && (m = line.match(DJANGO_RE))) {
            push({ kind: 'http', name: `* ${m[2]}`, line: ln, method: '*', path: m[2], framework: 'django', endLine: ln });
            continue;
        }
        if ((m = line.match(RPC_COMPUTED_RE))) {
            push({ kind: 'rpc', name: m[1], line: ln, handlerParam: firstParamName(m[2] ?? m[3]) ?? m[4] });
            continue;
        }
        if ((m = line.match(IPC_RE))) {
            push({ kind: 'rpc', name: m[4], line: ln, framework: 'electron', handlerParam: handlerParamFromLine(line, (m.index ?? 0) + m[0].length) });
            continue;
        }
        if ((m = line.match(TRPC_RE))) {
            push({ kind: 'rpc', name: m[1], line: ln, framework: 'trpc' });
            continue;
        }
        if ((m = line.match(CRON_RE))) {
            push({ kind: 'event', name: `cron ${m[2]}`, line: ln });
            continue;
        }
        if ((m = line.match(ON_RE))) {
            const receiver = m[1];
            const name = m[4];
            const param = handlerParamFromLine(line, (m.index ?? 0) + m[0].length);
            const rpcLike = RPC_RECEIVER_RE.test(receiver) && !LIFECYCLE_EVENTS.has(name);
            push({ kind: rpcLike ? 'rpc' : 'event', name: rpcLike ? name : `${receiver}.${m[2]}('${name}')`, line: ln, handlerParam: param });
            continue;
        }
        if (LAMBDA_RE.test(line)) {
            push({ kind: 'event', name: 'handler', line: ln, endLine: boundaryEnd('handler', ln), handlerParam: handlerParamFromLine(line, 0) });
            continue;
        }
        if ((m = line.match(CLI_COMMAND_RE)) && /\b(?:program|cli|yargs|commander|cmd)\b/.test(line)) {
            push({ kind: 'cli', name: m[2], line: ln });
            continue;
        }
        if (CLI_MAIN_RE.test(line)) {
            push({ kind: 'cli', name: 'main', line: ln });
            continue;
        }

        if (!python) {
            if ((m = line.match(EXPORT_FN_RE))) {
                push({ kind: 'export', name: m[1], line: ln, endLine: boundaryEnd(m[1], ln) });
                continue;
            }
            if ((m = line.match(EXPORT_CONST_RE))) {
                if (/^(?:async\b|function\b|\(|[A-Za-z_$][\w$]*\s*=>|\{|Effect\.|[A-Za-z_$][\w$.]*\s*\()/.test(m[2].trim())) {
                    push({ kind: 'export', name: m[1], line: ln });
                }
                continue;
            }
            if ((m = line.match(EXPORT_CLASS_RE))) {
                push({ kind: 'export', name: m[1], line: ln, endLine: boundaryEnd(m[1], ln) });
                continue;
            }
            if ((m = line.match(EXPORTS_PROP_RE))) {
                push({ kind: 'export', name: m[1], line: ln });
                continue;
            }
            if ((m = line.match(MODULE_EXPORTS_RE))) {
                const names = m[1] !== undefined
                    ? m[1].split(',').map(s => s.split(':')[0].trim()).filter(s => /^[A-Za-z_$][\w$]*$/.test(s))
                    : m[2] ? [m[2]] : [];
                for (const n of names) push({ kind: 'export', name: n, line: ln, endLine: ln });
                continue;
            }
            if ((m = line.match(EXPORT_LIST_RE))) {
                for (const part of m[1].split(',')) {
                    const n = part.trim().split(/\s+as\s+/).pop()?.trim();
                    if (n && /^[A-Za-z_$][\w$]*$/.test(n)) push({ kind: 'export', name: n, line: ln, endLine: ln });
                }
                continue;
            }
        } else if (!httpLines.has(ln)) {
            if ((m = line.match(PY_DEF_RE)) || (m = line.match(PY_CLASS_RE))) {
                push({ kind: 'export', name: m[1], line: ln });
                continue;
            }
        }
    }

    for (const t of tables) {
        const cands: { idx: number; indent: number; name: string; param?: string }[] = [];
        for (let i = t.start; i < t.end - 1 && i < lines.length; i++) {
            const line = lines[i];
            let m = line.match(TABLE_KEY_ARROW_RE);
            if (m) { cands.push({ idx: i, indent: m[1].length, name: m[3] ?? m[4], param: firstParamName(m[5]) ?? m[6] }); continue; }
            m = line.match(TABLE_KEY_METHOD_RE);
            if (m && !/^(?:if|for|while|switch|catch|function|return)$/.test(m[2])) cands.push({ idx: i, indent: m[1].length, name: m[2], param: firstParamName(m[3]) });
        }
        if (cands.length === 0) continue;
        let keyIndent = -1;
        for (let i = t.start; i < t.end - 1 && i < lines.length; i++) {
            if (lines[i].trim() && !isCommentLine(lines[i])) { keyIndent = lines[i].match(/^\s*/)![0].length; break; }
        }
        for (const c of cands) {
            if (c.indent !== keyIndent) continue;
            if (out.some(e => e.line === c.idx + 1)) continue;
            push({ kind: 'rpc', name: c.name, line: c.idx + 1, handlerParam: c.param });
        }
    }

    out.sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind));
    return out;
}

async function discoverInContent(content: string, baseName: string): Promise<Awaited<ReturnType<typeof discoverEndpoints>>> {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-inv-'));
    try {
        fs.writeFileSync(path.join(dir, baseName), content, 'utf8');
        return await discoverEndpoints(dir);
    } finally {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    }
}

function mergeDiscovered(ctx: Ctx, entries: RawEntry[], discovered: Awaited<ReturnType<typeof discoverEndpoints>>): void {
    const python = ctx.grammar === 'python';
    for (const d of discovered) {
        if (toPosix(d.file) !== ctx.rel) continue;
        const text = ctx.lines[d.line - 1];
        if (text === undefined || isCommentLine(text)) continue;
        const existing = entries.find(e => e.line === d.line && e.kind === 'http');
        if (existing) {
            existing.framework = d.framework;
            continue;
        }
        if (d.framework === 'django' && !python) continue;
        if (d.framework === 'express' && !/['"`]/.test(text)) continue;
        entries.push({
            kind: 'http', name: `${d.method} ${d.path}`.trim(), line: d.line,
            endLine: findRangeEnd(ctx.lines, d.line - 1, python),
            method: d.method, path: d.path, framework: d.framework,
        });
    }
    entries.sort((a, b) => a.line - b.line || a.kind.localeCompare(b.kind));
}

function innermostEntry(entries: InventoryEntryPoint[], line: number): string | null {
    let best: InventoryEntryPoint | null = null;
    for (const e of entries) {
        const end = e.endLine ?? e.line;
        if (line < e.line || line > end) continue;
        if (!best || (end - e.line) < ((best.endLine ?? best.line) - best.line)) best = e;
    }
    return best ? best.id : null;
}

// ── Inputs ──────────────────────────────────────────────────────────────────

function sourceRegexFor(grammar: SinkLanguage): RegExp {
    const prefixes = TAINT_SOURCES
        .filter(s => s.languages.includes(grammar) && s.prefix.includes('.'))
        .map(s => s.prefix)
        .sort((a, b) => b.length - a.length)
        .map(escapeRegExp);
    return new RegExp(`(?<![\\w$.])(${prefixes.join('|')})((?:\\.get\\(\\s*['"][^'"]+['"]\\s*\\)|\\??\\.[A-Za-z_$][\\w$]*|\\??\\.?\\[\\s*['"][^'"]+['"]\\s*\\])?)`, 'g');
}

interface InputDraft { entryId: string | null; source: string; line: number; col?: number; sourceType?: string; priority: number }

function collectInputs(ctx: Ctx, entries: InventoryEntryPoint[], raw: RawEntry[], taint: TaintResult[]): InputDraft[] {
    const drafts: InputDraft[] = [];
    for (const t of taint) {
        drafts.push({ entryId: innermostEntry(entries, t.sourceLine), source: t.source, line: t.sourceLine, sourceType: 'taint', priority: 0 });
    }
    if (ctx.grammar === 'unknown') return drafts;
    const re = sourceRegexFor(ctx.grammar);
    const typeOf = (prefix: string) => TAINT_SOURCES.find(s => s.prefix === prefix)?.sourceType;
    for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        if (isCommentLine(line)) continue;
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(line)) !== null) {
            drafts.push({ entryId: innermostEntry(entries, i + 1), source: (m[1] + (m[2] ?? '')).replace(/\?\.\[?/g, s => (s === '?.[' ? '[' : '.')), line: i + 1, col: m.index, sourceType: typeOf(m[1]), priority: 1 });
        }
        if (/\bprocess\.argv\b|\bsys\.argv\b/.test(line)) {
            drafts.push({ entryId: innermostEntry(entries, i + 1), source: line.includes('sys.argv') ? 'sys.argv' : 'process.argv', line: i + 1, sourceType: 'argv', priority: 1 });
        }
    }
    for (let k = 0; k < raw.length; k++) {
        const r = raw[k];
        const e = entries[k];
        if (!r.handlerParam || (r.kind !== 'rpc' && r.kind !== 'event' && r.kind !== 'cli')) continue;
        if (/^(?:req|request|ctx|c|_|res|reply|next)$/.test(r.handlerParam)) continue;
        const param = r.handlerParam;
        const fieldRe = new RegExp(`(?<![\\w$.])${escapeRegExp(param)}((?:\\??\\.[A-Za-z_$][\\w$]*)?)`, 'g');
        let any = false;
        for (let ln = r.line; ln <= Math.min(r.endLine, ctx.lines.length); ln++) {
            const text = ctx.lines[ln - 1];
            if (isCommentLine(text)) continue;
            fieldRe.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = fieldRe.exec(text)) !== null) {
                if (ln === r.line && !m[1]) continue;
                drafts.push({ entryId: e.id, source: `${param}${(m[1] ?? '').replace('?.', '.')}`, line: ln, col: m.index, sourceType: r.kind === 'event' ? 'event' : 'rpc', priority: 1 });
                any = true;
            }
        }
        if (!any) drafts.push({ entryId: e.id, source: param, line: r.line, sourceType: r.kind === 'event' ? 'event' : 'rpc', priority: 1 });
    }
    return drafts;
}

// ── Sinks ───────────────────────────────────────────────────────────────────

const PATTERN_SINKS: { kind: string; attackType: string; re: RegExp; skip?: RegExp; rank: number }[] = [
    { kind: 'db_write', attackType: 'broken_access_control', rank: 1, re: /['"`]\s*(?:INSERT\s+INTO|UPDATE\s+[\w."`]+\s+SET|DELETE\s+FROM|REPLACE\s+INTO|DROP\s+(?:TABLE|DATABASE)|ALTER\s+TABLE|TRUNCATE\s)/i },
    { kind: 'db_write', attackType: 'broken_access_control', rank: 1, re: /\b(?:db|prisma|knex|model|repo|repository|collection|table|supabase|sql|client|tx|trx|[A-Z][\w$]*)\b(?:\.[\w$]+)*\.(?:insert|insertOne|insertMany|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|destroy|remove|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete|createMany|bulkCreate|bulkWrite)\s*\(/, skip: /\b(?:crypto|hash|hmac|cipher|digest|Map|Set)\b/i },
    { kind: 'db_write', attackType: 'broken_access_control', rank: 1, re: /\.from\s*\([^)]*\)\s*\.(?:insert|update|upsert|delete)\s*\(/ },
    { kind: 'file_write', attackType: 'path_traversal', rank: 1, re: /\bfs(?:\.promises)?\.(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rename|renameSync|createWriteStream|mkdir|mkdirSync|copyFile|copyFileSync)\s*\(/ },
    { kind: 'file_read', attackType: 'path_traversal', rank: 1, re: /\b(?:res|reply|response)\.(?:sendFile|download)\s*\(|\bfs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|readdir|readdirSync)\s*\(/ },
    { kind: 'auth_token', attackType: 'broken_authentication', rank: 1, re: /\bjwt\.sign\s*\(|\b(?:res|reply|response)\.cookie\s*\(|\bsetCookie\s*\(/ },
    { kind: 'hardcoded_secret', attackType: 'secret_exposure', rank: 1, re: /['"`](?:sk_live_|sk_test_|rk_live_|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_|xox[abposr]-|AIza[0-9A-Za-z_-]{30,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)/ },
    { kind: 'process_spawn', attackType: 'command_injection', rank: 1, re: /\b(?:pty|nodePty|childProcess|child_process|cp)\.(?:spawn|fork|exec|execFile|execSync|spawnSync)\s*\(|(?<![\w$.])(?:execSync|execFileSync|spawnSync|execa|execaSync|execaCommand)\s*\(/ },
    { kind: 'db_read', attackType: 'broken_access_control', rank: 2, re: /['"`]\s*SELECT\s/i },
    { kind: 'db_read', attackType: 'broken_access_control', rank: 2, re: /\b(?:db|prisma|model|repo|repository|collection|supabase|[A-Z][\w$]*)\b(?:\.[\w$]+)*\.(?:findUnique|findFirst|findMany|findOne|findById|findAll|findByPk)\s*\(/ },
];

interface SinkDraft extends Omit<InventorySink, 'id'> { endLine: number; rank: number }

function collectSinks(ctx: Ctx, sinkFindings: SinkFinding[], taint: TaintResult[]): SinkDraft[] {
    const drafts: SinkDraft[] = [];
    for (const s of sinkFindings) {
        drafts.push({
            kind: s.sink, line: s.line, endLine: s.endLine, callExpression: clip(s.callExpression),
            attackType: s.canonicalType, severity: s.severity, enclosingFunction: s.enclosingFunction,
            detector: 'sinkFinder', rank: 0,
        });
    }
    for (const t of taint) {
        if (drafts.some(d => t.sinkLine >= d.line && t.sinkLine <= d.endLine && d.attackType === t.canonicalType)) continue;
        drafts.push({
            kind: t.sink, line: t.sinkLine, endLine: t.sinkLine, callExpression: clip(ctx.lines[t.sinkLine - 1] ?? t.sink),
            attackType: t.canonicalType, detector: 'taint', rank: 0,
        });
    }
    for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        if (isCommentLine(line)) continue;
        const ln = i + 1;
        const seen = new Set<string>();
        for (const p of PATTERN_SINKS) {
            if (seen.has(p.kind) || !p.re.test(line) || (p.skip && p.skip.test(line))) continue;
            if (drafts.some(d => ln >= d.line && ln <= d.endLine && (d.attackType === p.attackType || d.detector !== 'pattern'))) continue;
            if (p.kind.startsWith('db_') && drafts.some(d => d.detector !== 'pattern' && /(?:sql|nosql)_injection/.test(d.attackType ?? '') && Math.abs(d.line - ln) <= 3)) continue;
            seen.add(p.kind);
            drafts.push({ kind: p.kind, line: ln, endLine: ln, callExpression: clip(line), attackType: p.attackType, detector: 'pattern', rank: p.rank });
        }
    }
    return drafts;
}

// ── Guards ──────────────────────────────────────────────────────────────────

const GUARD_NAME_RE = /^(?:require|ensure|assert|check|verify|authorize|authorise|authenticate|protect|guard|can|is|has|must|only|validate)[A-Z_]\w*$/;
const GUARD_TOPIC_RE = /(?:Auth|Admin|Role|Permission|Owner|Member|Access|Session|Scope|Tenant|Login|Logged|Allowed|Authorized|Signed|Token|Privilege|Staff|Super)/;
const INLINE_ROLE_RE = /\b[\w$.?!]*(?:role|roles|permission|permissions|scope|scopes|isAdmin|isOwner|isStaff|isSuperuser|is_admin|is_staff|is_superuser|privilege|tier|accountType|userType)\b[\w$.?!\])]*\s*(?:!==|===|!=|==)\s*\S|(?:!==|===|!=|==)\s*[\w$.?!]*\b(?:role|roles|permission|scope)\b|\b(?:roles?|permissions?|scopes?)\??\.(?:includes|has|some|every|indexOf)\s*\(|\.includes\s*\(\s*[\w$.?!]*\b(?:role|permission|scope)\b|\bhasRole\s*\(|\bhasPermission\s*\(|\bcan\s*\(\s*['"]/i;
const INLINE_OWNER_RE = /\b[\w$.?!]*(?:owner|ownerId|owner_id|userId|user_id|created_by|createdBy|authorId|author_id|tenantId|tenant_id|orgId|org_id|accountId|account_id)\b[\w$.?!\])]*\s*(?:!==|===|!=|==)\s*[\w$.?!]*\b(?:user|session|auth|actor|principal|me|currentUser|current_user|viewer|caller|requester|claims|token)\b/i;
const INLINE_AUTH_RE = /\bif\s*\(\s*!\s*(?:req\.|request\.|ctx\.|ctx\.state\.|this\.)?(?:user|session|auth|token|currentUser|principal|claims|viewer|isAuthenticated|authenticated)\b|\bif\s+not\s+(?:request\.)?(?:user|current_user|session)\b|\.isAuthenticated\s*\(\s*\)/;
const DENY_RE = /\.status\s*\(\s*40[13]\s*\)|\bstatus(?:Code)?\s*:\s*40[13]\b|\bthrow\s+new\s+\w*(?:Forbidden|Unauthori[sz]ed|Unauthenticated|PermissionDenied|AccessDenied|NotAuthori[sz]ed|AuthError|AuthenticationError)\w*|\bHTTPException\s*\(\s*status_code\s*=\s*40[13]|\babort\s*\(\s*40[13]\s*\)/;
const PY_GUARD_DECORATOR_RE = /^\s*@([\w.]*(?:login_required|permission_required|user_passes_test|staff_member_required|roles_required|requires_auth|\w*(?:auth|admin|role|permission)\w*))\b/i;
const USE_RE = /\b([A-Za-z_$][\w$]*)\.use\s*\(([^)]*(?:\([^)]*\))?[^)]*)\)/;

function looksLikeGuard(name: string): boolean {
    const base = name.split('.').pop() ?? name;
    return (GUARD_NAME_RE.test(base) && GUARD_TOPIC_RE.test(base))
        || /(?:auth|guard|admin|role|permission|session|jwt|verify|protect|login|passport)/i.test(base) && !/^(?:express|cors|helmet|bodyParser|json|urlencoded|morgan|compression)$/i.test(base);
}

function isDefinitionLine(line: string, name: string): boolean {
    const n = escapeRegExp(name);
    return new RegExp(`\\bfunction\\s*\\*?\\s*${n}\\b|\\bdef\\s+${n}\\b|\\b(?:const|let|var)\\s+${n}\\b|^\\s*(?:export\\s+)?(?:async\\s+)?${n}\\s*\\([^)]*\\)\\s*(?::[^{=]*)?\\{\\s*$`).test(line);
}

function guardNamesFromMap(map: string): string[] {
    const out: string[] = [];
    for (const l of map.split('\n').slice(1)) {
        const m = l.match(/^([A-Za-z_$][\w$]*): used at/);
        if (m) out.push(m[1]);
    }
    return out;
}

interface GuardDraft extends Omit<InventoryGuard, 'id' | 'protects'> { protects: Set<string>; rank: number }

async function collectGuards(
    ctx: Ctx,
    entries: InventoryEntryPoint[],
    boundaries: FunctionBoundary[],
    attackTypes: AttackType[],
): Promise<GuardDraft[]> {
    const { lines } = ctx;
    const names = new Set<string>();
    try {
        for (const n of guardNamesFromMap(buildGuardMap(ctx.content, 100_000))) names.add(n);
    } catch { ctx.failed.push('guardMap'); }
    for (const e of entries) for (const mw of e.middleware ?? []) if (looksLikeGuard(mw)) names.add(mw);
    for (const b of boundaries) {
        if (GUARD_NAME_RE.test(b.name) && GUARD_TOPIC_RE.test(b.name)) names.add(b.name);
    }
    const definitions = new Map<string, number>();
    for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(/^\s*(?:export\s+)?(?:async\s+)?(?:function\s*\*?\s*([A-Za-z_$][\w$]*)|def\s+([A-Za-z_]\w*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(|function|[A-Za-z_$][\w$]*\s*=>))/);
        const n = m && (m[1] ?? m[2] ?? m[3]);
        if (!n) continue;
        if (!definitions.has(n)) definitions.set(n, i + 1);
        if (GUARD_NAME_RE.test(n) && GUARD_TOPIC_RE.test(n)) names.add(n);
    }

    const drafts: GuardDraft[] = [];
    const globalUses: { name: string; line: number }[] = [];
    for (let i = 0; i < lines.length; i++) {
        const m = lines[i].match(USE_RE);
        if (!m || isCommentLine(lines[i])) continue;
        for (const id of m[2].split(',').map(s => s.trim().replace(/\(.*$/s, ''))) {
            if (/^[A-Za-z_$][\w$.]*$/.test(id) && looksLikeGuard(id)) {
                names.add(id);
                globalUses.push({ name: id, line: i + 1 });
            }
        }
    }

    for (const name of names) {
        const re = new RegExp(`(?<![\\w$])${escapeRegExp(name)}(?![\\w$])`);
        const useLines: number[] = [];
        for (let i = 0; i < lines.length; i++) {
            const l = lines[i];
            if (isCommentLine(l) || /^\s*import\b|^\s*from\s+\S+\s+import\b/.test(l)) continue;
            if (!re.test(l.replace(/\/\/.*$/, ''))) continue;
            if (isDefinitionLine(l, name)) continue;
            useLines.push(i + 1);
        }
        const defLine = definitions.get(name);
        if (useLines.length === 0 && defLine === undefined) continue;
        const protects = new Set<string>();
        for (const e of entries) {
            if (e.middleware?.includes(name)) protects.add(e.id);
        }
        for (const ln of useLines) {
            const id = innermostEntry(entries, ln);
            if (id) protects.add(id);
        }
        for (const g of globalUses) {
            if (g.name !== name) continue;
            for (const e of entries) if (e.kind === 'http' && e.line > g.line) protects.add(e.id);
        }
        const asMiddleware = entries.some(e => e.middleware?.includes(name)) || globalUses.some(g => g.name === name);
        drafts.push({
            name, line: useLines[0] ?? defLine!, lines: useLines.slice(0, 50), protects,
            kind: asMiddleware ? 'middleware' : 'named', rank: 0,
        });
    }

    let evals = 0;
    for (const d of drafts) {
        if (evals >= MAX_GUARD_EVALS || ctx.grammar === 'unknown') break;
        const defLine = definitions.get(d.name);
        if (defLine === undefined) continue;
        const b = boundaries.find(x => x.name === d.name && x.startLine === defLine);
        const end = b?.endLine ?? findRangeEnd(lines, defLine - 1, ctx.grammar === 'python');
        const src = lines.slice(defLine - 1, end).join('\n');
        evals++;
        try {
            const results = await evaluateGuards([{ source: src, name: d.name }], attackTypes, ctx.grammar);
            const known = results.find(r => r.guardType !== 'unknown');
            if (known) d.guardType = known.guardType;
            const eff = results.filter(r => r.effective).map(r => r.attackType);
            if (eff.length) d.effectiveAgainst = eff;
        } catch { ctx.failed.push(`evaluateGuards:${d.name}`); }
    }

    const inlineLines = new Set<number>();
    for (let i = 0; i < lines.length; i++) {
        const l = lines[i];
        if (isCommentLine(l) || /^\s*import\b/.test(l)) continue;
        const code = l.replace(/\s\/\/.*$/, '');
        const ln = i + 1;
        const dec = ctx.grammar === 'python' ? code.match(PY_GUARD_DECORATOR_RE) : null;
        if (dec) {
            const nextEntry = entries.find(e => e.line >= ln - 3 && e.line <= ln + 3);
            drafts.push({ name: dec[1], line: ln, kind: 'middleware', protects: new Set(nextEntry ? [nextEntry.id] : []), rank: 0 });
            inlineLines.add(ln);
            continue;
        }
        const isCheck = INLINE_ROLE_RE.test(code) || INLINE_OWNER_RE.test(code) || INLINE_AUTH_RE.test(code);
        if (isCheck && /\b(?:if|elif|unless|return|assert|require|when|&&|\|\||\?)\b|^\s*(?:if|elif)\b|[?&|]/.test(code) && !/^\s*(?:type|interface)\b/.test(code)) {
            if (drafts.some(d => d.kind !== 'inline' && d.line === ln)) continue;
            const id = innermostEntry(entries, ln);
            drafts.push({ name: clip(code, 100), line: ln, kind: 'inline', protects: new Set(id ? [id] : []), rank: 1 });
            inlineLines.add(ln);
            continue;
        }
        if (DENY_RE.test(code)) {
            if (inlineLines.has(ln - 1) || inlineLines.has(ln - 2)) continue;
            const id = innermostEntry(entries, ln);
            const prev = (lines[i - 1] ?? '').trim();
            const label = /^\s*(?:if|elif)\b/.test(prev) ? `${clip(prev, 60)} → ${clip(code, 40)}` : clip(code, 100);
            drafts.push({ name: label, line: ln, kind: 'inline', protects: new Set(id ? [id] : []), rank: 2 });
            inlineLines.add(ln);
        }
    }
    return drafts;
}

// ── Roles ───────────────────────────────────────────────────────────────────

const ROLE_LITERAL = `['"\`]([A-Za-z][\\w-]{1,30})['"\`]`;
const ROLE_PATTERNS: RegExp[] = [
    new RegExp(`\\b[\\w$.?!]*(?:role|Role|roles|ROLE|permission|scope|userType|accountType|tier)\\w*[\\w$.?!\\])]*\\s*(?:!==|===|!=|==)\\s*${ROLE_LITERAL}`, 'g'),
    new RegExp(`${ROLE_LITERAL}\\s*(?:!==|===|!=|==)\\s*[\\w$.?!]*(?:role|Role|roles|permission|scope)\\b`, 'g'),
    new RegExp(`\\b(?:hasRole|requireRole|requireRoles|checkRole|isRole|hasAnyRole|Roles|roles_required|role_required|hasPermission|requirePermission)\\s*\\(\\s*${ROLE_LITERAL}`, 'g'),
    new RegExp(`\\b(?:roles?|permissions?|scopes?)\\??\\.(?:includes|has|indexOf)\\s*\\(\\s*${ROLE_LITERAL}`, 'g'),
    new RegExp(`\\b(?:role|Role|roles|ROLE)\\w*\\s*(?::|=)\\s*${ROLE_LITERAL}`, 'g'),
    new RegExp(`\\b(?:role|Role|ROLE)\\w*\\s*(?:==|===|!=|!==|in)\\s*\\(?\\s*\\[?\\s*${ROLE_LITERAL}`, 'g'),
];
const ROLE_CONTEXT_RE = /\b(?:role|roles|Role|Roles|ROLE|ROLES|permission|permissions|Permission|scope|userType|accountType|AccessLevel|accessLevel)\b/;
const ROLE_FLAG_RE = /\b(?:is|has)(Admin|Owner|Staff|Superuser|SuperAdmin|Moderator|Manager|Member|Editor|Viewer|Guest|Client|Operator)\b|\bis_(admin|staff|superuser|owner|moderator)\b/g;
const NOT_ROLE = new Set(['string', 'number', 'boolean', 'object', 'undefined', 'null', 'true', 'false', 'function', 'id', 'name', 'type', 'utf8', 'utf-8', 'base64', 'base64url', 'hex', 'sha256', 'json', 'role', 'roles']);

function collectRoles(ctx: Ctx): string[] {
    const found: string[] = [];
    const add = (r: string | undefined) => {
        if (!r) return;
        const v = r.toLowerCase();
        if (NOT_ROLE.has(v) || /^\d/.test(v)) return;
        if (!found.includes(v)) found.push(v);
    };
    for (const line of ctx.lines) {
        if (isCommentLine(line)) continue;
        const code = line.replace(/\s\/\/.*$/, '');
        for (const re of ROLE_PATTERNS) {
            re.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = re.exec(code)) !== null) add(m[1]);
        }
        if (ROLE_CONTEXT_RE.test(code)) {
            const union = code.match(/(?:['"`][A-Za-z][\w-]{1,30}['"`]\s*\|\s*)+['"`][A-Za-z][\w-]{1,30}['"`]/g);
            if (union) for (const u of union) for (const lit of u.match(/[A-Za-z][\w-]{1,30}/g) ?? []) add(lit);
            const arr = code.match(/(?:role|roles|Role|Roles|ROLES|permission|permissions)\w*\s*(?::[^=]*)?=\s*\[([^\]]*)\]/);
            if (arr) for (const lit of arr[1].match(/['"`]([A-Za-z][\w-]{1,30})['"`]/g) ?? []) add(lit.slice(1, -1));
            const tern = code.match(/(?:role|Role)\w*\s*(?:===?|!==?)\s*['"`][\w-]+['"`]\s*\?\s*['"`]([\w-]+)['"`]\s*:\s*['"`]([\w-]+)['"`]/);
            if (tern) { add(tern[1]); add(tern[2]); }
        }
        ROLE_FLAG_RE.lastIndex = 0;
        let f: RegExpExecArray | null;
        while ((f = ROLE_FLAG_RE.exec(code)) !== null) add(f[1] ?? f[2]);
    }
    return found.slice(0, INVENTORY_LIST_CAP);
}

// ── Connected files ─────────────────────────────────────────────────────────

const IMPORT_SPEC_RES: RegExp[] = [
    /\bimport\s+(?:type\s+)?(?:[^'"`;]*?\s+from\s+)?['"]([^'"]+)['"]/g,
    /\bexport\s+(?:type\s+)?(?:\*|\{[^}]*\})\s+from\s+['"]([^'"]+)['"]/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];
const PY_IMPORT_RE = /^\s*from\s+(\.+[\w.]*)\s+import\b/;

function importSpecs(ctx: Ctx): { spec: string; line: number }[] {
    const out: { spec: string; line: number }[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
        const l = ctx.lines[i];
        if (isCommentLine(l)) continue;
        for (const re of IMPORT_SPEC_RES) {
            re.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = re.exec(l)) !== null) out.push({ spec: m[1], line: i + 1 });
        }
        const py = l.match(PY_IMPORT_RE);
        if (py) {
            const dots = py[1].match(/^\.+/)![0].length;
            const rest = py[1].slice(dots).replace(/\./g, '/');
            const up = dots === 1 ? './' : '../'.repeat(dots - 1);
            out.push({ spec: `${up}${rest}`, line: i + 1 });
        }
    }
    return out;
}

function isConfigPath(rel: string): boolean {
    return /(?:^|\/)(?:config|configs|settings|env|environment|constants)(?:\/|[\w.-]*\.(?:ts|js|mjs|cjs|py|json)$)/i.test(rel);
}

function isMiddlewarePath(rel: string): boolean {
    return /(?:^|\/)(?:middleware|middlewares|guards?|policies|policy|auth|permissions?)(?:\/|[\w.-]*\.(?:ts|js|mjs|cjs|py)$)/i.test(rel);
}

function listWorkspaceFiles(root: string, max: number, deadline: number): string[] {
    const out: string[] = [];
    const stack = [root];
    while (stack.length && out.length < max && Date.now() < deadline) {
        const dir = stack.pop()!;
        let ents: fs.Dirent[];
        try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
        for (const e of ents) {
            if (e.isDirectory()) {
                if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) stack.push(path.join(dir, e.name));
            } else if (e.isFile() && CODE_EXT.test(e.name)) {
                out.push(path.join(dir, e.name));
                if (out.length >= max) break;
            }
        }
    }
    return out;
}

async function findImporters(ctx: Ctx): Promise<{ file: string; line: number }[]> {
    if (!ctx.workspaceRoot) return [];
    const parsed = path.posix.parse(ctx.rel);
    const base = parsed.name === 'index' || parsed.name === '__init__' ? path.posix.basename(parsed.dir) : parsed.name;
    if (!base) return [];
    const esc = escapeRegExp(base);
    const pattern = `(?:from\\s+|require\\(\\s*|import\\(\\s*|import\\s+)['"][^'"]*${esc}(?:/index)?(?:\\.[a-z]+)?['"]|from\\s+\\.+[\\w.]*${esc}\\s+import`;
    const candidates: { file: string; line: number; text: string }[] = [];
    try {
        const res = await searchCode(ctx.workspaceRoot, pattern);
        for (const h of res.hits) candidates.push({ file: toPosix(h.path), line: h.line, text: h.text });
    } catch {
        const deadline = Date.now() + 1500;
        const textRe = new RegExp(pattern, 'i');
        for (const abs of listWorkspaceFiles(ctx.workspaceRoot, 3000, deadline)) {
            if (Date.now() > deadline) break;
            let text: string;
            try {
                if (fs.statSync(abs).size > 512 * 1024) continue;
                text = fs.readFileSync(abs, 'utf8');
            } catch { continue; }
            if (!text.includes(base)) continue;
            const ls = text.split('\n');
            for (let i = 0; i < ls.length; i++) {
                if (textRe.test(ls[i])) candidates.push({ file: toPosix(path.relative(ctx.workspaceRoot, abs)), line: i + 1, text: ls[i] });
            }
        }
    }
    const out: { file: string; line: number }[] = [];
    for (const c of candidates) {
        if (c.file === ctx.rel || /(?:^|\/)node_modules\//.test(c.file)) continue;
        const specs: string[] = [];
        for (const re of IMPORT_SPEC_RES) {
            re.lastIndex = 0;
            let m: RegExpExecArray | null;
            while ((m = re.exec(c.text)) !== null) specs.push(m[1]);
        }
        const py = c.text.match(PY_IMPORT_RE);
        if (py) {
            const dots = py[1].match(/^\.+/)![0].length;
            specs.push(`${dots === 1 ? './' : '../'.repeat(dots - 1)}${py[1].slice(dots).replace(/\./g, '/')}`);
        }
        if (specs.some(s => resolveSpec(s, c.file, ctx.workspaceRoot) === ctx.rel) && !out.some(o => o.file === c.file)) {
            out.push({ file: c.file, line: c.line });
        }
    }
    return out;
}

function parseReferenceFiles(text: string): string[] {
    const out: string[] = [];
    for (const l of text.split('\n')) {
        const m = l.match(/^\s+(.+?):(\d+)(?::\d+)?\s+\[/);
        if (m) {
            const f = toPosix(m[1]);
            if (!out.includes(f)) out.push(f);
        }
    }
    return out;
}

const RELATION_RANK: Record<string, number> = { imports: 0, imported_by: 1, middleware: 2, config: 3, callee: 4 };
const IMPORT_QUOTA = 15;

function pickConnected<T extends InventoryConnectedFile & { order: number }>(ranked: T[]): T[] {
    if (ranked.length <= INVENTORY_CONNECTED_CAP) return ranked;
    const tagged = (c: T) => (/\((?:middleware\/auth|config)\)/.test(c.reason) ? 0 : 1);
    const imports = ranked.filter(c => c.relation === 'imports').sort((a, b) => tagged(a) - tagged(b) || a.order - b.order);
    const others = ranked.filter(c => c.relation !== 'imports');
    const picked = new Set<T>(imports.slice(0, others.length ? IMPORT_QUOTA : INVENTORY_CONNECTED_CAP));
    for (const c of [...others, ...imports]) {
        if (picked.size >= INVENTORY_CONNECTED_CAP) break;
        picked.add(c);
    }
    return ranked.filter(c => picked.has(c));
}

function addConnected(list: (InventoryConnectedFile & { order: number })[], ctx: Ctx, file: string, relation: ConnectedRelation, reason: string, order: number): void {
    const f = toPosix(file);
    if (!f || f === ctx.rel || /(?:^|\/)node_modules\//.test(f)) return;
    const existing = list.find(c => c.file === f);
    if (existing) {
        if (!existing.reason.includes(reason) && existing.reason.length < 200) existing.reason = `${existing.reason}; ${reason}`;
        return;
    }
    list.push({ file: f, relation, reason, order });
}

// ── Main ────────────────────────────────────────────────────────────────────

function assignIds<T>(items: T[], prefix: string): (T & { id: string })[] {
    return items.map((it, i) => ({ id: `${prefix}${i + 1}`, ...it }));
}

function capList<T>(ctx: Ctx, name: string, items: T[], rank: (t: T) => number, line: (t: T) => number, cap = INVENTORY_LIST_CAP): T[] {
    if (items.length <= cap) return items;
    ctx.truncated.push(`${name}: ${items.length} → ${cap}`);
    return [...items].sort((a, b) => rank(a) - rank(b) || line(a) - line(b)).slice(0, cap).sort((a, b) => line(a) - line(b));
}

function fairRanks<T>(items: T[], entryOf: (t: T) => string | null, base: (t: T) => number, line: (t: T) => number): Map<T, number> {
    const groups = new Map<string, T[]>();
    for (const it of items) {
        const k = entryOf(it) ?? '-';
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k)!.push(it);
    }
    const ranks = new Map<T, number>();
    for (const g of groups.values()) {
        g.sort((a, b) => base(a) - base(b) || line(a) - line(b));
        g.forEach((it, k) => ranks.set(it, base(it) === 0 ? -1 : k * 10 + base(it)));
    }
    return ranks;
}

export async function buildFileInventory(workspaceRoot: string, filePath: string, content: string): Promise<FileInventory> {
    const started = Date.now();
    const { abs, rel } = relPathOf(workspaceRoot, filePath);
    const text = typeof content === 'string' ? content : '';
    const ctx: Ctx = {
        workspaceRoot, abs, rel, content: text, lines: text.split(/\r?\n/),
        grammar: grammarForFile(rel), failed: [], truncated: [], timings: {},
    };
    const inventory: FileInventory = {
        file: rel, entryPoints: [], inputs: [], sinks: [], guards: [], roles: [], connected: [], flows: [],
    };

    try {
        const onDisk = (() => {
            try { return fs.statSync(abs).isFile(); } catch { return false; }
        })();
        const sameOnDisk = onDisk && (() => {
            try { return fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n') === text.replace(/\r\n/g, '\n'); } catch { return false; }
        })();
        const lang = ctx.grammar === 'unknown' ? null : ctx.grammar;
        const specs = timed(ctx, 'importSpecs', [] as { spec: string; line: number }[], () => importSpecs(ctx));
        const hasRelativeImports = specs.some(s => s.spec.startsWith('.'));

        const boundaries = await step(ctx, 'extractFunctionBoundaries', [] as FunctionBoundary[], async () => (await extractFunctionBoundaries(text, rel)) ?? [], 5000);
        let rawEntries: RawEntry[] = timed(ctx, 'entryPoints', [] as RawEntry[], () => collectEntries(ctx, boundaries));

        const discoveredP = rawEntries.length === 0 && lang
            ? step(ctx, 'discoverEndpoints', [] as Awaited<ReturnType<typeof discoverEndpoints>>, () => discoverInContent(text, path.basename(abs)))
            : Promise.resolve([]);
        const relatedP = onDisk && workspaceRoot
            ? step(ctx, 'getRelatedFilesForFile', [] as Awaited<ReturnType<typeof getRelatedFilesForFile>>, () => getRelatedFilesForFile(abs, workspaceRoot), 3000)
            : Promise.resolve([]);
        const importersP = workspaceRoot
            ? step(ctx, 'findImporters', [] as { file: string; line: number }[], () => findImporters(ctx))
            : Promise.resolve([] as { file: string; line: number }[]);
        const exportedNames = rawEntries.filter(e => e.kind === 'export').map(e => e.name).slice(0, MAX_REFERENCE_SYMBOLS);
        const refsP = onDisk && workspaceRoot && exportedNames.length
            ? importersP.then(found => found.length >= 3 ? [] : step(ctx, 'findReferences', [] as { file: string; name: string }[], async () => {
                const out: { file: string; name: string }[] = [];
                for (const name of exportedNames) {
                    for (const file of parseReferenceFiles(await findReferences(workspaceRoot, rel, name))) out.push({ file, name });
                }
                return out;
            }, 2000))
            : Promise.resolve([] as { file: string; name: string }[]);

        const taint = lang ? await step(ctx, 'trackTaint', [] as TaintResult[], () => trackTaint(text, lang), 8000) : [];
        const sinkFindings = lang ? await step(ctx, 'findSinks', [] as SinkFinding[], () => findSinks(text, lang, taint), 8000) : [];
        const crossP = sameOnDisk && lang && workspaceRoot && hasRelativeImports
            ? step(ctx, 'trackTaintCrossFile', [] as CrossFileTaintResult[], () => trackTaintCrossFile({ workspaceRoot, filePath: rel, maxDepth: 2, maxFiles: 8 }), 3000)
            : Promise.resolve([] as CrossFileTaintResult[]);

        const discovered = (await discoveredP).map(d => ({ ...d, file: rel }));
        timed(ctx, 'mergeEndpoints', undefined, () => mergeDiscovered(ctx, rawEntries, discovered));
        rawEntries = capList(ctx, 'entryPoints', rawEntries, e => (e.kind === 'export' ? 1 : 0), e => e.line);
        inventory.entryPoints = assignIds(rawEntries.map(e => {
            const ep: Omit<InventoryEntryPoint, 'id'> = { kind: e.kind, name: e.name, line: e.line, endLine: e.endLine };
            if (e.method) ep.method = e.method;
            if (e.path !== undefined && e.kind === 'http') ep.path = e.path;
            if (e.framework) ep.framework = e.framework;
            if (e.middleware?.length) ep.middleware = e.middleware;
            return ep;
        }), 'ep');
        const entries = inventory.entryPoints;

        let sinkDrafts: SinkDraft[] = timed(ctx, 'sinks', [] as SinkDraft[], () => collectSinks(ctx, sinkFindings, taint));
        sinkDrafts.sort((a, b) => a.line - b.line || a.rank - b.rank);
        const sinkRanks = fairRanks(sinkDrafts, s => innermostEntry(entries, s.line), s => s.rank, s => s.line);
        sinkDrafts = capList(ctx, 'sinks', sinkDrafts, s => sinkRanks.get(s) ?? 0, s => s.line);
        const sinksWithIds = assignIds(sinkDrafts, 'sk');
        inventory.sinks = sinksWithIds.map(({ endLine: _e, rank: _r, ...s }) => ({ ...s, entryId: innermostEntry(entries, s.line) }));

        const inputDrafts: InputDraft[] = timed(ctx, 'inputs', [] as InputDraft[], () => collectInputs(ctx, entries, rawEntries, taint));
        const seenInput = new Map<string, InputDraft>();
        for (const d of inputDrafts) {
            const key = `${d.entryId ?? '-'}|${d.source}`;
            const prev = seenInput.get(key);
            if (!prev || d.priority < prev.priority || (d.priority === prev.priority && (d.line < prev.line || (d.line === prev.line && (d.col ?? 0) < (prev.col ?? 0))))) seenInput.set(key, d);
        }
        let inputs = [...seenInput.values()].sort((a, b) => a.line - b.line || (a.col ?? 0) - (b.col ?? 0) || a.source.localeCompare(b.source));
        const typeOrder: Record<string, number> = { taint: 0, body: 1, query: 2, rpc: 3, event: 3, path: 4, header: 5, cookie: 6, argv: 7 };
        const inputRanks = fairRanks(inputs, i => i.entryId, i => i.priority, i => (typeOrder[i.sourceType ?? ''] ?? 8) * 1_000_000 + i.line);
        inputs = capList(ctx, 'inputs', inputs, i => inputRanks.get(i) ?? 0, i => i.line);
        inventory.inputs = assignIds(inputs.map(i => {
            const out: Omit<InventoryInput, 'id'> = { entryId: i.entryId, source: i.source, line: i.line };
            if (i.sourceType && i.sourceType !== 'taint') out.sourceType = i.sourceType;
            return out;
        }), 'in');

        const attackTypes = new Set<AttackType>(['broken_access_control']);
        for (const s of inventory.sinks) if (s.attackType && ATTACK_TYPES.has(s.attackType)) attackTypes.add(s.attackType as AttackType);
        let guardDrafts: GuardDraft[] = await step(ctx, 'guards', [] as GuardDraft[], () => collectGuards(ctx, entries, boundaries, [...attackTypes].slice(0, 6)), 8000);
        guardDrafts.sort((a, b) => a.line - b.line || a.rank - b.rank);
        guardDrafts = capList(ctx, 'guards', guardDrafts, g => g.rank, g => g.line);
        inventory.guards = assignIds(guardDrafts.map(({ rank: _r, protects, ...g }) => {
            const out: Omit<InventoryGuard, 'id'> = { ...g };
            if (protects.size) out.protects = [...protects].sort((a, b) => Number(a.slice(2)) - Number(b.slice(2)));
            return out;
        }), 'g');

        inventory.roles = timed(ctx, 'roles', [] as string[], () => collectRoles(ctx));

        const inputKey = new Map<string, string>();
        for (const i of inventory.inputs) {
            inputKey.set(`${i.source}@${i.line}`, i.id);
            if (!inputKey.has(`${i.entryId ?? '-'}|${i.source}`)) inputKey.set(`${i.entryId ?? '-'}|${i.source}`, i.id);
        }
        const sinkFor = (line: number, attackType?: string): string | undefined => {
            const hits = sinksWithIds.filter(s => line >= s.line && line <= s.endLine);
            return (hits.find(s => s.attackType === attackType) ?? hits[0])?.id;
        };
        const inputFor = (source: string, line: number): string => {
            return inputKey.get(`${source}@${line}`)
                ?? inputKey.get(`${innermostEntry(entries, line) ?? '-'}|${source}`)
                ?? `${source}@L${line}`;
        };
        const flows: InventoryFlow[] = [];
        const flowSeen = new Set<string>();
        for (const t of taint) {
            const from = inputFor(t.source, t.sourceLine);
            const to = sinkFor(t.sinkLine, t.canonicalType) ?? `${t.sink}@L${t.sinkLine}`;
            const key = `${from}>${to}`;
            if (flowSeen.has(key)) continue;
            flowSeen.add(key);
            flows.push({
                from, to, crossFile: false, attackType: t.canonicalType,
                via: t.propagationPath.map(s => `L${s.line} ${s.variable} (${s.operation})`).slice(0, 12),
            });
        }

        const cross = await crossP;
        const connected: (InventoryConnectedFile & { order: number })[] = [];
        let order = 0;
        for (const c of cross) {
            const isCross = c.sinkFile !== rel || c.sourceFile !== rel || c.crossFileSteps.some(s => s.operation === 'call-cross-file');
            if (!isCross) continue;
            const from = c.sourceFile === rel ? inputFor(c.source, c.sourceLine) : `${c.sourceFile}:${c.sourceLine} ${c.source}`;
            const to = c.sinkFile === rel ? (sinkFor(c.sinkLine, c.canonicalType) ?? `${c.sink}@L${c.sinkLine}`) : `${c.sinkFile}:${c.sinkLine} ${c.sink}`;
            const key = `${from}>${to}`;
            if (flowSeen.has(key)) {
                const existing = flows.find(f => `${f.from}>${f.to}` === key);
                if (existing) existing.crossFile = true;
                continue;
            }
            flowSeen.add(key);
            flows.push({ from, to, crossFile: true, attackType: c.canonicalType, via: c.crossFileSteps.map(s => `${s.file}:${s.line} ${s.description}`).slice(0, 12) });
            for (const f of [c.sourceFile, c.sinkFile]) if (f !== rel) addConnected(connected, ctx, f, 'callee', `cross-file flow to ${c.sink}`, order++);
            for (const s of c.crossFileSteps) {
                const m = s.description.match(/\bin\s+([^\s:]+):\d+/);
                if (m) addConnected(connected, ctx, m[1], 'callee', `called at L${s.line}`, order++);
            }
        }
        inventory.flows = capList(ctx, 'flows', flows, f => (f.crossFile ? 0 : 1), () => 0);

        for (const { spec, line } of specs) {
            if (!workspaceRoot || !spec.startsWith('.')) continue;
            const target = resolveSpec(spec, rel, workspaceRoot);
            if (!target) continue;
            const relation: ConnectedRelation = 'imports';
            const tag = isConfigPath(target) ? ' (config)' : isMiddlewarePath(target) ? ' (middleware/auth)' : '';
            addConnected(connected, ctx, target, relation, `imports '${spec}' at L${line}${tag}`, order++);
        }
        const importers = [...await importersP].sort((a, b) => Number(isTestPath(a.file)) - Number(isTestPath(b.file)));
        for (const imp of importers) addConnected(connected, ctx, imp.file, 'imported_by', `imports this file at ${imp.file}:${imp.line}${isTestPath(imp.file) ? ' (test)' : ''}`, order++);

        for (const ref of await refsP) addConnected(connected, ctx, ref.file, 'imported_by', `references ${ref.name}`, order++);

        for (const rf of await relatedP) {
            const relation: ConnectedRelation = rf.relationship === 'middleware' ? 'middleware'
                : rf.relationship === 'config' ? 'config'
                : rf.relationship === 'route_handler' ? 'callee'
                : rf.relationship === 'imported_by' ? 'imported_by'
                : 'imports';
            addConnected(connected, ctx, rf.filePath, relation, `project map: ${rf.relationship}`, order++);
        }

        if (workspaceRoot) {
            let dir = path.dirname(abs);
            const root = path.resolve(workspaceRoot);
            for (let k = 0; k < 8; k++) {
                const pkg = path.join(dir, ctx.grammar === 'python' ? 'pyproject.toml' : 'package.json');
                if (fs.existsSync(pkg)) {
                    addConnected(connected, ctx, toPosix(path.relative(root, pkg)), 'config', 'dependency versions and scripts', order++);
                    break;
                }
                if (path.resolve(dir) === root) break;
                const parent = path.dirname(dir);
                if (parent === dir) break;
                dir = parent;
            }
        }

        connected.sort((a, b) => RELATION_RANK[a.relation] - RELATION_RANK[b.relation] || a.order - b.order);
        if (connected.length > INVENTORY_CONNECTED_CAP) ctx.truncated.push(`connected: ${connected.length} → ${INVENTORY_CONNECTED_CAP}`);
        inventory.connected = pickConnected(connected).map(({ order: _o, ...c }) => c);
    } catch {
        ctx.failed.push('buildFileInventory');
    }

    inventory.stats = {
        lines: ctx.lines.length,
        elapsedMs: Date.now() - started,
        truncated: ctx.truncated,
        failedSteps: ctx.failed,
        stepMs: ctx.timings,
    };
    return inventory;
}
