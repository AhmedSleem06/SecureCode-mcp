/**
 * Endpoint discovery — scans the workspace for HTTP route handler definitions
 * across all supported frameworks.
 *
 * Uses ripgrep (via searchCode) for speed. Detects:
 *   - Next.js App Router:  export async function GET/POST/PATCH/DELETE/PUT
 *   - Express:             app.get/post/patch/delete/put('path', handler)
 *                          router.get/post/...('path', handler)
 *   - FastAPI:             @app.get/post/...("/path")
 *                          @router.get/post/...("/path")
 *   - Flask:               @app.route("/path")  @app.get/post/...("/path")
 *   - Django:              path('url', views.handler)  re_path(...)
 *
 * Returns a compact list of { method, path, file, line, framework } entries.
 */

import { searchCode, SearchHit } from '../utils/searchCode';

export interface DiscoveredEndpoint {
    method: string;       // GET, POST, PATCH, DELETE, PUT, or '*' for route()
    path: string;         // route path if extractable, else ''
    file: string;         // workspace-relative
    line: number;         // 1-indexed
    framework: string;    // 'nextjs', 'express', 'fastapi', 'flask', 'django', 'unknown'
}

const HTTP_METHODS = ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'] as const;

// Patterns to search for. Each entry has a regex and a framework label.
const PATTERNS: { regex: string; framework: string }[] = [
    // Next.js App Router: export async function GET / POST / etc.
    { regex: 'export\\s+async\\s+function\\s+(GET|POST|PATCH|DELETE|PUT)\\b', framework: 'nextjs' },
    // Express: app.METHOD( or router.METHOD(
    { regex: '(app|router)\\.(get|post|patch|delete|put)\\s*\\(', framework: 'express' },
    // Express: app.all(
    { regex: '(app|router)\\.all\\s*\\(', framework: 'express' },
    // FastAPI: @app.get( / @router.get(
    { regex: '@(app|router)\\.(get|post|patch|delete|put)\\s*\\(', framework: 'fastapi' },
    // Flask: @app.route(
    { regex: '@app\\.route\\s*\\(', framework: 'flask' },
    // Flask 2.0: @app.get( / @app.post( etc
    { regex: '@app\\.(get|post|patch|delete|put)\\s*\\(', framework: 'flask' },
    // Django: path('url', views.handler)
    { regex: '(re_)?path\\s*\\(\\s*[\'"]', framework: 'django' },
];

function extractMethod(text: string, framework: string): string {
    const upper = text.toUpperCase();
    for (const m of HTTP_METHODS) {
        if (upper.includes(m)) return m;
    }
    if (framework === 'flask' && text.includes('.route(')) return '*';
    if (framework === 'django') return '*';
    if (upper.includes('.ALL(')) return '*';
    return '?';
}

function extractPath(text: string): string {
    // Try to find a string literal (single or double quoted) in the line
    const match = text.match(/['"`]([^'"`]+)['"`]/);
    return match ? match[1] : '';
}

export async function discoverEndpoints(
    workspaceRoot: string,
    glob?: string,
): Promise<DiscoveredEndpoint[]> {
    const allEndpoints: DiscoveredEndpoint[] = [];
    const seen = new Set<string>(); // dedup by file:line

    for (const { regex, framework } of PATTERNS) {
        try {
            const result = await searchCode(workspaceRoot, regex, glob);
            for (const hit of result.hits) {
                const key = `${hit.path}:${hit.line}`;
                if (seen.has(key)) continue;
                seen.add(key);

                allEndpoints.push({
                    method: extractMethod(hit.text, framework),
                    path: extractPath(hit.text),
                    file: hit.path,
                    line: hit.line,
                    framework,
                });
            }
        } catch {
            // ripgrep not available — skip this pattern
        }
    }

    // Sort by file, then line
    allEndpoints.sort((a, b) => {
        if (a.file !== b.file) return a.file.localeCompare(b.file);
        return a.line - b.line;
    });

    return allEndpoints;
}

export function formatEndpoints(endpoints: DiscoveredEndpoint[]): string {
    if (endpoints.length === 0) {
        return 'No HTTP route handlers found in the workspace.';
    }

    const lines: string[] = [`Found ${endpoints.length} endpoint(s):`];
    for (const ep of endpoints) {
        const pathStr = ep.path ? ` ${ep.path}` : '';
        lines.push(`  ${ep.method.padEnd(6)} ${ep.file}:${ep.line} [${ep.framework}]${pathStr}`);
    }
    return lines.join('\n');
}
