const BLOCKED_MODULES = new Set(['child_process', 'net', 'cluster', 'worker_threads']);

const BLOCKED_PATTERNS: Array<{ pattern: RegExp; reason: (mod: string) => string }> = [
    { pattern: /process\.exit\s*\(/g, reason: () => 'process.exit() masks test results — use console.error + throw instead' },
    { pattern: /require\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/g, reason: () => 'dynamic require with variable is not statically checkable' },
];

const ALLOWED_IMPORT_PREFIXES = ['node:', 'effect', 'bun', 'bun:', '@synara/', './', '../'];

const BLOCKED_MODULE_REASONS: Record<string, string> = {
    child_process: 'child_process is blocked — use only for testing command injection with mock spawns',
    net: 'net is blocked — use HTTP libraries instead',
    cluster: 'cluster is blocked',
    worker_threads: 'worker_threads is blocked',
};

export function checkTestSafety(script: string, _workspaceRoot: string): { allowed: boolean; reason: string } {
    for (const { pattern, reason } of BLOCKED_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(script)) {
            return { allowed: false, reason: reason('') };
        }
    }

    const importRegex = /(?:import\s+[^;]+?from\s*|require\s*\(\s*)["']([^"']+)["']/g;
    let match: RegExpExecArray | null;
    while ((match = importRegex.exec(script)) !== null) {
        const mod = match[1];
        if (BLOCKED_MODULES.has(mod)) {
            return { allowed: false, reason: BLOCKED_MODULE_REASONS[mod] || mod };
        }
        if (mod.startsWith('node:') || mod.startsWith('./') || mod.startsWith('../')) continue;
        if (mod.startsWith('effect') || mod.startsWith('bun') || mod.startsWith('@synara/')) continue;
        if (ALLOWED_IMPORT_PREFIXES.some(p => mod.startsWith(p))) continue;
    }

    return { allowed: true, reason: '' };
}
