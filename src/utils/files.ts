import * as fs from 'fs';
import * as path from 'path';

const SUPPORTED_EXTENSIONS: Record<string, string> = {
    '.js': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
    '.jsx': 'javascriptreact',
    '.ts': 'typescript',
    '.tsx': 'typescriptreact',
    '.py': 'python',
    // Note: .php is intentionally omitted — the MCP parserLoader has no
    // tree-sitter-php.wasm. PHP files will return 'Unsupported file type'
    // with a clear message instead of silently producing zero findings.
    '.json': 'json',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.toml': 'toml',
    '.ini': 'ini',
    '.env': 'env',
    '.cfg': 'ini',
    '.conf': 'ini',
    '.config': 'ini',
};

export function inferLanguage(filePath: string): string | undefined {
    const ext = path.extname(filePath).toLowerCase();
    if (SUPPORTED_EXTENSIONS[ext]) return SUPPORTED_EXTENSIONS[ext];

    // Dotfiles like .env, .env.local, .env.production have no extension
    const base = path.basename(filePath).toLowerCase();
    if (base === '.env' || /^\.env\.[\w.-]+$/.test(base)) return 'env';

    return undefined;
}

export function isSupportedFile(filePath: string): boolean {
    return inferLanguage(filePath) !== undefined;
}

export function resolveWorkspacePath(workspaceRoot: string, inputPath: string): string {
    const resolved = path.resolve(workspaceRoot, inputPath);
    const normalizedRoot = path.resolve(workspaceRoot);
    if (!resolved.startsWith(normalizedRoot + path.sep) && resolved !== normalizedRoot) {
        throw new Error(`Path '${inputPath}' is outside the workspace root. Only files within the workspace can be read.`);
    }
    return resolved;
}

export function readFileFromWorkspace(workspaceRoot: string, inputPath: string): { code: string; language: string; absolutePath: string } {
    const absPath = resolveWorkspacePath(workspaceRoot, inputPath);
    if (!fs.existsSync(absPath)) {
        throw new Error(`File not found: ${inputPath}`);
    }
    const code = fs.readFileSync(absPath, 'utf8');
    const language = inferLanguage(absPath);
    if (!language) {
        throw new Error(`Unsupported file type: ${path.extname(inputPath)}`);
    }
    return { code, language, absolutePath: absPath };
}
