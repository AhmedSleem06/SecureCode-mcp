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
    '.php': 'php',
};

export function inferLanguage(filePath: string): string | undefined {
    const ext = path.extname(filePath).toLowerCase();
    return SUPPORTED_EXTENSIONS[ext];
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
