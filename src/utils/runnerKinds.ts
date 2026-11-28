export const COMPILED_LANG_RUNNERS = new Set(['go', 'ruby', 'php', 'java-maven', 'java-gradle', 'dotnet']);

export const COMPILED_LANG_TIMEOUT_MS = 180_000;

export function isCompiledLangRunner(runner: string): boolean {
    return COMPILED_LANG_RUNNERS.has(runner);
}
