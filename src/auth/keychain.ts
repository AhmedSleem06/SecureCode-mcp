import { execSync, execFileSync } from 'child_process';
import * as os from 'os';

const SERVICE_NAME = 'SecureCode-MCP';
const ACCOUNT_NAME = 'api-token';

export type Platform = 'darwin' | 'win32' | 'linux';

function detectPlatform(): Platform {
    const platform = os.platform();
    if (platform === 'darwin' || platform === 'win32' || platform === 'linux') {
        return platform;
    }
    return 'linux';
}

const KeychainDarwin = {
    set(token: string): void {
        execSync(
            `security add-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" -w "${token.replace(/"/g, '\\"')}" -U`,
            { stdio: 'pipe' },
        );
    },

    get(): string | null {
        try {
            const buf = execSync(
                `security find-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" -w`,
                { stdio: 'pipe', encoding: 'utf8' },
            );
            return buf.trim() || null;
        } catch {
            return null;
        }
    },

    delete(): boolean {
        try {
            execSync(
                `security delete-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}"`,
                { stdio: 'pipe' },
            );
            return true;
        } catch {
            return false;
        }
    },
};

const KeychainWin32 = {
    set(token: string): void {
        const psScript = `
            Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public class CredMan {
                [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool CredWriteW(ref CREDENTIAL cred, uint flags);

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct CREDENTIAL {
                    public uint Flags;
                    public uint Type;
                    public string TargetName;
                    public string Comment;
                    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                    public uint CredentialBlobSize;
                    public string CredentialBlob;
                    public uint Persist;
                    public uint AttributeCount;
                    public IntPtr Attributes;
                    public string TargetAlias;
                    public string UserName;
                }
            }
"@
            $blob = [System.Text.Encoding]::Unicode.GetBytes("${token.replace(/"/g, '`"')}")
            $cred = New-Object CredMan+CREDENTIAL
            $cred.Flags = 0
            $cred.Type = 1
            $cred.TargetName = "${SERVICE_NAME}"
            $cred.CredentialBlobSize = $blob.Length
            $cred.CredentialBlob = "${token.replace(/"/g, '`"')}"
            $cred.Persist = 2
            $cred.UserName = "${ACCOUNT_NAME}"
            [CredMan]::CredWriteW([ref]$cred, 0) | Out-Null
        `;
        execSync('powershell -NoProfile -Command "' + psScript.replace(/"/g, '\\"').replace(/\n/g, ' ') + '"', {
            stdio: 'pipe',
            encoding: 'utf8',
        });
    },

    get(): string | null {
        const psScript = `
            Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public class CredMan {
                [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool CredReadW(string target, uint type, uint flags, out IntPtr cred);

                [DllImport("advapi32.dll")]
                public static extern void CredFree(IntPtr cred);

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct CREDENTIAL {
                    public uint Flags;
                    public uint Type;
                    public string TargetName;
                    public string Comment;
                    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                    public uint CredentialBlobSize;
                    public string CredentialBlob;
                    public uint Persist;
                    public uint AttributeCount;
                    public IntPtr Attributes;
                    public string TargetAlias;
                    public string UserName;
                }
            }
"@
            $ptr = [IntPtr]::Zero
            $ok = [CredMan]::CredReadW("${SERVICE_NAME}", 1, 0, [ref]$ptr)
            if (-not $ok) { return "" }
            $cred = [Runtime.InteropServices.Marshal]::PtrToStructure[CredMan+CREDENTIAL]($ptr)
            [CredMan]::CredFree($ptr)
            return $cred.CredentialBlob
        `;
        try {
            const result = execSync('powershell -NoProfile -Command "' + psScript.replace(/"/g, '\\"').replace(/\n/g, ' ') + '"', {
                stdio: 'pipe',
                encoding: 'utf8',
            });
            const token = result.trim();
            return token || null;
        } catch {
            return null;
        }
    },

    delete(): boolean {
        const psScript = `
            Add-Type @"
            using System;
            using System.Runtime.InteropServices;
            public class CredMan {
                [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool CredDeleteW(string target, uint type, uint flags);
            }
"@
            [CredMan]::CredDeleteW("${SERVICE_NAME}", 1, 0) | Out-Null
        `;
        try {
            execSync('powershell -NoProfile -Command "' + psScript.replace(/"/g, '\\"').replace(/\n/g, ' ') + '"', {
                stdio: 'pipe',
            });
            return true;
        } catch {
            return false;
        }
    },
};

const KeychainLinux = {
    set(token: string): void {
        execSync(
            `secret-tool store --label="${SERVICE_NAME}" service "${SERVICE_NAME}" account "${ACCOUNT_NAME}" <<< '${token.replace(/'/g, "'\\''")}'`,
            { stdio: 'pipe', shell: '/bin/bash' },
        );
    },

    get(): string | null {
        try {
            const buf = execSync(
                `secret-tool lookup service "${SERVICE_NAME}" account "${ACCOUNT_NAME}"`,
                { stdio: 'pipe', encoding: 'utf8' },
            );
            return buf.trim() || null;
        } catch {
            return null;
        }
    },

    delete(): boolean {
        try {
            execSync(
                `secret-tool clear service "${SERVICE_NAME}" account "${ACCOUNT_NAME}"`,
                { stdio: 'pipe' },
            );
            return true;
        } catch {
            return false;
        }
    },
};

const IMPLS: Record<Platform, typeof KeychainDarwin> = {
    darwin: KeychainDarwin,
    win32: KeychainWin32,
    linux: KeychainLinux,
};

export interface KeychainResult {
    success: boolean;
    method: 'keychain' | 'file';
    platform: Platform;
    error?: string;
}

export class Keychain {
    static isAvailable(): boolean {
        const platform = detectPlatform();
        try {
            if (platform === 'darwin') {
                execSync('which security', { stdio: 'pipe' });
                return true;
            } else if (platform === 'win32') {
                return true;
            } else if (platform === 'linux') {
                execSync('which secret-tool', { stdio: 'pipe' });
                return true;
            }
        } catch {
            return false;
        }
        return false;
    }

    static get(): string | null {
        const platform = detectPlatform();
        try {
            return IMPLS[platform].get();
        } catch {
            return null;
        }
    }

    static set(token: string): KeychainResult {
        const platform = detectPlatform();
        try {
            IMPLS[platform].set(token);
            return { success: true, method: 'keychain', platform };
        } catch (err: any) {
            return { success: false, method: 'file', platform, error: err.message };
        }
    }

    static delete(): boolean {
        const platform = detectPlatform();
        try {
            return IMPLS[platform].delete();
        } catch {
            return false;
        }
    }

    static getPlatform(): Platform {
        return detectPlatform();
    }
}
