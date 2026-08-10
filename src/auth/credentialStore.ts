import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

const CRED_DIR = path.join(os.homedir(), '.securecode');
const CRED_FILE = path.join(CRED_DIR, 'credentials.json');

export interface StoredCredentials {
    apiToken: string;
    apiUrl: string;
    storedAt: string;
}

export class CredentialStore {
    static get(): StoredCredentials | null {
        const envToken = process.env.SECURECODE_API_TOKEN;
        const envUrl = process.env.SECURECODE_API_URL || 'https://api.usesecurecode.tech';
        if (envToken) {
            return { apiToken: envToken, apiUrl: envUrl, storedAt: 'env' };
        }

        try {
            if (!fs.existsSync(CRED_FILE)) return null;
            const stat = fs.statSync(CRED_FILE);
            if (stat.mode & 0o077) {
                console.error(`[securecode] Warning: ${CRED_FILE} is group/world accessible. Run: chmod 600 ${CRED_FILE}`);
            }
            const raw = fs.readFileSync(CRED_FILE, 'utf8');
            const parsed = JSON.parse(raw) as StoredCredentials;
            if (!parsed.apiToken || !parsed.apiUrl) return null;
            return parsed;
        } catch {
            return null;
        }
    }

    static save(credentials: StoredCredentials): void {
        if (!fs.existsSync(CRED_DIR)) {
            fs.mkdirSync(CRED_DIR, { recursive: true, mode: 0o700 });
        }
        fs.writeFileSync(CRED_FILE, JSON.stringify(credentials, null, 2), { mode: 0o600 });
    }

    static clear(): boolean {
        try {
            if (fs.existsSync(CRED_FILE)) {
                fs.unlinkSync(CRED_FILE);
                return true;
            }
        } catch {
            // best effort
        }
        return false;
    }

    static getOrThrow(): StoredCredentials {
        const creds = CredentialStore.get();
        if (!creds) {
            throw new Error(
                'Not authenticated. Run `securecode-mcp login` or set SECURECODE_API_TOKEN environment variable.',
            );
        }
        return creds;
    }
}
