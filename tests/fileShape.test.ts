import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { detectDeclarationOnly } from '../src/attack/fileShape';

const SYNARA_SERVICES_SERVER_AUTH = `import type {
  AuthBearerBootstrapResult,
  AuthBootstrapResult,
  AuthClientMetadata,
  AuthClientSession,
  AuthCreatePairingCredentialInput,
  AuthPairingCredentialResult,
  AuthPairingLink,
  AuthSessionId,
  AuthSessionState,
  AuthWebSocketTokenResult,
  ServerAuthDescriptor,
  ServerAuthSessionMethod,
} from "@synara/contracts";
import { Data, DateTime, ServiceMap } from "effect";
import type { Effect } from "effect";

import type { SessionRole } from "./SessionCredentialService";

export interface AuthRequest {
  readonly headers: Record<string, string | undefined>;
  readonly cookies: Record<string, string | undefined>;
  readonly url?: URL;
}

export interface AuthenticatedSession {
  readonly sessionId: AuthSessionId;
  readonly subject: string;
  readonly method: ServerAuthSessionMethod;
  readonly role: SessionRole;
  readonly expiresAt?: DateTime.DateTime;
}

export interface AuthenticatedHttpSession extends AuthenticatedSession {
  readonly credentialSource: "bearer" | "cookie";
}

export class AuthError extends Data.TaggedError("AuthError")<{
  readonly message: string;
  readonly status?: 400 | 401 | 403 | 429 | 500;
  readonly cause?: unknown;
}> {}

export interface ServerAuthShape {
  readonly getDescriptor: () => Effect.Effect<ServerAuthDescriptor>;
  readonly getSessionState: (request: AuthRequest) => Effect.Effect<AuthSessionState, never>;
  readonly exchangeBootstrapCredential: (
    credential: string,
    requestMetadata: AuthClientMetadata,
  ) => Effect.Effect<
    {
      readonly response: AuthBootstrapResult;
      readonly sessionToken: string;
    },
    AuthError
  >;
  readonly exchangeBootstrapCredentialForBearerSession: (
    credential: string,
    requestMetadata: AuthClientMetadata,
  ) => Effect.Effect<AuthBearerBootstrapResult, AuthError>;
  readonly issuePairingCredential: (
    input?: AuthCreatePairingCredentialInput & {
      readonly role?: SessionRole;
    },
  ) => Effect.Effect<AuthPairingCredentialResult, AuthError>;
  readonly listPairingLinks: () => Effect.Effect<ReadonlyArray<AuthPairingLink>, AuthError>;
  readonly revokePairingLink: (id: string) => Effect.Effect<boolean, AuthError>;
  readonly listClientSessions: (
    currentSessionId: AuthSessionId,
  ) => Effect.Effect<ReadonlyArray<AuthClientSession>, AuthError>;
  readonly revokeClientSession: (
    currentSessionId: AuthSessionId,
    targetSessionId: AuthSessionId,
  ) => Effect.Effect<boolean, AuthError>;
  readonly revokeOtherClientSessions: (
    currentSessionId: AuthSessionId,
  ) => Effect.Effect<number, AuthError>;
  readonly logoutSession: (sessionId: AuthSessionId) => Effect.Effect<boolean, AuthError>;
  readonly authenticateHttpRequest: (
    request: AuthRequest,
  ) => Effect.Effect<AuthenticatedHttpSession, AuthError>;
  readonly authenticateWebSocketUpgrade: (
    request: AuthRequest,
  ) => Effect.Effect<AuthenticatedSession, AuthError>;
  readonly issueWebSocketToken: (
    session: AuthenticatedSession,
  ) => Effect.Effect<AuthWebSocketTokenResult, AuthError>;
  readonly issueStartupPairingUrl: (baseUrl: string) => Effect.Effect<string, AuthError>;
}

export class ServerAuth extends ServiceMap.Service<ServerAuth, ServerAuthShape>()(
  "synara/auth/Services/ServerAuth",
) {}
`;

describe('detectDeclarationOnly — positive', () => {
    it('detects the Synara Services/ServerAuth.ts shape (interfaces + Effect tag classes)', () => {
        expect(detectDeclarationOnly(SYNARA_SERVICES_SERVER_AUTH)).toBe(true);
    });

    it('detects the contract-specified single-line ServiceMap tag class', () => {
        const src = `import { ServiceMap } from "effect";
export interface ServerAuthShape { readonly x: () => void }
export class ServerAuth extends ServiceMap.Service<ServerAuth, ServerAuthShape>()("t3/auth/Services/ServerAuth") {}
`;
        expect(detectDeclarationOnly(src)).toBe(true);
    });

    it('detects plain interface / type / declare files without semicolons', () => {
        const src = `// Types for the API
import type { Foo } from './foo'
export type Id = string
export type Status =
  | 'active'
  | 'disabled'
export interface User {
  id: Id
  status: Status
  callback(arg: string): void
}
declare global {
  interface Window { app: unknown }
}
declare function helper(x: number): string
export type { Foo }
export * from './other'
`;
        expect(detectDeclarationOnly(src)).toBe(true);
    });

    it('detects abstract classes with signature-only members', () => {
        const src = `export abstract class Repo<T> {
  abstract find(id: string): Promise<T>;
  abstract save(item: T): Promise<void>;
  readonly name?: string;
}`;
        expect(detectDeclarationOnly(src)).toBe(true);
    });

    it('detects Context.GenericTag const tags', () => {
        const src = `import { Context } from "effect";
export interface Db { query(sql: string): unknown }
export const Db = Context.GenericTag<Db>("app/Db");
`;
        expect(detectDeclarationOnly(src)).toBe(true);
    });
});

describe('detectDeclarationOnly — negative', () => {
    it('rejects files with function bodies', () => {
        expect(detectDeclarationOnly(`export interface A { x: string }\nexport function f(a: A) { return a.x; }`)).toBe(false);
    });

    it('rejects top-level calls with side effects (app.listen())', () => {
        const src = `import express from 'express';
export interface Config { port: number }
const app = express();
app.listen(3000);
`;
        expect(detectDeclarationOnly(src)).toBe(false);
    });

    it('rejects a bare top-level call even with only types around it', () => {
        expect(detectDeclarationOnly(`export type A = string\nregister()\n`)).toBe(false);
    });

    it('rejects classes with method bodies', () => {
        const src = `export interface S { run(): void }
export class Impl implements S {
  run() {
    console.log('x');
  }
}`;
        expect(detectDeclarationOnly(src)).toBe(false);
    });

    it('rejects classes with property initializers', () => {
        expect(detectDeclarationOnly(`export class C { count = 0 }`)).toBe(false);
    });

    it('rejects const value declarations and enums', () => {
        expect(detectDeclarationOnly(`const a = 1;`)).toBe(false);
        expect(detectDeclarationOnly(`export type A = string;\nexport enum Color { Red, Green }`)).toBe(false);
    });

    it('rejects arrow-function consts', () => {
        expect(detectDeclarationOnly(`export type A = string;\nexport const f = (a: A) => a.length;`)).toBe(false);
    });

    it('rejects empty files and import-only files', () => {
        expect(detectDeclarationOnly('')).toBe(false);
        expect(detectDeclarationOnly(`import type { A } from './a';\n`)).toBe(false);
        expect(detectDeclarationOnly(`import './polyfill';\nexport type A = string;`)).toBe(false);
    });

    it('rejects a Layers-style implementation', () => {
        const src = `import { Effect, Layer } from "effect";
import { ServerAuth, type ServerAuthShape } from "../Services/ServerAuth";

const AUTHORIZATION_PREFIX = "Bearer ";

function parseBearerToken(headers: Record<string, string | undefined>): string | null {
  const header = headers.authorization;
  if (typeof header !== "string" || !header.startsWith(AUTHORIZATION_PREFIX)) {
    return null;
  }
  return header.slice(AUTHORIZATION_PREFIX.length).trim();
}

export const ServerAuthLive = Layer.effect(ServerAuth, Effect.gen(function* () {
  return {} as ServerAuthShape;
}));
`;
        expect(detectDeclarationOnly(src)).toBe(false);
    });

    it('accepts function boundaries that hold no statements', () => {
        expect(detectDeclarationOnly(`export interface A { x: string }\n// return\n`, [{ name: 'A', startLine: 1, endLine: 2 }])).toBe(true);
    });

    const synaraLayers = path.resolve(__dirname, '../../test_lab/synara/apps/server/src/auth/Layers/ServerAuth.ts');
    it.skipIf(!fs.existsSync(synaraLayers))('rejects the real Synara Layers/ServerAuth.ts (local sanity check)', () => {
        expect(detectDeclarationOnly(fs.readFileSync(synaraLayers, 'utf8'))).toBe(false);
    });
});
