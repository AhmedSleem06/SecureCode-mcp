import * as fs from 'fs';
import * as path from 'path';

const EFFECT_MOCK_JS = `const E = {
    sync: (fn) => ({ _tag: "Sync", fn }),
    die: (msg) => { throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg)); },
    gen: (generatorFn) => ({
        _tag: "Gen",
        run() {
            const gen = generatorFn();
            let result = gen.next();
            while (!result.done) {
                const y = result.value;
                if (y && y._tag === "Sync") result = gen.next(y.fn());
                else if (y && y._tag === "Die") throw new Error(y.msg);
                else if (y && y._tag === "Succeed") result = gen.next(y.v);
                else if (y && y._tag === "Fail") throw y.e;
                else result = gen.next(y);
            }
            return result.value;
        }
    }),
    succeed: (v) => ({ _tag: "Succeed", v }),
    fail: (e) => ({ _tag: "Fail", e }),
    runSync: (e) => e && e._tag === "Gen" ? e.run() : e && e._tag === "Sync" ? e.fn() : e,
    runPromise: async (e) => e && e._tag === "Gen" ? e.run() : e && e._tag === "Sync" ? e.fn() : e,
    map: (e, fn) => e && e._tag === "Sync" ? { _tag: "Sync", fn: () => fn(e.fn()) } : e,
    flatMap: (e, fn) => e && e._tag === "Sync" ? { _tag: "Sync", fn: () => { const r = e.fn(); return fn(r); } } : e,
    catchAll: (e, fn) => e,
    try_: (fn) => ({ _tag: "Sync", fn: () => { try { return fn(); } catch (e) { return e; } } }),
};
export const Effect = E;
export const Layer = {
    effect: (tag, genEffect) => {
        const result = genEffect && genEffect._tag === "Gen" ? genEffect.run() : genEffect;
        return { _tag: "Layer", tag, gen: genEffect, ...result };
    },
    succeed: (val) => ({ _tag: "Layer", val }),
    fail: (e) => ({ _tag: "Layer", e }),
    empty: { _tag: "Layer" },
    build: (layer) => layer,
    toRuntime: (layer) => layer,
    provide: (effect, layer) => effect,
};
export const Context = {
    Tag: (id) => class { static _tag = id; },
    make: (tag, val) => ({ [tag]: val }),
    get: (tag) => ({ _tag: "Sync", fn: () => tag }),
};
export const Schema = {
    TaggedErrorClass: () => () => class extends Error {
        constructor(props) { super(props?.message || ""); Object.assign(this, props); }
    },
    String: { _tag: "String" },
    Number: { _tag: "Number" },
    Boolean: { _tag: "Boolean" },
    optional: (s) => s,
    Defect: { _tag: "Defect" },
    Struct: (fields) => ({ _tag: "Struct", fields }),
    Array: (item) => ({ _tag: "Array", item }),
    decodeUnknownSync: (schema) => (val) => val,
    encodeSync: (schema) => (val) => val,
};
export const ServiceMap = {
    Service: () => () => class {
        static _tag = "mock-service";
        static key = "mock-service";
    },
};
export const pipe = (val, ...fns) => fns.reduce((v, fn) => fn(v), val);
export const Option = {
    some: (v) => ({ _tag: "Some", value: v }),
    none: { _tag: "None" },
    isSome: (o) => o && o._tag === "Some",
    isNone: (o) => !o || o._tag === "None",
    getOrElse: (o, fn) => o && o._tag === "Some" ? o.value : fn(),
    map: (o, fn) => o && o._tag === "Some" ? { _tag: "Some", value: fn(o.value) } : o,
};
export const Either = {
    left: (e) => ({ _tag: "Left", left: e }),
    right: (v) => ({ _tag: "Right", right: v }),
    isRight: (e) => e && e._tag === "Right",
    isLeft: (e) => e && e._tag === "Left",
    getOrElse: (e, fn) => e && e._tag === "Right" ? e.right : fn(),
    map: (e, fn) => e && e._tag === "Right" ? { _tag: "Right", right: fn(e.right) } : e,
};
export const Cause = {
    die: (msg) => ({ _tag: "Die", msg }),
    fail: (e) => ({ _tag: "Fail", e }),
    toString: (c) => JSON.stringify(c),
};
export const Stream = {
    fromIterable: (items) => ({ _tag: "Stream", items }),
    run: (stream) => stream,
};
export const SubscriptionRef = {
    make: (val) => ({ _tag: "SubscriptionRef", ref: { value: val } }),
    get: (sr) => ({ _tag: "Sync", fn: () => sr.ref.value }),
    set: (sr, val) => ({ _tag: "Sync", fn: () => { sr.ref.value = val; } }),
};
export const Ref = {
    make: (val) => ({ value: val }),
    get: (r) => ({ _tag: "Sync", fn: () => r.value }),
    set: (r, val) => ({ _tag: "Sync", fn: () => { r.value = val; } }),
    update: (r, fn) => ({ _tag: "Sync", fn: () => { r.value = fn(r.value); } }),
};
export const Fiber = {
    run: (effect) => ({ _tag: "Fiber", effect }),
    join: (fiber) => fiber.effect,
};
export const Runtime = {
    defaultRuntime: { runSync: E.runSync, runPromise: E.runPromise },
};
`;

const EFFECT_PKG_JSON = JSON.stringify({
    name: "effect",
    version: "0.0.0-mock",
    main: "index.js",
    type: "module",
});

export function createEffectMock(workspaceRoot: string): void {
    const mockDir = path.join(workspaceRoot, 'node_modules', 'effect');
    fs.mkdirSync(mockDir, { recursive: true });
    fs.writeFileSync(path.join(mockDir, 'package.json'), EFFECT_PKG_JSON, 'utf8');
    fs.writeFileSync(path.join(mockDir, 'index.js'), EFFECT_MOCK_JS, 'utf8');
}
