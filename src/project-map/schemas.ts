/**
 * Phase 4 — validator schema collection.
 *
 * Where a request body is declared by a schema (zod, Joi, yup, pydantic), the
 * schema's fields ARE the endpoint's parameters: they are the inputs that
 * actually reach the handler, and they are frequently the only place the field
 * names appear at all. `CreateUserSchema.parse(req.body)` never mentions
 * `email` or `name`, so a params pass that only looks for `req.body.<name>`
 * reads reports an endpoint with no inputs.
 */

import { TreeSitterNode } from './parserLoader';
import { baseIdentifier, isIdentifier, isStringLiteral, stringLiteralValue, walk } from './astHelpers';
import { ValidatorLibrary } from './types';

/** A validation schema declared in a file, keyed by its local variable name. */
export interface SchemaDef {
    /** Field names the schema declares. */
    fields: string[];
    library: ValidatorLibrary;
}

/** Builder receivers that produce an object schema, mapped to their library. */
const SCHEMA_BUILDERS: { library: ValidatorLibrary; receivers: RegExp; methods: Set<string> }[] = [
    { library: 'zod', receivers: /^z$|^zod$/, methods: new Set(['object', 'strictObject']) },
    { library: 'joi', receivers: /^joi$/i, methods: new Set(['object']) },
    { library: 'yup', receivers: /^yup$/, methods: new Set(['object', 'shape']) },
];

/** Methods that run a schema against a value: `Schema.parse(req.body)`. */
export const SCHEMA_VALIDATION_METHODS = new Set([
    'parse', 'safeParse', 'parseAsync', 'safeParseAsync',
    'validate', 'validateAsync', 'validateSync',
    'cast', 'load', 'model_validate', 'parse_obj',
]);

/** Field names declared by a JS object literal: `{ email: ..., name: ... }`. */
function objectLiteralFields(node: TreeSitterNode, source: string): string[] {
    const fields: string[] = [];
    for (const child of node.namedChildren) {
        if (child.type !== 'pair') continue;
        const key = child.child(0);
        if (!key) continue;
        const text = source.slice(key.startIndex, key.endIndex);
        fields.push(isStringLiteral(key) ? stringLiteralValue(key, source) : text);
    }
    return fields;
}

/** Field names declared by a pydantic model body: `email: EmailStr`. */
function pydanticModelFields(classNode: TreeSitterNode, source: string): string[] {
    const body = classNode.namedChildren.find(c => c.type === 'block');
    if (!body) return [];
    const fields: string[] = [];
    for (const stmt of body.namedChildren) {
        for (const n of stmt.type === 'expression_statement' ? stmt.namedChildren : [stmt]) {
            if (n.type !== 'assignment') continue;
            const target = n.child(0);
            if (target && isIdentifier(target)) {
                fields.push(source.slice(target.startIndex, target.endIndex));
            }
        }
    }
    return fields;
}

/**
 * Collect every validation schema declared in a file.
 *
 * JS/TS: `const S = z.object({...})` / `Joi.object({...})` / `yup.object({...})`.
 * Python: `class S(BaseModel): ...` — pydantic models, including subclasses of
 * a model already seen in this file.
 */
export function collectSchemas(
    root: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
): Map<string, SchemaDef> {
    const out = new Map<string, SchemaDef>();

    for (const n of walk(root)) {
        // --- JS/TS builder calls -------------------------------------------
        if (n.type === 'variable_declarator') {
            const name = n.child(0);
            const value = n.child(n.childCount - 1);
            if (!name || !value || !isIdentifier(name)) continue;
            if (value.type !== 'call_expression') continue;
            const def = schemaFromBuilderCall(value, source, imports);
            if (def) out.set(source.slice(name.startIndex, name.endIndex), def);
            continue;
        }

        // --- Python pydantic models ----------------------------------------
        if (n.type === 'class_definition') {
            const nameNode = n.namedChildren.find(c => isIdentifier(c));
            const bases = n.namedChildren.find(c => c.type === 'argument_list');
            if (!nameNode || !bases) continue;
            const baseText = source.slice(bases.startIndex, bases.endIndex);
            const inheritsModel = /\bBaseModel\b/.test(baseText)
                || [...out.keys()].some(k => new RegExp(`\\b${k}\\b`).test(baseText));
            if (!inheritsModel) continue;
            const fields = pydanticModelFields(n, source);
            if (fields.length === 0) continue;
            out.set(source.slice(nameNode.startIndex, nameNode.endIndex), {
                fields,
                library: 'pydantic',
            });
        }
    }

    return out;
}

/** Recognise `z.object({...})` / `Joi.object({...})` and read its fields. */
function schemaFromBuilderCall(
    call: TreeSitterNode,
    source: string,
    imports: Map<string, string>,
): SchemaDef | null {
    const fn = call.child(0);
    if (!fn || (fn.type !== 'member_expression' && fn.type !== 'attribute')) return null;
    const obj = fn.child(0);
    const prop = fn.child(fn.childCount - 1);
    if (!obj || !prop) return null;
    const receiver = baseIdentifier(obj, source);
    if (!receiver) return null;
    const method = source.slice(prop.startIndex, prop.endIndex);

    const spec = imports.get(receiver) ?? '';
    const builder = SCHEMA_BUILDERS.find(b =>
        b.methods.has(method) && (b.receivers.test(receiver) || b.receivers.test(spec)));
    if (!builder) return null;

    const args = call.child(call.childCount - 1);
    const literal = args?.namedChildren.find(c => c.type === 'object');
    if (!literal) return null;
    const fields = objectLiteralFields(literal, source);
    if (fields.length === 0) return null;
    return { fields, library: builder.library };
}
