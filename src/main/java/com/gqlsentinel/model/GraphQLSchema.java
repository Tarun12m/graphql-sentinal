package com.gqlsentinel.model;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * A parsed, read-only view of a GraphQL schema obtained via introspection.
 *
 * <p>We parse only what a pentester actually reads: the type list (name + kind), each type's
 * fields with argument names, and the three root operation type names. Full introspection carries
 * far more (directives, deprecation, descriptions); we skip it to keep the tree legible and the
 * parser resilient to shape differences between server implementations.
 *
 * <p>Parsing is null-tolerant throughout because introspection output varies and may be partial;
 * a missing sub-object yields an empty section rather than an exception.
 */
public final class GraphQLSchema {

    public record Argument(String name, String type) {}

    public record Field(String name, String type, List<Argument> args) {}

    public record Type(String name, String kind, List<Field> fields) {}

    private final String queryTypeName;
    private final String mutationTypeName;
    private final String subscriptionTypeName;
    private final List<Type> types;

    private GraphQLSchema(String q, String m, String s, List<Type> types) {
        this.queryTypeName = q;
        this.mutationTypeName = m;
        this.subscriptionTypeName = s;
        this.types = types;
    }

    public String queryTypeName() { return queryTypeName; }
    public String mutationTypeName() { return mutationTypeName; }
    public String subscriptionTypeName() { return subscriptionTypeName; }
    public List<Type> types() { return types; }

    /**
     * Parse from the {@code data} object of an introspection response (i.e. the object that
     * contains {@code __schema}). Returns null if there is no schema present.
     */
    public static GraphQLSchema fromIntrospectionData(JsonObject data) {
        if (data == null || !data.has("__schema") || !data.get("__schema").isJsonObject()) {
            return null;
        }
        JsonObject schema = data.getAsJsonObject("__schema");

        String q = rootTypeName(schema, "queryType");
        String m = rootTypeName(schema, "mutationType");
        String s = rootTypeName(schema, "subscriptionType");

        List<Type> types = new ArrayList<>();
        if (schema.has("types") && schema.get("types").isJsonArray()) {
            for (JsonElement el : schema.getAsJsonArray("types")) {
                if (el.isJsonObject()) {
                    Type t = parseType(el.getAsJsonObject());
                    if (t != null) {
                        types.add(t);
                    }
                }
            }
        }
        return new GraphQLSchema(q, m, s, types);
    }

    private static String rootTypeName(JsonObject schema, String key) {
        if (schema.has(key) && schema.get(key).isJsonObject()) {
            JsonObject o = schema.getAsJsonObject(key);
            if (o.has("name") && !o.get("name").isJsonNull()) {
                return o.get("name").getAsString();
            }
        }
        return null;
    }

    private static Type parseType(JsonObject t) {
        String name = str(t, "name");
        if (name == null) {
            return null; // anonymous/wrapper types are not useful in the tree view
        }
        String kind = str(t, "kind");
        List<Field> fields = new ArrayList<>();
        if (t.has("fields") && t.get("fields").isJsonArray()) {
            for (JsonElement fe : t.getAsJsonArray("fields")) {
                if (fe.isJsonObject()) {
                    fields.add(parseField(fe.getAsJsonObject()));
                }
            }
        }
        return new Type(name, kind, fields);
    }

    private static Field parseField(JsonObject f) {
        String name = str(f, "name");
        String type = unwrapTypeName(f.getAsJsonObject("type"));
        List<Argument> args = new ArrayList<>();
        if (f.has("args") && f.get("args").isJsonArray()) {
            for (JsonElement ae : f.getAsJsonArray("args")) {
                if (ae.isJsonObject()) {
                    JsonObject a = ae.getAsJsonObject();
                    args.add(new Argument(str(a, "name"), unwrapTypeName(a.getAsJsonObject("type"))));
                }
            }
        }
        return new Field(name, type, args);
    }

    /**
     * GraphQL type references nest as NON_NULL(LIST(NAMED)). Walk down {@code ofType} to the base
     * named type and re-apply the wrappers as [] / ! so the rendered type reads naturally.
     */
    private static String unwrapTypeName(JsonObject typeRef) {
        if (typeRef == null) {
            return "?";
        }
        String kind = str(typeRef, "kind");
        String name = str(typeRef, "name");
        if (name != null) {
            return name;
        }
        JsonObject of = typeRef.has("ofType") && typeRef.get("ofType").isJsonObject()
                ? typeRef.getAsJsonObject("ofType") : null;
        String inner = unwrapTypeName(of);
        if ("NON_NULL".equals(kind)) {
            return inner + "!";
        }
        if ("LIST".equals(kind)) {
            return "[" + inner + "]";
        }
        return inner;
    }

    private static String str(JsonObject o, String key) {
        return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : null;
    }

    /** Render a compact, human-readable tree for the UI schema view. */
    public String renderTree() {
        StringBuilder sb = new StringBuilder();
        sb.append("schema {\n");
        sb.append("  query: ").append(nullToDash(queryTypeName)).append('\n');
        sb.append("  mutation: ").append(nullToDash(mutationTypeName)).append('\n');
        sb.append("  subscription: ").append(nullToDash(subscriptionTypeName)).append('\n');
        sb.append("}\n\n");

        for (Type t : types) {
            // Hide GraphQL's own introspection types (they start with "__") to reduce noise.
            if (t.name().startsWith("__")) {
                continue;
            }
            sb.append(t.kind() == null ? "type" : t.kind().toLowerCase()).append(' ')
              .append(t.name()).append(" {\n");
            for (Field f : t.fields()) {
                sb.append("    ").append(f.name());
                if (!f.args().isEmpty()) {
                    sb.append('(');
                    for (int i = 0; i < f.args().size(); i++) {
                        Argument a = f.args().get(i);
                        if (i > 0) {
                            sb.append(", ");
                        }
                        sb.append(a.name()).append(": ").append(a.type());
                    }
                    sb.append(')');
                }
                sb.append(": ").append(f.type()).append('\n');
            }
            sb.append("}\n\n");
        }
        return sb.toString();
    }

    private static String nullToDash(String s) {
        return s == null ? "—" : s;
    }
}
