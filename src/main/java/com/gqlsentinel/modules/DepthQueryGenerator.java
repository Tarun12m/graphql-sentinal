package com.gqlsentinel.modules;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.gqlsentinel.model.GraphQLSchema;

/**
 * Generates a single, bounded, deeply-nested query to probe for a missing depth/cost limit.
 *
 * <p>To nest legitimately we need a cycle in the schema graph — a type reachable from a root query
 * field that contains a field looping back to itself (e.g. {@code User.friends: [User]}). We find
 * the shortest such self-reference and repeat it up to the requested depth, terminating in
 * {@code __typename} (always a valid scalar leaf).
 *
 * <p><b>Safety:</b> the generator physically cannot emit a query deeper than the caller asks for,
 * and callers derive that from {@link com.gqlsentinel.core.Configuration#maxProbeDepth()} which is
 * itself clamped to {@link com.gqlsentinel.core.Configuration#HARD_MAX_DEPTH}. There is no code
 * path that produces an unbounded query — the point is to demonstrate the missing control, not to
 * exhaust the server.
 */
public final class DepthQueryGenerator {

    /** A discovered nesting: a root query field and a field on its type that loops back to it. */
    public record SelfReference(String rootField, String rootType, String cycleField) {}

    /**
     * Find a root query field whose (object) type has a field returning that same type, preferring
     * fields with no required arguments so the generated query needs no variables.
     */
    public Optional<SelfReference> findSelfReference(GraphQLSchema schema) {
        if (schema == null || schema.queryTypeName() == null) {
            return Optional.empty();
        }
        Map<String, GraphQLSchema.Type> byName = index(schema);
        GraphQLSchema.Type queryType = byName.get(schema.queryTypeName());
        if (queryType == null) {
            return Optional.empty();
        }
        for (GraphQLSchema.Field rootField : queryType.fields()) {
            if (hasRequiredArgs(rootField)) {
                continue; // avoid fields that would need us to invent argument values
            }
            String rootTypeName = baseName(rootField.type());
            GraphQLSchema.Type rootType = byName.get(rootTypeName);
            if (rootType == null) {
                continue;
            }
            for (GraphQLSchema.Field candidate : rootType.fields()) {
                if (hasRequiredArgs(candidate)) {
                    continue;
                }
                if (rootTypeName.equals(baseName(candidate.type()))) {
                    return Optional.of(new SelfReference(rootField.name(), rootTypeName, candidate.name()));
                }
            }
        }
        return Optional.empty();
    }

    /** Build the nested query string for the given self-reference and depth (>= 1). */
    public String generate(SelfReference ref, int depth) {
        int d = Math.max(1, depth);
        StringBuilder inner = new StringBuilder("__typename");
        // Wrap the leaf in `cycleField { ... }` d times.
        for (int i = 0; i < d; i++) {
            inner = new StringBuilder(ref.cycleField() + " { " + inner + " }");
        }
        return "query DepthProbe { " + ref.rootField() + " { " + inner + " } }";
    }

    private static boolean hasRequiredArgs(GraphQLSchema.Field field) {
        return field.args().stream().anyMatch(a -> a.type() != null && a.type().endsWith("!"));
    }

    /** Strip GraphQL type wrappers ([], !) to get the underlying named type. */
    static String baseName(String type) {
        if (type == null) {
            return "";
        }
        return type.replace("[", "").replace("]", "").replace("!", "").trim();
    }

    private static Map<String, GraphQLSchema.Type> index(GraphQLSchema schema) {
        Map<String, GraphQLSchema.Type> m = new HashMap<>();
        for (GraphQLSchema.Type t : schema.types()) {
            m.put(t.name(), t);
        }
        return m;
    }
}
