package com.gqlsentinel.modules;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import com.gqlsentinel.model.GraphQLSchema;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DepthQueryGeneratorTest {

    private final DepthQueryGenerator generator = new DepthQueryGenerator();

    // A minimal introspection payload with a self-referential type: User.manager -> User.
    private GraphQLSchema selfReferentialSchema() {
        String json = """
            {"data":{"__schema":{
              "queryType":{"name":"Query"},
              "mutationType":null,
              "subscriptionType":null,
              "types":[
                {"kind":"OBJECT","name":"Query","fields":[
                  {"name":"me","type":{"kind":"OBJECT","name":"User","ofType":null},"args":[]}
                ]},
                {"kind":"OBJECT","name":"User","fields":[
                  {"name":"manager","type":{"kind":"OBJECT","name":"User","ofType":null},"args":[]},
                  {"name":"name","type":{"kind":"SCALAR","name":"String","ofType":null},"args":[]}
                ]}
              ]
            }}}
            """;
        JsonObject data = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("data");
        return GraphQLSchema.fromIntrospectionData(data);
    }

    @Test
    void findsSelfReferenceThroughRootField() {
        Optional<DepthQueryGenerator.SelfReference> ref =
                generator.findSelfReference(selfReferentialSchema());
        assertTrue(ref.isPresent());
        assertEquals("me", ref.get().rootField());
        assertEquals("User", ref.get().rootType());
        assertEquals("manager", ref.get().cycleField());
    }

    @Test
    void generatedQueryNestsExactlyToRequestedDepthAndTerminatesInScalar() {
        DepthQueryGenerator.SelfReference ref =
                generator.findSelfReference(selfReferentialSchema()).orElseThrow();
        String query = generator.generate(ref, 3);

        // The cycle field should appear exactly 'depth' times and end in __typename.
        int occurrences = query.split("manager", -1).length - 1;
        assertEquals(3, occurrences);
        assertTrue(query.contains("__typename"));
        assertTrue(query.startsWith("query DepthProbe { me {"));
    }

    @Test
    void baseNameStripsListAndNonNullWrappers() {
        assertEquals("User", DepthQueryGenerator.baseName("[User!]!"));
        assertEquals("String", DepthQueryGenerator.baseName("String"));
    }
}
