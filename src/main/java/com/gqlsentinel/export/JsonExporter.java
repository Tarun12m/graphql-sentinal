package com.gqlsentinel.export;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.util.List;

import com.gqlsentinel.model.Finding;

/**
 * Serialises findings to a stable, machine-readable JSON document for pipelines/report tooling.
 *
 * <p>We map explicitly to a {@link JsonObject} rather than reflectively serialising {@link Finding}
 * so the export schema is a deliberate contract, decoupled from internal field names — internal
 * refactors won't silently change the exported format.
 */
public final class JsonExporter {

    public String export(List<Finding> findings) {
        JsonObject root = new JsonObject();
        root.addProperty("tool", "GraphQL Sentinel");
        root.addProperty("schemaVersion", "1.0");
        root.addProperty("generatedAt", java.time.Instant.now().toString());
        root.addProperty("findingCount", findings.size());

        JsonArray arr = new JsonArray();
        for (Finding f : findings) {
            JsonObject o = new JsonObject();
            o.addProperty("id", f.id());
            o.addProperty("timestamp", f.timestamp().toString());
            o.addProperty("severity", f.severity().name());
            o.addProperty("module", f.module());
            o.addProperty("title", f.title());
            o.addProperty("description", f.description());
            o.addProperty("affectedOperation", f.affectedOperation());
            o.addProperty("endpoint", f.endpointUrl());
            o.addProperty("remediation", f.remediation());
            o.addProperty("requestEvidence", f.requestEvidence());
            o.addProperty("responseEvidence", f.responseEvidence());
            arr.add(o);
        }
        root.add("findings", arr);

        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(root);
    }
}
