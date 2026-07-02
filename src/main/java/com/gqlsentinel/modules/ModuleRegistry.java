package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

import com.gqlsentinel.core.ActiveRequestSender;
import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.GraphQLOperation;

/**
 * Constructs and owns the six analysis modules and provides a single dispatch surface for the
 * passive handler and the UI. Centralising construction here keeps the wiring/ordering (depth
 * depends on introspection's parsed schema) in one obvious place.
 */
public final class ModuleRegistry {

    private final IntrospectionModule introspection;
    private final FieldAuthorizationModule fieldAuthorization;
    private final DepthComplexityModule depthComplexity;
    private final BatchingModule batching;
    private final InjectionSurfaceModule injectionSurface;
    private final List<AnalysisModule> all;
    private final ExtensionContext ctx;

    public ModuleRegistry(ExtensionContext ctx) {
        this.ctx = ctx;
        ActiveRequestSender sender = new ActiveRequestSender(ctx);

        // Order matters: depth/complexity reuses the schema that introspection parses.
        this.introspection = new IntrospectionModule(ctx, sender);
        this.fieldAuthorization = new FieldAuthorizationModule(ctx, sender);
        this.depthComplexity = new DepthComplexityModule(ctx, sender, introspection);
        this.batching = new BatchingModule(ctx, sender);
        this.injectionSurface = new InjectionSurfaceModule(ctx);

        this.all = List.of(introspection, fieldAuthorization, depthComplexity, batching, injectionSurface);
    }

    /** Fan out an observed exchange to every module's passive hook. Never sends traffic. */
    public void dispatchPassive(DetectedEndpoint endpoint, HttpRequestResponse exchange,
                                List<GraphQLOperation> operations) {
        for (AnalysisModule module : all) {
            try {
                module.onTraffic(endpoint, exchange, operations);
            } catch (RuntimeException e) {
                // One module misbehaving must not stop the others or break the proxy pipeline.
                ctx.logger().debug("Passive module '" + module.name() + "' threw: " + e.getMessage());
            }
        }
    }

    public List<AnalysisModule> all() {
        return all;
    }

    public IntrospectionModule introspection() {
        return introspection;
    }
}
