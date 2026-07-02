package com.gqlsentinel.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;

import com.gqlsentinel.model.EndpointRegistry;
import com.gqlsentinel.model.FindingStore;
import com.gqlsentinel.model.SessionProfile;

/**
 * Dependency container assembled once at startup and handed to every module and UI panel.
 *
 * <p>Rationale: modules need a consistent set of collaborators (logger, scope gate, HTTP client,
 * shared stores, config, the two session profiles). Passing this one object instead of a long
 * constructor argument list keeps wiring readable and makes it trivial to add a collaborator
 * later without touching every module signature. It is a plain holder — no logic — so it stays a
 * boring, safe seam.
 */
public final class ExtensionContext {

    private final MontoyaApi api;
    private final ExtensionLogger logger;
    private final Configuration config;
    private final ScopeGate scopeGate;
    private final GraphQLDetector detector;
    private final GraphQLRequestParser parser;
    private final FindingStore findingStore;
    private final EndpointRegistry endpointRegistry;

    // The two mutable session profiles the authz module uses. Held here so the config UI and the
    // module share exactly one instance each.
    private final SessionProfile lowPrivSession = new SessionProfile(SessionProfile.Role.LOW_PRIV);

    public ExtensionContext(MontoyaApi api) {
        this.api = api;
        this.logger = new ExtensionLogger(api.logging());
        this.config = new Configuration();
        this.scopeGate = new ScopeGate(api.scope(), logger);
        this.parser = new GraphQLRequestParser(logger);
        this.detector = new GraphQLDetector(parser);
        this.findingStore = new FindingStore();
        this.endpointRegistry = new EndpointRegistry();
    }

    public MontoyaApi api() { return api; }
    public Http http() { return api.http(); }
    public ExtensionLogger logger() { return logger; }
    public Configuration config() { return config; }
    public ScopeGate scopeGate() { return scopeGate; }
    public GraphQLDetector detector() { return detector; }
    public GraphQLRequestParser parser() { return parser; }
    public FindingStore findingStore() { return findingStore; }
    public EndpointRegistry endpointRegistry() { return endpointRegistry; }
    public SessionProfile lowPrivSession() { return lowPrivSession; }
}
