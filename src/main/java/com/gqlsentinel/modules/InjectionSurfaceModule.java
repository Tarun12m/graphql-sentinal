package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.GraphQLOperation;
import com.gqlsentinel.model.Severity;

/**
 * Passively maps GraphQL arguments that plausibly reach injection sinks and flags them for manual
 * review. It is intentionally a <em>signposting</em> tool, not an exploiter: it never sends a
 * payload. GraphQL's typed inputs mean classic injection lives where user-controlled arguments are
 * passed into a backend query/command/file/URL — so we surface those arguments by name and let the
 * tester decide what to probe by hand.
 *
 * <p>Findings are INFO ("candidate for manual review") on purpose: naming an argument's likely sink
 * is a hypothesis, not a vulnerability. Over-claiming here would erode trust in the whole tool.
 */
public final class InjectionSurfaceModule implements AnalysisModule {

    /** Sink categories mapped to argument-name keywords that hint the value reaches that sink. */
    private enum Sink {
        SQL_NOSQL("SQL/NoSQL query", List.of("query", "search", "filter", "where", "sort", "order",
                "orderby", "q", "term", "keyword", "sql")),
        IDENTIFIER_LOOKUP("database identifier lookup (SQLi/IDOR)", List.of("id", "uid", "userid",
                "user_id", "pid", "postid", "objectid", "ref")),
        PATH_TRAVERSAL("filesystem path (path traversal / LFI)", List.of("file", "filename", "path",
                "dir", "directory", "folder", "template", "include")),
        SSRF_URL("outbound URL (SSRF / open redirect)", List.of("url", "uri", "link", "webhook",
                "callback", "redirect", "endpoint", "host", "domain", "image", "avatar")),
        COMMAND("OS command (command injection)", List.of("cmd", "command", "exec", "run", "ping",
                "shell", "process"));

        final String label;
        final List<String> keywords;
        Sink(String label, List<String> keywords) {
            this.label = label;
            this.keywords = keywords;
        }
    }

    // Grabs `argName:` occurrences (field arguments and input-object fields) from a GraphQL doc.
    // Pragmatic and deliberately over-inclusive — surface mapping wants candidates, and dedupe
    // plus INFO severity keep the noise manageable.
    private static final Pattern ARG_PATTERN = Pattern.compile("([A-Za-z_][A-Za-z0-9_]*)\\s*:");

    // GraphQL keywords / structural tokens that ARG_PATTERN would otherwise catch as "arguments".
    private static final Set<String> NON_ARGS = Set.of("query", "mutation", "subscription");

    private final ExtensionContext ctx;

    public InjectionSurfaceModule(ExtensionContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public String name() {
        return "Injection Surface";
    }

    @Override
    public String description() {
        return "Passively flags GraphQL arguments that may reach injection sinks (SQL, path, SSRF, "
                + "command) as candidates for manual review. Never sends payloads.";
    }

    @Override
    public void onTraffic(DetectedEndpoint endpoint, HttpRequestResponse exchange,
                          List<GraphQLOperation> operations) {
        for (GraphQLOperation op : operations) {
            Map<String, Sink> candidates = classifyArguments(op.query());
            for (Map.Entry<String, Sink> entry : candidates.entrySet()) {
                report(endpoint, op, entry.getKey(), entry.getValue());
            }
        }
    }

    /** Extract argument names and map each to its most likely sink category, if any. */
    private Map<String, Sink> classifyArguments(String query) {
        Map<String, Sink> result = new LinkedHashMap<>();
        if (query == null) {
            return result;
        }
        Matcher m = ARG_PATTERN.matcher(query);
        while (m.find()) {
            String arg = m.group(1);
            String lower = arg.toLowerCase(Locale.ROOT);
            if (NON_ARGS.contains(lower)) {
                continue;
            }
            Sink sink = sinkFor(lower);
            if (sink != null) {
                // Keep the first (most specific) classification for each argument name.
                result.putIfAbsent(arg, sink);
            }
        }
        return result;
    }

    private Sink sinkFor(String argLower) {
        // Prefer more specific sinks first: an exact keyword equality beats a substring contains.
        for (Sink sink : Sink.values()) {
            if (sink.keywords.contains(argLower)) {
                return sink;
            }
        }
        for (Sink sink : Sink.values()) {
            for (String kw : sink.keywords) {
                if (kw.length() >= 3 && argLower.contains(kw)) {
                    return sink;
                }
            }
        }
        return null;
    }

    private void report(DetectedEndpoint endpoint, GraphQLOperation op, String arg, Sink sink) {
        Finding f = Finding.builder()
                .severity(Severity.INFO)
                .module(name())
                .title("Injection-surface candidate: argument '" + arg + "'")
                .description("The argument '" + arg + "' on " + op.displayName() + " has a name "
                        + "suggesting its value may reach a " + sink.label + ". This is a candidate "
                        + "for MANUAL injection testing only — the extension has not sent any payload "
                        + "and makes no claim that the argument is exploitable.")
                .affectedOperation(op.displayName() + " (arg: " + arg + ")")
                .endpointUrl(endpoint.url())
                .remediation("Manually verify that '" + arg + "' is safely handled: parameterised "
                        + "queries for DB sinks, allow-listing/canonicalisation for paths and URLs, "
                        + "and never passing argument values into shell commands.")
                .requestEvidence("Operation: " + op.displayName() + "\nArgument observed: " + arg
                        + "\nSuspected sink: " + sink.label
                        + "\n\n(Passive finding — request body shown for context)\n"
                        + safeBody(op))
                .responseEvidence("(none — passive surface mapping does not send requests)")
                .build();
        ctx.findingStore().add(f);
    }

    private String safeBody(GraphQLOperation op) {
        String q = op.query();
        if (q == null) {
            return "";
        }
        return q.length() > 2000 ? q.substring(0, 2000) + "\n...[truncated]..." : q;
    }
}
