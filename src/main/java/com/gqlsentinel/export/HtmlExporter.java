package com.gqlsentinel.export;

import java.time.Instant;
import java.util.List;

import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.Severity;

/**
 * Renders findings as a single, self-contained HTML report (inline CSS, no external assets) so a
 * tester can hand the file straight to a client. All dynamic text is HTML-escaped to prevent a
 * hostile response body captured as evidence from injecting markup into the report.
 */
public final class HtmlExporter {

    public String export(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.append("<title>GraphQL Sentinel Report</title>");
        sb.append("<style>")
          .append("body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;")
          .append("margin:0;padding:2rem;background:#f5f6f8;color:#1b1f23;}")
          .append("h1{margin:0 0 .25rem;} .meta{color:#57606a;margin-bottom:1.5rem;}")
          .append(".summary{margin:1rem 0 2rem;} .pill{display:inline-block;padding:.2rem .6rem;")
          .append("border-radius:999px;color:#fff;font-size:.8rem;margin-right:.4rem;}")
          .append(".finding{background:#fff;border:1px solid #d0d7de;border-radius:8px;")
          .append("padding:1rem 1.25rem;margin-bottom:1rem;box-shadow:0 1px 2px rgba(0,0,0,.04);}")
          .append(".finding h3{margin:.1rem 0 .4rem;} .sev{font-weight:600;}")
          .append(".kv{color:#57606a;font-size:.9rem;margin:.1rem 0;}")
          .append("pre{background:#0d1117;color:#c9d1d9;padding:.75rem;border-radius:6px;")
          .append("overflow:auto;font-size:.8rem;max-height:22rem;}")
          .append("details{margin-top:.5rem;} summary{cursor:pointer;color:#0969da;}")
          .append("</style></head><body>");

        sb.append("<h1>GraphQL Sentinel — Security Findings</h1>");
        sb.append("<div class=\"meta\">Generated ").append(esc(Instant.now().toString()))
          .append(" · ").append(findings.size()).append(" finding(s)</div>");

        sb.append("<div class=\"summary\">").append(severityPills(findings)).append("</div>");

        for (Finding f : findings) {
            String color = f.severity().hexColor();
            sb.append("<div class=\"finding\">");
            sb.append("<div><span class=\"pill\" style=\"background:").append(color).append("\">")
              .append(esc(f.severity().name())).append("</span>")
              .append("<span class=\"kv\">").append(esc(f.module())).append("</span></div>");
            sb.append("<h3>").append(esc(f.title())).append("</h3>");
            sb.append("<div class=\"kv\"><b>Endpoint:</b> ").append(esc(f.endpointUrl())).append("</div>");
            sb.append("<div class=\"kv\"><b>Operation:</b> ").append(esc(f.affectedOperation())).append("</div>");
            sb.append("<p>").append(esc(f.description())).append("</p>");
            sb.append("<div class=\"kv\"><b>Remediation:</b> ").append(esc(f.remediation())).append("</div>");
            sb.append("<details><summary>Request evidence</summary><pre>")
              .append(esc(f.requestEvidence())).append("</pre></details>");
            sb.append("<details><summary>Response evidence</summary><pre>")
              .append(esc(f.responseEvidence())).append("</pre></details>");
            sb.append("</div>");
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    private String severityPills(List<Finding> findings) {
        StringBuilder sb = new StringBuilder();
        for (Severity s : Severity.values()) {
            long count = findings.stream().filter(f -> f.severity() == s).count();
            sb.append("<span class=\"pill\" style=\"background:").append(s.hexColor()).append("\">")
              .append(s.name()).append(": ").append(count).append("</span>");
        }
        return sb.toString();
    }

    /** Minimal but correct HTML escaping for text nodes and attribute-adjacent content. */
    private String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
