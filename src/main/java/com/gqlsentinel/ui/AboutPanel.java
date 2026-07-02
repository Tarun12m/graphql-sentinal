package com.gqlsentinel.ui;

import javax.swing.BorderFactory;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;

/**
 * Authorisation-only disclaimer and a short "how to use" primer. Shown as the first thing an
 * operator sees so the intended, lawful use of the tool is unambiguous.
 */
public final class AboutPanel extends JPanel {

    public AboutPanel() {
        super(new BorderLayout());
        JEditorPane pane = new JEditorPane("text/html", DISCLAIMER_HTML);
        pane.setEditable(false);
        pane.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        add(new JScrollPane(pane), BorderLayout.CENTER);
    }

    private static final String DISCLAIMER_HTML = """
        <html>
        <h1>GraphQL Sentinel</h1>
        <p>A focused GraphQL security-testing toolkit for Burp Suite (Montoya API).</p>

        <h2 style="color:#8a1c1c;">⚠ Authorised use only</h2>
        <p><b>This tool is for authorised security testing only.</b> Use it exclusively against
        systems you own or have explicit, written permission to test — for example an engagement
        with a signed scope, or an intentionally vulnerable lab such as the Damn Vulnerable GraphQL
        Application (DVGA). Testing systems without authorisation is illegal in most jurisdictions.</p>

        <p>The extension is built to keep you inside those lines:</p>
        <ul>
          <li>It <b>respects Burp's target scope</b> and never acts on out-of-scope hosts.</li>
          <li>Active testing is <b>disarmed by default</b> — until you arm it, the tool only
              passively observes traffic.</li>
          <li>Depth and batching probes are <b>hard-capped</b> so the tool demonstrates a missing
              control without attempting to cause an outage.</li>
          <li>It <b>never replays state-changing operations</b> (mutations) automatically.</li>
          <li>Injection candidates are <b>flagged for manual review</b>, never auto-exploited.</li>
        </ul>

        <h2>Quick start</h2>
        <ol>
          <li>Add your target to Burp's <i>Target &rarr; Scope</i>.</li>
          <li>Browse the app through Burp as the <b>privileged</b> user. Detected GraphQL endpoints
              appear on the <i>Endpoints</i> tab.</li>
          <li>On the <i>Configuration</i> tab, enter a <b>low-privilege</b> user's session and
              <b>ARM</b> active testing.</li>
          <li>Select an endpoint and run the modules. Review results on the <i>Findings</i> tab and
              export a JSON/HTML report.</li>
        </ol>
        </html>
        """;
}
