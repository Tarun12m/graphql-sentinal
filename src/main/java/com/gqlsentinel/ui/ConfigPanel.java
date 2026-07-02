package com.gqlsentinel.ui;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;

import com.gqlsentinel.core.Configuration;
import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.model.SessionProfile;

/**
 * Configuration surface: the master ARM switch, the safety bounds, session credentials, and
 * logging. Every control writes straight through to the shared {@link Configuration} /
 * {@link com.gqlsentinel.core.ScopeGate} / {@link SessionProfile} instances, so there is no
 * separate "apply" step to forget except for the multi-field session editor.
 */
public final class ConfigPanel extends JPanel {

    private final ExtensionContext ctx;

    public ConfigPanel(ExtensionContext ctx) {
        super(new BorderLayout());
        this.ctx = ctx;

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(buildArmingSection());
        content.add(buildBoundsSection());
        content.add(buildSessionSection());
        content.add(buildLoggingSection());

        add(new JScrollPane(content), BorderLayout.CENTER);
    }

    private JPanel buildArmingSection() {
        JPanel p = section("Active testing (safety)");

        JLabel warn = new JLabel("<html><b>Active testing is DISARMED by default.</b> While disarmed, "
                + "the extension only passively observes traffic. Arming it permits the extension to "
                + "send crafted, bounded requests to <u>in-scope</u> hosts only. Only arm this against "
                + "targets you are explicitly authorised to test.</html>");
        warn.setForeground(new Color(0x8a, 0x1c, 0x1c));
        warn.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(warn);

        JCheckBox arm = new JCheckBox("ARM active testing (send crafted requests to in-scope hosts)");
        arm.setAlignmentX(Component.LEFT_ALIGNMENT);
        arm.addActionListener(e -> ctx.scopeGate().setActiveTestingArmed(arm.isSelected()));
        p.add(arm);
        return p;
    }

    private JPanel buildBoundsSection() {
        JPanel p = section("Conservative bounds");
        Configuration cfg = ctx.config();

        JPanel grid = new JPanel(new GridLayout(0, 2, 8, 6));
        grid.setAlignmentX(Component.LEFT_ALIGNMENT);

        JSpinner depth = new JSpinner(new SpinnerNumberModel(
                cfg.maxProbeDepth(), 1, Configuration.HARD_MAX_DEPTH, 1));
        depth.addChangeListener(e -> cfg.setMaxProbeDepth((Integer) depth.getValue()));
        grid.add(new JLabel("Max probe depth (hard cap " + Configuration.HARD_MAX_DEPTH + "):"));
        grid.add(depth);

        JSpinner batch = new JSpinner(new SpinnerNumberModel(
                cfg.probeBatchSize(), 2, Configuration.HARD_MAX_BATCH, 1));
        batch.addChangeListener(e -> cfg.setProbeBatchSize((Integer) batch.getValue()));
        grid.add(new JLabel("Probe batch size (hard cap " + Configuration.HARD_MAX_BATCH + "):"));
        grid.add(batch);

        JSpinner delay = new JSpinner(new SpinnerNumberModel(
                cfg.activeRequestDelayMs(), 0, 5000, 50));
        delay.addChangeListener(e -> cfg.setActiveRequestDelayMs((Integer) delay.getValue()));
        grid.add(new JLabel("Delay between active requests (ms):"));
        grid.add(delay);

        p.add(grid);

        JCheckBox allowMutations = new JCheckBox(
                "Allow replaying state-changing operations (mutations/subscriptions) — NOT recommended");
        allowMutations.setForeground(new Color(0x8a, 0x1c, 0x1c));
        allowMutations.setAlignmentX(Component.LEFT_ALIGNMENT);
        allowMutations.addActionListener(e ->
                cfg.setAllowStateChangingReplay(allowMutations.isSelected()));
        p.add(allowMutations);
        return p;
    }

    private JPanel buildSessionSection() {
        JPanel p = section("Low-privilege session (for field-authorization testing)");

        JLabel help = new JLabel("<html>Browse the target as the <b>privileged</b> user to capture "
                + "baseline queries. Then enter a <b>low-privilege</b> user's credentials here; the "
                + "field-authorization module replays captured queries as this user and as an "
                + "unauthenticated client, and diffs the responses.</html>");
        help.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(help);

        JPanel grid = new JPanel(new GridLayout(0, 2, 8, 6));
        grid.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextField bearer = new JTextField();
        JTextField cookie = new JTextField();
        JTextArea headers = new JTextArea(4, 30);
        headers.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY));
        headers.setToolTipText("One 'Header-Name: value' per line");

        grid.add(new JLabel("Bearer token (without 'Bearer '):"));
        grid.add(bearer);
        grid.add(new JLabel("Cookie header value:"));
        grid.add(cookie);
        p.add(grid);

        p.add(labelled("Custom headers (one 'Name: value' per line):", headers));

        JButton apply = new JButton("Apply low-priv session");
        apply.setAlignmentX(Component.LEFT_ALIGNMENT);
        apply.addActionListener(e -> applySession(bearer.getText(), cookie.getText(), headers.getText()));
        p.add(apply);
        return p;
    }

    private void applySession(String bearer, String cookie, String customHeaders) {
        SessionProfile profile = ctx.lowPrivSession();
        // Rebuild from scratch so removing a field in the UI actually removes it from the profile.
        profile.headers().clear();
        profile.setBearerToken(bearer);
        profile.setCookie(cookie);
        for (String line : customHeaders.split("\\R")) {
            int idx = line.indexOf(':');
            if (idx > 0) {
                profile.putHeader(line.substring(0, idx), line.substring(idx + 1));
            }
        }
        ctx.logger().info("Low-priv session updated (" + profile.headers().size() + " header(s)).");
    }

    private JPanel buildLoggingSection() {
        JPanel p = section("Logging");
        JCheckBox debug = new JCheckBox("Enable debug logging (verbose per-request tracing)");
        debug.setAlignmentX(Component.LEFT_ALIGNMENT);
        debug.addActionListener(e -> ctx.logger().setDebugEnabled(debug.isSelected()));
        p.add(debug);
        return p;
    }

    // ---- small layout helpers ---------------------------------------------------------------

    private JPanel section(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, p.getMaximumSize().height));
        return p;
    }

    private JPanel labelled(String label, Component field) {
        JPanel row = new JPanel(new BorderLayout(6, 2));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel l = new JLabel(label);
        row.add(l, BorderLayout.NORTH);
        row.add(field instanceof JTextArea ? new JScrollPane(field) : field, BorderLayout.CENTER);
        return row;
    }
}
