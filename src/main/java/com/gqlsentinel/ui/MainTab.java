package com.gqlsentinel.ui;

import javax.swing.JComponent;
import javax.swing.JTabbedPane;

import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.modules.ModuleRegistry;

/**
 * Assembles the sub-tabs into the single Burp suite tab. Kept thin: it only wires the panels
 * together in a sensible order (disclaimer first, then the daily-driver tabs).
 */
public final class MainTab {

    private final JTabbedPane root = new JTabbedPane();

    public MainTab(ExtensionContext ctx, ModuleRegistry modules) {
        root.addTab("About / Disclaimer", new AboutPanel());
        root.addTab("Endpoints", new EndpointsPanel(ctx, modules));
        root.addTab("Findings", new FindingsPanel(ctx));
        root.addTab("Schema", new SchemaPanel(modules.introspection()));
        root.addTab("Configuration", new ConfigPanel(ctx));
    }

    public JComponent component() {
        return root;
    }
}
