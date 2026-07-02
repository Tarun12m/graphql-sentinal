package com.gqlsentinel;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.SwingUtilities;

import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.core.PassiveDetectionHandler;
import com.gqlsentinel.modules.ModuleRegistry;
import com.gqlsentinel.ui.MainTab;

/**
 * Extension entry point. Burp instantiates this class (declared in the JAR's manifest via the
 * Montoya service loader) and calls {@link #initialize}.
 *
 * <p>Responsibilities kept deliberately tiny — this is composition root only:
 * <ol>
 *   <li>Build the {@link ExtensionContext} (all shared services).</li>
 *   <li>Construct the modules.</li>
 *   <li>Register the passive proxy handler (safe, always-on).</li>
 *   <li>Register the UI tab.</li>
 * </ol>
 * No analysis logic lives here; everything is delegated so each concern stays independently
 * testable and this file reads as a wiring diagram.
 */
public final class GraphQLSentinelExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("GraphQL Sentinel");

        ExtensionContext ctx = new ExtensionContext(api);
        ctx.logger().info("GraphQL Sentinel initialising — passive detection active; "
                + "active testing DISARMED until enabled in the Configuration tab.");

        ModuleRegistry modules = new ModuleRegistry(ctx);

        // Passive detection is always safe (it never sends traffic) so we register it immediately.
        api.proxy().registerResponseHandler(new PassiveDetectionHandler(ctx, modules));

        // Build the UI on the EDT, as Swing requires.
        SwingUtilities.invokeLater(() -> {
            MainTab mainTab = new MainTab(ctx, modules);
            api.userInterface().registerSuiteTab("GraphQL Sentinel", mainTab.component());
            ctx.logger().info("GraphQL Sentinel UI registered.");
        });

        // Clean shutdown hook: nothing holds OS resources, but log so the operator sees lifecycle.
        api.extension().registerUnloadingHandler(() ->
                ctx.logger().info("GraphQL Sentinel unloading. Goodbye."));
    }
}
