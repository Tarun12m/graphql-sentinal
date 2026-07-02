package com.gqlsentinel.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;

import com.gqlsentinel.modules.IntrospectionModule;
import com.gqlsentinel.model.GraphQLSchema;

/**
 * Displays the most recently parsed introspection schema as a readable tree. Pulls on demand from
 * the {@link IntrospectionModule} rather than caching, so it always reflects the latest fetch.
 */
public final class SchemaPanel extends JPanel {

    private final IntrospectionModule introspection;
    private final JTextArea schemaArea = new JTextArea();

    public SchemaPanel(IntrospectionModule introspection) {
        super(new BorderLayout());
        this.introspection = introspection;

        schemaArea.setEditable(false);
        schemaArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(schemaArea);
        scroll.setBorder(BorderFactory.createTitledBorder("Parsed schema (from introspection)"));

        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Refresh schema view");
        refresh.addActionListener(e -> refresh());
        bar.add(refresh);

        add(bar, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        refresh();
    }

    private void refresh() {
        GraphQLSchema schema = introspection.lastSchema();
        if (schema == null) {
            schemaArea.setText("No schema available yet.\n\n"
                    + "Run the Introspection module against an endpoint (Endpoints tab). "
                    + "If introspection is disabled on the target (the secure configuration), "
                    + "no schema can be retrieved.");
        } else {
            schemaArea.setText(schema.renderTree());
        }
        schemaArea.setCaretPosition(0);
    }
}
