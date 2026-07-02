package com.gqlsentinel.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.modules.AnalysisModule;
import com.gqlsentinel.modules.ModuleRegistry;

/**
 * Lists discovered GraphQL endpoints and launches the active modules against the selected one.
 *
 * <p>Active runs happen on a single-threaded background executor, never on the EDT: they perform
 * network I/O and must not freeze Burp's UI, and serialising them (one at a time) is a further
 * politeness measure toward the target on top of the per-request delay.
 */
public final class EndpointsPanel extends JPanel {

    private final ExtensionContext ctx;
    private final ModuleRegistry modules;
    private final EndpointTableModel tableModel = new EndpointTableModel();
    private final JTable table = new JTable(tableModel);

    // Single worker so active tests run sequentially and never block the Swing thread.
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "gql-sentinel-active");
        t.setDaemon(true);
        return t;
    });

    public EndpointsPanel(ExtensionContext ctx, ModuleRegistry modules) {
        super(new BorderLayout());
        this.ctx = ctx;
        this.modules = modules;

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scroll = new JScrollPane(table);
        scroll.setBorder(BorderFactory.createTitledBorder("Detected GraphQL endpoints (in-scope only)"));

        add(buildToolbar(), BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        ctx.endpointRegistry().addListener(ep -> SwingUtilities.invokeLater(this::refresh));
        refresh();
    }

    private JPanel buildToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bar.add(new JLabel("Run against selected endpoint:  "));
        for (AnalysisModule module : modules.all()) {
            if (module.supportsActive()) {
                JButton b = new JButton(module.name());
                b.setToolTipText(module.description());
                b.addActionListener(e -> runModule(module));
                bar.add(b);
            }
        }
        JButton all = new JButton("Run ALL active");
        all.addActionListener(e -> runAllActive());
        bar.add(all);

        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refresh());
        bar.add(refresh);
        return bar;
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel note = new JLabel("Active tests require ARMING in the Configuration tab and only run "
                + "against in-scope hosts.");
        note.setForeground(new Color(0x57, 0x60, 0x6a));
        bar.add(note);
        return bar;
    }

    private void runAllActive() {
        withSelectedEndpoint(endpoint -> {
            for (AnalysisModule module : modules.all()) {
                if (module.supportsActive()) {
                    submit(endpoint, module);
                }
            }
        });
    }

    private void runModule(AnalysisModule module) {
        withSelectedEndpoint(endpoint -> submit(endpoint, module));
    }

    private void withSelectedEndpoint(Consumer<DetectedEndpoint> action) {
        int row = table.getSelectedRow();
        DetectedEndpoint endpoint = tableModel.at(row);
        if (endpoint == null) {
            JOptionPane.showMessageDialog(this, "Select an endpoint first.");
            return;
        }
        if (!ctx.scopeGate().isActiveTestingArmed()) {
            JOptionPane.showMessageDialog(this,
                    "Active testing is disarmed. Enable it in the Configuration tab first.");
            return;
        }
        action.accept(endpoint);
    }

    private void submit(DetectedEndpoint endpoint, AnalysisModule module) {
        ctx.logger().info("Queued active module '" + module.name() + "' for " + endpoint.key());
        worker.submit(() -> {
            try {
                module.runActive(endpoint);
            } catch (RuntimeException ex) {
                ctx.logger().error("Active module '" + module.name() + "' failed", ex);
            } finally {
                SwingUtilities.invokeLater(this::refresh); // introspection state may have changed
            }
        });
    }

    private void refresh() {
        tableModel.setData(ctx.endpointRegistry().all());
    }

    private static final class EndpointTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Endpoint", "Confidence", "Introspection", "Samples"};
        private List<DetectedEndpoint> data = new ArrayList<>();

        void setData(List<DetectedEndpoint> data) {
            this.data = data;
            fireTableDataChanged();
        }

        DetectedEndpoint at(int row) {
            return row >= 0 && row < data.size() ? data.get(row) : null;
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            DetectedEndpoint e = data.get(row);
            return switch (col) {
                case 0 -> e.url();
                case 1 -> e.confidence();
                case 2 -> e.introspection().name();
                case 3 -> e.samples().size();
                default -> "";
            };
        }
    }
}
