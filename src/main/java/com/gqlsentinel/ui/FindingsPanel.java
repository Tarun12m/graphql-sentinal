package com.gqlsentinel.ui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.export.HtmlExporter;
import com.gqlsentinel.export.JsonExporter;
import com.gqlsentinel.model.Finding;

/**
 * The findings table plus an evidence viewer and export controls.
 *
 * <p>Swing threading: the {@link com.gqlsentinel.model.FindingStore} notifies us from analysis
 * threads, so every model mutation is marshalled onto the Event Dispatch Thread via
 * {@link SwingUtilities#invokeLater}. The table reads an immutable snapshot so it never tears.
 */
public final class FindingsPanel extends JPanel {

    private final ExtensionContext ctx;
    private final FindingTableModel tableModel = new FindingTableModel();
    private final JTable table = new JTable(tableModel);
    private final JTextArea descriptionArea = new JTextArea();
    private final JTextArea requestArea = new JTextArea();
    private final JTextArea responseArea = new JTextArea();

    private final JsonExporter jsonExporter = new JsonExporter();
    private final HtmlExporter htmlExporter = new HtmlExporter();

    public FindingsPanel(ExtensionContext ctx) {
        super(new BorderLayout());
        this.ctx = ctx;

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                showSelectedEvidence();
            }
        });

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Findings"));

        JTabbedPane evidenceTabs = new JTabbedPane();
        descriptionArea.setEditable(false);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        requestArea.setEditable(false);
        responseArea.setEditable(false);
        evidenceTabs.addTab("Description", new JScrollPane(descriptionArea));
        evidenceTabs.addTab("Request evidence", new JScrollPane(requestArea));
        evidenceTabs.addTab("Response evidence", new JScrollPane(responseArea));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, evidenceTabs);
        split.setResizeWeight(0.55);

        add(buildToolbar(), BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        // Auto-refresh whenever a new finding lands.
        ctx.findingStore().addListener(f -> SwingUtilities.invokeLater(this::refresh));
        refresh();
    }

    private JPanel buildToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton refresh = new JButton("Refresh");
        refresh.addActionListener(e -> refresh());
        JButton clear = new JButton("Clear findings");
        clear.addActionListener(e -> {
            ctx.findingStore().clear();
            refresh();
        });
        JButton exportJson = new JButton("Export JSON");
        exportJson.addActionListener(e -> export("json"));
        JButton exportHtml = new JButton("Export HTML");
        exportHtml.addActionListener(e -> export("html"));

        bar.add(refresh);
        bar.add(clear);
        bar.add(exportJson);
        bar.add(exportHtml);
        return bar;
    }

    private void refresh() {
        tableModel.setData(ctx.findingStore().snapshot());
    }

    private void showSelectedEvidence() {
        int row = table.getSelectedRow();
        Finding f = tableModel.at(row);
        if (f == null) {
            descriptionArea.setText("");
            requestArea.setText("");
            responseArea.setText("");
            return;
        }
        descriptionArea.setText(f.title() + "\n\n" + f.description()
                + "\n\nRemediation:\n" + f.remediation());
        descriptionArea.setCaretPosition(0);
        requestArea.setText(f.requestEvidence());
        requestArea.setCaretPosition(0);
        responseArea.setText(f.responseEvidence());
        responseArea.setCaretPosition(0);
    }

    private void export(String format) {
        List<Finding> findings = ctx.findingStore().snapshot();
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No findings to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("graphql-sentinel-report." + format));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        String content = format.equals("json") ? jsonExporter.export(findings)
                                                : htmlExporter.export(findings);
        try {
            Files.write(chooser.getSelectedFile().toPath(), content.getBytes(StandardCharsets.UTF_8));
            ctx.logger().info("Exported " + findings.size() + " findings to "
                    + chooser.getSelectedFile().getAbsolutePath());
            JOptionPane.showMessageDialog(this, "Exported " + findings.size() + " findings.");
        } catch (IOException ex) {
            ctx.logger().error("Export failed", ex);
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage());
        }
    }

    /** Table model backed by an immutable snapshot list. */
    private static final class FindingTableModel extends AbstractTableModel {
        private static final String[] COLS =
                {"Severity", "Module", "Title", "Endpoint", "Operation", "Time"};
        private static final DateTimeFormatter TIME_FMT =
                DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

        private List<Finding> data = new ArrayList<>();

        void setData(List<Finding> data) {
            this.data = data;
            fireTableDataChanged();
        }

        Finding at(int row) {
            return row >= 0 && row < data.size() ? data.get(row) : null;
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            Finding f = data.get(row);
            return switch (col) {
                case 0 -> f.severity().name();
                case 1 -> f.module();
                case 2 -> f.title();
                case 3 -> f.endpointUrl();
                case 4 -> f.affectedOperation();
                case 5 -> TIME_FMT.format(f.timestamp());
                default -> "";
            };
        }
    }
}
