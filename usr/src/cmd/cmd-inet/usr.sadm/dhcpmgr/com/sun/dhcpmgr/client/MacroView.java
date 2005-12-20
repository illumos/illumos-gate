/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.*;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.bridge.BridgeException;

// Background thread for doing retrieval while keeping GUI live
class MacroLoader extends com.sun.dhcpmgr.ui.SwingWorker {
    public Object construct() {
	try {
	    return DataManager.get().getMacros(true);
	} catch (final BridgeException e) {
	    // Since we're in a background thread, ask Swing to run ASAP.
	    SwingUtilities.invokeLater(new Runnable() {
		Object [] args = new Object[] { e.getMessage() };
		public void run() {
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("error_loading_macros"));
		    JOptionPane.showMessageDialog(null, form.format(args),
			ResourceStrings.getString("server_error_title"),
			JOptionPane.ERROR_MESSAGE);
		}
	    });
	}
	return null;
    }

    public void finished() {
	Macro [] macros = (Macro [])get();
	if (macros == null) {
	    macros = new Macro[0];
	}

	MacroView.macroTreeModel.getRootNode().setMacros(macros);
    }
}

/**
 * Implements a display of the macro hierarchy contained in the dhcptab
 */
public class MacroView implements View {

    // A node in the tree of macros
    class MacroTreeNode extends DefaultMutableTreeNode {
	private boolean scannedIncludes = false;
	private boolean isScanning = false;

	public MacroTreeNode(Object o) {
	    super(o);
	}

	public String toString() {
	    Macro m = (Macro)getUserObject();
	    return m.getKey();
	}

	public int getChildCount() {
	    /*
	     * scannedIncludes is used so that we only build the tree once;
	     * isScanning prevents us from recursing infinitely because add()
	     * ends up coming right back here
	     */
	    if (!scannedIncludes && !isScanning) {
		isScanning = true;
		Macro m = (Macro)getUserObject();
		Enumeration e = m.elements();
		while (e.hasMoreElements()) {
		    OptionValue o = (OptionValue)e.nextElement();
		    if (o instanceof IncludeOptionValue) {
			Macro m2 =
			    macroTreeModel.getRootNode().getMacro(
			    (String)o.getValue());
			if (m2 != null) {
			    add(new MacroTreeNode(m2));
			}
		    }
		}
		scannedIncludes = true;
		isScanning = false;
	    }
	    return super.getChildCount();
	}

	public Macro getMacro() {
	    return (Macro)getUserObject();
	}
    }

    /*
     * Special class for the root node; this handles retrieving the data from
     * the server
     */
    class MacroTreeRootNode extends MacroTreeNode {
	private Macro [] macros = null;

	public MacroTreeRootNode() {
	    super(new Macro());
	}

	public MacroTreeRootNode(Object o) {
	    super(o);
	}

	protected void setMacros(Macro [] newmacros) {
	    macros = newmacros;
	    if (newmacros != null) {
		for (int i = 0; i < macros.length; ++i) {
		    add(new MacroTreeNode(macros[i]));
		}
	    }
	    macroTreeModel.reload();
	    reloadCompleted();
	}

	public String toString() {
	    return ResourceStrings.getString("macros");
	}

	public int getChildCount() {
	    if (macros == null) {
		return 0;
	    }
	    return super.getChildCount();
	}

	public void load() {
	    // Display starting message and clear tree
	    MainFrame.setStatusText(
		ResourceStrings.getString("loading_macros"));
	    removeAllChildren();
	    macroTreeModel.reload();
	    // Kick off background loader
	    MacroLoader loader = new MacroLoader();
	}

	public Macro getMacro() {
	    return null;
	}

	// Find a particular macro by name
	public Macro getMacro(String name) {
	    if (macros != null) {
		for (int i = 0; i < macros.length; ++i) {
		    if (name.equals(macros[i].getKey())) {
			return macros[i];
		    }
		}
	    }
	    return null;
	}
    }

    // Model for data contained in macro tree
    class MacroTreeModel extends DefaultTreeModel {
	public MacroTreeModel(MacroTreeRootNode n) {
	    super(n);
	}

	public void load() {
	    getRootNode().load();
	}

	public Macro getMacro(String name) {
	    return getRootNode().getMacro(name);
	}

	public MacroTreeRootNode getRootNode() {
	    return (MacroTreeRootNode)super.getRoot();
	}
    }

    // Model for table displaying contents of a macro
    class MacroTableModel extends AbstractTableModel {
	private Macro macro = null;

	public MacroTableModel() {
	    super();
	}

	public void display(Macro m) {
	    macro = m;
	    fireTableDataChanged();
	}

	public int getRowCount() {
	    if (macro == null) {
		return 0;
	    } else {
		return macro.optionCount();
	    }
	}

	public int getColumnCount() {
	    return 2;
	}

	public Object getValueAt(int row, int column) {
	    if (macro == null) {
		return null;
	    }
	    switch (column) {
	    case 0:
		return macro.getOptionAt(row).getName();
	    case 1:
		return macro.getOptionAt(row).getValue();
	    default:
		return null;
	    }
	}

	public Class getColumnClass(int column) {
	    switch (column) {
	    case 0:
	    case 1:
		return String.class;
	    default:
		super.getColumnClass(column);
	    }
	    return null;
	}

	public String getColumnName(int column) {
	    switch (column) {
	    case 0:
		return ResourceStrings.getString("option_column");
	    case 1:
		return ResourceStrings.getString("value_column");
	    default:
		super.getColumnName(column);
	    }
	    return null;
	}
    }

    // Recipient of update messages sent when the macro editing dialogs exit
    class DialogListener implements ActionListener {
	public void actionPerformed(ActionEvent e) {
	    if (!e.getActionCommand().equals(DialogActions.CANCEL)) {
		reload();
	    }
	}
    }

    private JTree macroTree;
    protected  static MacroTreeModel macroTreeModel = null;
    private AutosizingTable macroTable;
    private JScrollPane treePane;
    private JScrollPane macroTablePane;
    private JSplitPane splitPane;
    private boolean firstActivation = true;
    private MacroTableModel macroTableModel;
    private JCheckBoxMenuItem showGrid;
    private JMenuItem macroHelp;
    private Vector[] menuItems;
    private Frame myFrame;
    private boolean firstview = true;
    private Vector selectionListeners = new Vector();

    public MacroView() {
	// Create tree for macro display
	macroTreeModel = new MacroTreeModel(new MacroTreeRootNode());
	macroTree = new JTree(macroTreeModel);
	// Listen for selection events, load selected macro into table
	macroTree.addTreeSelectionListener(new TreeSelectionListener() {
	    public void valueChanged(TreeSelectionEvent e) {
		TreePath selPath = macroTree.getSelectionPath();
		if (selPath != null) {
		    TreeNode node = (TreeNode)selPath.getLastPathComponent();
		    if (node instanceof MacroTreeNode) {
			macroTableModel.display(
			    ((MacroTreeNode)node).getMacro());
		    } else {
			macroTableModel.display(null);
		    }
		} else {
		    macroTableModel.display(null);
		}
		// Notify listeners that our selection state may have changed
		notifySelectionListeners();
	    }
	});
	// Single selection for now
	macroTree.getSelectionModel().setSelectionMode(
	    TreeSelectionModel.SINGLE_TREE_SELECTION);
	// Make a scroll pane for it
	treePane = new JScrollPane();
	treePane.getViewport().add(macroTree);
	// Make double-clicks the same as Edit->Properties
	macroTree.addMouseListener(new MouseAdapter() {
	    public void mouseClicked(MouseEvent e) {
		if (e.getClickCount() == 2) {
		    // Don't do anything if it's the root node
		    TreePath selPath =
			macroTree.getClosestPathForLocation(e.getX(), e.getY());
		    macroTree.addSelectionPath(selPath);
		    if (selPath.getPathCount() != 1) {
			handleProperties();
		    }
		}
	    }
	});

	// Create table to display in data area
	macroTableModel = new MacroTableModel();
	macroTable = new AutosizingTable(macroTableModel);

	// Can't mess with the column order, or select any data
	macroTable.getTableHeader().setReorderingAllowed(false);
	macroTable.setRowSelectionAllowed(false);
	macroTable.setColumnSelectionAllowed(false);

	// Now wrap it with scrollbars
	macroTablePane = new JScrollPane(macroTable);

	// Create split pane containing the tree & table, side-by-side
	splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treePane,
	    macroTablePane);

	// Create menu items
        Mnemonic mnShowGrid =
            new Mnemonic(ResourceStrings.getString("show_grid"));
        showGrid = new JCheckBoxMenuItem(mnShowGrid.getString(),
            true);
        showGrid.setMnemonic(mnShowGrid.getMnemonic());
	showGrid.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		macroTable.setShowGrid(showGrid.getState());
	    }
	});

	Mnemonic mnOnMacros =
	    new Mnemonic(ResourceStrings.getString("on_macros_item"));
	macroHelp = new JMenuItem(mnOnMacros.getString());
	macroHelp.setMnemonic(mnOnMacros.getMnemonic());
	macroHelp.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		DhcpmgrApplet.showHelp("macros_reference");
	    }
	});


	/*
	 * Construct lists of menu items custom to this view.
	 */
	menuItems = new Vector[MainFrame.MENU_COUNT];
	for (int i = 0; i < menuItems.length; ++i) {
	    menuItems[i] = new Vector();
	}
	menuItems[MainFrame.VIEW_MENU].addElement(showGrid);
	menuItems[MainFrame.HELP_MENU].addElement(macroHelp);
    }

    public String getName() {
	return ResourceStrings.getString("macro_view_name");
    }

    // Return menus that we wish to add to MainFrame, in our case none
    public Enumeration menus() {
	return null;
    }

    // Return menu items for each menu as requested by MainFrame
    public Enumeration menuItems(int menu) {
	return menuItems[menu].elements();
    }

    public Component getDisplay() {
	return splitPane;
    }

    private void reload() {
	macroTreeModel.load();
    }

    // Callback from model when loading completed to update display
    private void reloadCompleted() {
	// Doesn't display correctly without this
	splitPane.resetToPreferredSizes();
	String s = MessageFormat.format(
	    ResourceStrings.getString("macro_status_message"),
	    macroTreeModel.getRootNode().getChildCount());
	MainFrame.setStatusText(s);
	macroTree.clearSelection();
	macroTable.clearSelection();
	/*
	 * Check for syntax errors.
	 */
	MacroTreeRootNode rootNode = macroTreeModel.getRootNode();
	Vector errs = new Vector();
	for (int i = 0; i < rootNode.macros.length; ++i) {
	    try {
		rootNode.macros[i].validate();
	    } catch (ValidationException e) {
		errs.addElement(rootNode.macros[i].getKey());
	    }
	}
	if (errs.size() != 0) {
	    // Found some errors; warn user
	    Object [] objs = new Object[2];
	    objs[0] = ResourceStrings.getString("macro_validation_warning");
	    JList macroList = new JList(errs);
	    JScrollPane scrollPane = new JScrollPane(macroList);
	    macroList.setVisibleRowCount(4);
	    objs[1] = scrollPane;
	    JOptionPane.showMessageDialog(macroTable, objs,
		ResourceStrings.getString("warning"),
		JOptionPane.WARNING_MESSAGE);
	}
	macroTree.setSelectionRow(1);
    }

    public void setActive(boolean state) {
	if (state) {
	    // We only do an automatic load the first time we're displayed
	    if (firstview) {
		myFrame = (Frame)SwingUtilities.getAncestorOfClass(
		    MainFrame.class, macroTree);
		reload();
		firstview = false;
	    }
	}
    }

    /*
     * Handle a find operation.
     * Algorithm used here searches nodes in the order they appear in the
     * displayed tree.  This requires traversing the entire tree starting at
     * an arbitrary point with some special twists.
     */
    public void find(String s) {
	// Clear status if we had an old message lying there
	MainFrame.setStatusText("");
	MacroTreeNode startNode =
	    (MacroTreeNode)macroTree.getLastSelectedPathComponent();
	if (startNode == null) {
	    // Nothing selected so start at root
	    startNode = macroTreeModel.getRootNode();
	}
	// Start by searching children of selected node
	MacroTreeNode result = searchUnderNode(startNode, s);
	if (result != null) {
	    selectNode(result); // Found one, select it and return
	    return;
	}
	// Get all ancestor nodes of selected
	TreeNode [] path = macroTreeModel.getPathToRoot(startNode);
	MacroTreeNode pathNode = null;

	// Walk up towards root of tree, at each level search all children
	for (int i = path.length - 1; i >= 0; --i) {
	    result = searchNodeLevel((MacroTreeNode)path[i], startNode, s);
	    if (result != null) {
		selectNode(result); // Found one, select it and return
		return;
	    }
	    // Move up a level
	    startNode = (MacroTreeNode)path[i];
	    /*
	     * If it's not the root node and it matches, remember it.  We don't
	     * return immediately because this is actually about last in the
	     * display order.
	     */
	    if (startNode.getMacro() != null) {
		if (startNode.getMacro().getKey().indexOf(s) != -1) {
		    pathNode = startNode;
		}
	    }
	}
	// We found one on the path to the root, select and return
	if (pathNode != null) {
	    selectNode(pathNode);
	    return;
	}
	// Nothing found; show an error
	MessageFormat form = null;
	Object [] args = new Object[1];
	form = new MessageFormat(ResourceStrings.getString("find_macro_error"));
	args[0] = s;
	MainFrame.setStatusText(form.format(args));
    }

    // Search a particular level of a tree in the order a user would expect
    private MacroTreeNode searchNodeLevel(MacroTreeNode n,
	    MacroTreeNode startNode, String s) {
	// Skip all children prior to the startNode in display order
	Enumeration e = n.children();
	while (e.hasMoreElements()) {
	    MacroTreeNode cn = (MacroTreeNode)e.nextElement();
	    if (cn == startNode) {
		break;
	    }
	}
	// Now search those after the startNode in the display order
	while (e.hasMoreElements()) {
	    MacroTreeNode cn = (MacroTreeNode)e.nextElement();
	    MacroTreeNode result = searchNode(cn, s);
	    if (result != null) {
		return result;
	    }
	}
	// Got to the end of this level and didn't find it, so wrap to beginning
	e = n.children();
	while (e.hasMoreElements()) {
	    MacroTreeNode cn = (MacroTreeNode)e.nextElement();
	    if (cn == startNode) {
		break;
	    }
	    MacroTreeNode result = searchNode(cn, s);
	    if (result != null) {
		return result;
	    }
	}
	return null;
    }

    // Search a node and all its children for a particular string
    private MacroTreeNode searchNode(MacroTreeNode n, String s) {
	if (n.getMacro().getKey().indexOf(s) != -1
	    || n.getMacro().getValue().indexOf(s) != -1) {
	    return n;
	}
	return searchUnderNode(n, s);
    }

    // Search all children, recursively, of a node for a particular string
    private MacroTreeNode searchUnderNode(MacroTreeNode n, String s) {
	Enumeration e = n.children();
	while (e.hasMoreElements()) {
	    MacroTreeNode cn = (MacroTreeNode)e.nextElement();
	    if (cn.getMacro().getKey().indexOf(s) != -1
		|| cn.getMacro().getValue().indexOf(s) != -1) {
		return cn;
	    }
	    MacroTreeNode result = searchUnderNode(cn, s);
	    if (result != null) {
		return result;
	    }
	}
	return null;
    }

    // Select a node and make sure it's visible
    private void selectNode(MacroTreeNode n) {
	macroTree.clearSelection();
	TreePath selPath = new TreePath(macroTreeModel.getPathToRoot(n));
	macroTree.addSelectionPath(selPath);
	macroTree.scrollPathToVisible(selPath);
    }

    // Return the macro currently selected
    private Macro getSelectedMacro() {
	TreePath selPath = macroTree.getSelectionPath();
	if (selPath != null) {
	    TreeNode node = (TreeNode)selPath.getLastPathComponent();
	    if (node instanceof MacroTreeNode) {
		return ((MacroTreeNode)node).getMacro();
	    }
	}
	return null;
    }

    public void handleCreate() {
	CreateMacroDialog d = new CreateMacroDialog(myFrame,
	    CreateMacroDialog.CREATE);
	d.addActionListener(new DialogListener());
	d.pack();
	d.setVisible(true);
    }

    public void handleDelete() {
	Macro m = getSelectedMacro();
	if (m == null) {
	    return;
	}
	DeleteMacroDialog d = new DeleteMacroDialog(myFrame, m);
	d.addActionListener(new DialogListener());
	d.pack();
	d.setVisible(true);
    }

    public void handleDuplicate() {
	Macro m = getSelectedMacro();
	if (m == null) {
	    return;
	}
	CreateMacroDialog d = new CreateMacroDialog(myFrame,
	    CreateMacroDialog.DUPLICATE);
	d.addActionListener(new DialogListener());
	d.setMacro((Macro)m.clone());
	d.pack();
	d.setVisible(true);
    }

    public void handleProperties() {
	Macro m = getSelectedMacro();
	if (m == null) {
	    return;
	}
	CreateMacroDialog d = new CreateMacroDialog(myFrame,
	    CreateMacroDialog.EDIT);
	d.addActionListener(new DialogListener());
	d.setMacro((Macro)m.clone());
	d.pack();
	d.setVisible(true);
    }

    public void handleUpdate() {
	reload();
    }

    public void addSelectionListener(SelectionListener listener) {
	selectionListeners.addElement(listener);
    }

    public void removeSelectionListener(SelectionListener listener) {
	selectionListeners.removeElement(listener);
    }

    private void notifySelectionListeners() {
	Enumeration en = selectionListeners.elements();
	while (en.hasMoreElements()) {
	    SelectionListener l = (SelectionListener)en.nextElement();
	    l.valueChanged();
	}
    }

    public boolean isSelectionEmpty() {
	TreePath path = macroTree.getSelectionPath();
	// If empty or the root of the tree is selected, then we call it empty
	return ((path == null) || (path.getPathCount() == 1));
    }

    public boolean isSelectionMultiple() {
	return false; // We don't allow multiple selection
    }
}
