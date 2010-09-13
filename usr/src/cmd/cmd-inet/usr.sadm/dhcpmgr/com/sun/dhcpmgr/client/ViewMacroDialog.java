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
 * Copyright 1998-2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;

/**
 * This dialog allows the user to view the contents of a macro,
 */
public class ViewMacroDialog extends JDialog {

    class MacroTableModel extends AbstractTableModel {
	private Macro macro;
	
	public MacroTableModel() {
	    setMacro(new Macro());
	}
	
	public MacroTableModel(Macro m) {
	    super();
	    setMacro(m);
	}
	
	public void setMacro(Macro m) {
	    macro = m;
	    fireTableDataChanged();
	}
	
	public int getRowCount() {
	    return macro.optionCount();
	}
	
	public int getColumnCount() {
	    return 2;
	}
	
	public Object getValueAt(int row, int column) {
	    OptionValue v = null;	
	    try {
		v = macro.getOptionAt(row);
	    } catch (ArrayIndexOutOfBoundsException e) {
		return null;
	    }
	    if (v == null) {
		return null;
	    }
	    switch (column) {
	    case 0:
		return v.getName();
	    case 1:
		return v.getValue();
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
    
    private JTextField name;
    private AutosizingTable macroTable;
    private MacroTableModel macroTableModel;
    private JButton closeButton;
    
    /**
     * Construct the dialog.
     * @arg owner The owning dialog
     * @arg c The component relative to which we should be positioned
     * @arg macro The macro we're viewing
     */
    public ViewMacroDialog(Dialog owner, Component c, Macro macro) {
	super(owner);
	setLocationRelativeTo(c);
	
	setTitle(ResourceStrings.getString("view_macro_title"));
	
	getContentPane().setLayout(new BoxLayout(getContentPane(),
	    BoxLayout.Y_AXIS));
	JPanel mainPanel = new JPanel(new BorderLayout());
	mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	
	name = new JTextField(30);
	name.setEditable(false);
	JPanel panel = new JPanel();

	Mnemonic mnName =
            new Mnemonic(ResourceStrings.getString("name_label"));
 	JLabel nLbl = new JLabel(mnName.getString());
        nLbl.setLabelFor(panel);
        nLbl.setToolTipText(mnName.getString());
	nLbl.setDisplayedMnemonic(mnName.getMnemonic());
        panel.add(nLbl);
        panel.add(name);
        mainPanel.add(panel, BorderLayout.NORTH);

	JPanel contentsPanel = new JPanel();
	contentsPanel.setLayout(new BorderLayout());
	Border b = BorderFactory.createCompoundBorder(
	    BorderFactory.createLineBorder(Color.black),
	    BorderFactory.createEmptyBorder(5, 10, 5, 10));
	contentsPanel.setBorder(BorderFactory.createTitledBorder(b,
	    ResourceStrings.getString("contents_label")));
	contentsPanel.setToolTipText(
	    ResourceStrings.getString("contents_label"));
	macroTableModel = new MacroTableModel();
	macroTable = new AutosizingTable(macroTableModel);
	macroTable.getTableHeader().setReorderingAllowed(false);
	macroTable.getTableHeader().setResizingAllowed(false);

	JScrollPane macroTablePane = new JScrollPane(macroTable);
	// Resize table as otherwise it asks for a huge area
	Dimension d = macroTable.getPreferredScrollableViewportSize();
	d.height = 100;
	d.width = 300;
	macroTable.setPreferredScrollableViewportSize(d);
	
	contentsPanel.add(macroTablePane, BorderLayout.CENTER);
	mainPanel.add(contentsPanel, BorderLayout.CENTER);
		
	getContentPane().add(mainPanel);
	getContentPane().add(new JSeparator());
	
	JPanel buttonPanel = new JPanel();

	Mnemonic mnOK = 
	    new Mnemonic(ResourceStrings.getString("ok"));
	closeButton = new JButton(mnOK.getString());
	closeButton.setToolTipText(mnOK.getString());
	closeButton.setMnemonic(mnOK.getMnemonic());

	buttonPanel.add(closeButton);
	closeButton.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		setVisible(false);
		dispose();
	    }
	});
	
	getContentPane().add(buttonPanel);
	
        name.setText(macro.getKey());
	macroTableModel.setMacro(macro);
    }
}
