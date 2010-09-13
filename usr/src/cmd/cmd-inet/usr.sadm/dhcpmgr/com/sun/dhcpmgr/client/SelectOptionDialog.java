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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;

import java.awt.*;
import java.awt.event.*;
import java.text.MessageFormat;
import java.util.*;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;

/**
 * Dialog to select an option for inclusion in a macro.
 */
public class SelectOptionDialog extends JComponent
	implements ButtonPanelListener {
    private JComboBox category;
    private AutosizingTable optionTable;
    private ButtonPanel buttonPanel;
    private OptionTableModel optionTableModel;
    private TableSorter sortedModel;
    static final String SELECTED_OPTION = "selected_option";
    static String value = null;
    static JDialog dialog;
    private OptionContext [] categories = {
	Option.ctxts[Option.STANDARD],
	Option.ctxts[Option.EXTEND],
	Option.ctxts[Option.VENDOR],
	Option.ctxts[Option.SITE]
    };

    // Model for the table displaying option descriptions
    class OptionTableModel extends AbstractTableModel {
	private Option [] data;
	private ResourceBundle bundle;
	
	public OptionTableModel() {
	    super();
	    data = new Option[0];
	    // Locate the resource bundle containing the localized descriptions
	    bundle = ResourceBundle.getBundle(
		"com.sun.dhcpmgr.client.OptionDescriptions",
		Locale.getDefault());
	}
	
	public void setCategory(OptionContext category) {
	    byte code = category.getCode();
	    if (code == Option.ctxts[Option.STANDARD].getCode()) {
		data = StandardOptions.getAllOptions();
	    } else if (code == Option.ctxts[Option.EXTEND].getCode() || 
		code == Option.ctxts[Option.SITE].getCode() ||
		code == Option.ctxts[Option.VENDOR].getCode()) {
		try {
		    // Get all locally defined options from DataManager
		    Option [] allOptions = DataManager.get().getOptions(false);
		    Vector v = new Vector();
		    // Now filter by the selected type
		    for (int i = 0; i < allOptions.length; ++i) {
			if (allOptions[i].getContext() == code) {
			    v.addElement(allOptions[i]);
			}
		    }
		    // Convert to an array
		    data = new Option[v.size()];
		    v.copyInto(data);
		} catch (Exception e) {
		    data = new Option[0];
		}
	    }
	    // Tell the sorter things changed
	    sortedModel.reallocateIndexes();
	    fireTableDataChanged();
	}
	
	public int getRowCount() {
	    return data.length;
	}
	
	public int getColumnCount() {
	    return 2;
	}
	
	public Object getValueAt(int row, int column) {
	    if (column == 0) {
		return data[row].getKey();
	    } else {
		try {
		    /**
		     * Look up descriptions in the properties file indexed by
		     * option name
		     */
		    return bundle.getString(data[row].getKey());
		} catch (Exception e) {
		    // Ignore; we just don't have a description for this one
		    return null;

		}
	    }
	}
	
	public Class getColumnClass(int column) {
	    return String.class;
	}
	
	public String getColumnName(int column) {
	    if (column == 0) {
		return ResourceStrings.getString("option_column");
	    } else {
		return ResourceStrings.getString("description_column");
	    }
	}
	
	public boolean isCellEditable(int row, int column) {
	    return false;
	}
    }
    
    // Generate the dialog
    public void createDialog() {
	dialog = new JDialog((JFrame)null,
	    ResourceStrings.getString("select_option_title"), true);
	
	dialog.getContentPane().setLayout(new BoxLayout(dialog.getContentPane(),
	    BoxLayout.Y_AXIS));

	// Label and combo box for selecting option category
	JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

 	Mnemonic mnCat =
            new Mnemonic(ResourceStrings.getString("category_label"));
        JLabel catLbl =
            new JLabel(mnCat.getString());
	panel.add(catLbl);
        category = new JComboBox(categories);

        catLbl.setLabelFor(category);
        catLbl.setToolTipText(mnCat.getString());
        catLbl.setDisplayedMnemonic(mnCat.getMnemonic());

	category.setEditable(false);
	panel.add(category);
	
	dialog.getContentPane().add(panel);

	// Table for selecting the options in the given category	
	optionTableModel = new OptionTableModel();
	// Sort options by name, alphabetically
	sortedModel = new TableSorter(optionTableModel);
	sortedModel.sortByColumn(0);
	// Use an auto-sizing table so descriptions get the space they need
	optionTable = new AutosizingTable(sortedModel);
	optionTable.getTableHeader().setReorderingAllowed(false);
	optionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	JScrollPane scrollPane = new JScrollPane(optionTable);
	panel = new JPanel();
	panel.add(scrollPane);
	dialog.getContentPane().add(panel);
	
	// Put in usual separator and buttons
	dialog.getContentPane().add(new JSeparator());
	buttonPanel = new ButtonPanel(false, false);
	buttonPanel.addButtonPanelListener(this);
	dialog.getContentPane().add(buttonPanel);
	
	/*
	 * As user changes category selected, update table to view category
	 * contents
	 */
	category.addItemListener(new ItemListener() {
	    public void itemStateChanged(ItemEvent e) {
	    	updateTable();
	    }
	});
	
	// Only enable OK when there is an option selected in the table
	optionTable.getSelectionModel().addListSelectionListener(
		new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		if (optionTable.getSelectedRow() == -1) {
		    buttonPanel.setOkEnabled(false);
		} else {
		    buttonPanel.setOkEnabled(true);
		}
	    }
	});
	
	// Ensure table displays data for initial selection
	updateTable();
    }
    
    /**
     * Update the table to the current category selection.
     */
    private void updateTable() {
	optionTableModel.setCategory(categories[category.getSelectedIndex()]);
	optionTable.clearSelection();
    }

    public void buttonPressed(int buttonId) {
	switch (buttonId) {
	case OK:
	    firePropertyChange(SELECTED_OPTION, null,
		(String)optionTableModel.getValueAt(
		sortedModel.mapRowAt(optionTable.getSelectedRow()), 0));
	    break;
	case CANCEL:
	    firePropertyChange(SELECTED_OPTION, null, null);
	    break;
	}
    }
    
    /**
     * Here's the way to display this dialog modally and retrieve the value
     * selected
     * @param c a component relative to which the dialog should be displayed
     */
    public static String showDialog(Component c) {	
	SelectOptionDialog d = new SelectOptionDialog();
	d.createDialog();
	/*
	 * When user presses OK or Cancel, retrieve the value and kill the
	 * dialog
	 */
	d.addPropertyChangeListener(new PropertyChangeListener() {
	    public void propertyChange(PropertyChangeEvent e) {
		dialog.setVisible(false);
		dialog.dispose();
		value = (String)e.getNewValue();
	    }
	});
	dialog.setLocationRelativeTo(c);
	dialog.pack();
	dialog.setVisible(true);
	return value;
    }
}
