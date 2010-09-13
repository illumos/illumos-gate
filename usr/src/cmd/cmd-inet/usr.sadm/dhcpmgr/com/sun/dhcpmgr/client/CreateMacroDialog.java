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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
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

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.bridge.NotRunningException;

/**
 * Dialog to create/duplicate/edit a macro.
 */
public class CreateMacroDialog extends JDialog implements ButtonPanelListener {

    // Model for the table that displays the macro's contents
    class MacroTableModel extends AbstractTableModel {
	Macro macro;
	
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
		return super.getColumnClass(column);
	    }
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
	
	public boolean isCellEditable(int row, int column) {
	    return false;
	}
	
	public void moveRowUp(int row) {
	    OptionValue v = macro.getOptionAt(row);
	    macro.deleteOptionAt(row);
	    macro.insertOptionAt(v, row-1);
	    fireTableRowsUpdated(row-1, row);
	}
	
	public void moveRowDown(int row) {
	    OptionValue v = macro.getOptionAt(row);
	    macro.deleteOptionAt(row);
	    macro.insertOptionAt(v, row+1);
    	    fireTableRowsUpdated(row, row+1);
	}
	
	public void deleteRow(int row) {
	    macro.deleteOptionAt(row);
	    fireTableRowsDeleted(row, row);
	}
	
	public void setOptionAt(OptionValue v, int row) {
	    macro.setOptionAt(v, row);
	    fireTableDataChanged();
	}

    	public int findRowForOption(String opt) {
	    for (int i = 0; i < getRowCount(); ++i) {
	    	OptionValue v = macro.getOptionAt(i);
		if (opt.equals(v.getName())) {
		    return i;
		}
	    }
	    return -1;
	}
    }
    
    public static final int CREATE = 0;
    public static final int EDIT = 1;
    public static final int DUPLICATE = 2;
    
    private int mode = CREATE;
    private Macro originalMacro = null;
    private MacroNameField name;
    private JTextField optionName;
    private JTextField optionValue;
    private AutosizingTable macroTable;
    private MacroTableModel macroTableModel;
    private ButtonPanel buttonPanel;
    private JButton deleteButton, addButton, modifyButton, selectButton;
    private UpButton upButton;
    private DownButton downButton;
    private JCheckBox signalBox;
    private Vector listeners;
    private String savedOptionName = "";

    /*
     * Listener for the editing buttons which are used to manipulate the
     * table's contents
     */
    ActionListener listener = new ActionListener() {
	public void actionPerformed(ActionEvent e) {
	    int row = macroTable.getSelectedRow();
	    int lastRow = macroTable.getRowCount() - 1;
	    
	    Object src = e.getSource();
	    if (src == upButton) {
		if (row == 0)  {
		    return; // Can't move the first row up
		}
		macroTableModel.moveRowUp(row);
		/*
		 * Keep the row we moved selected so that repeated move up's
		 * affect the same data
		 */
		macroTable.clearSelection();
		macroTable.addRowSelectionInterval(row-1, row-1);
	    } else if (src == downButton) {
		if (row == lastRow) {
		    return; // Can't move the last row down
		}
		macroTableModel.moveRowDown(row);
		/*
		 * Keep the row we moved selected so that repeated move down's
		 * affect the same data
		 */
		macroTable.clearSelection();
		macroTable.addRowSelectionInterval(row+1, row+1);
	    } else if (src == deleteButton) {
		macroTableModel.deleteRow(row);
		/*
		 * Keep the same row selected so that repeated delete presses
		 * can be used to delete a series of options
		 */
		macroTable.clearSelection();
		if (row == lastRow) {
		    row = macroTableModel.getRowCount()-1;
		}
		if (macroTableModel.getRowCount() > 0) {
		    macroTable.addRowSelectionInterval(row, row);
		}
		if (macroTableModel.getRowCount() <= 0) {
		    modifyButton.setEnabled(false);
		}
	    } else if (src == selectButton) {
		// Show dialog that allows selection of options
		String s = SelectOptionDialog.showDialog(selectButton);

		/*
		 * User selected something, put it in the name field
		 * set the focus to the value field
		 */
		if (s != null) {
		    optionName.setText(s);
		    optionValue.requestFocus();
		}
	    } else if ((src == addButton) || (src == modifyButton)) {
		// Update the table from the field contents
		OptionValue v = null;
		v = OptionValueFactory.newOptionValue(optionName.getText());
		if (v instanceof BogusOptionValue) {
		    optionName.requestFocus();
		    // bad option name
		    MessageFormat form = null;
		    Object [] args = new Object[1];
		    args[0] = optionName.getText();
		    form = new MessageFormat(
		        ResourceStrings.getString("bad_option_name"));
		    JOptionPane.showMessageDialog(macroTable, form.format(args),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return;
		}
		try {
		    /*
		     * Catch an empty value field, which is only legal for
		     * a boolean option
		     */
		    String s = optionValue.getText();
		    if (s.length() == 0 && !(v instanceof BooleanOptionValue)) {
		    	throw new ValidationException();
		    }
		    v.setValue(s);
		} catch (ValidationException ex) {
		    // bad option value
		    optionValue.requestFocus();
		    MessageFormat form = null;
		    Object [] args = new Object[2];
		    form = new MessageFormat(
		        ResourceStrings.getString("bad_option_value"));
		    args[0] = optionValue.getText();
		    args[1] = optionName.getText();
		    JOptionPane.showMessageDialog(macroTable, form.format(args),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return;
		}
		/*
		 * Don't allow a second instance of any option other than
		 * Include in a macro, but only check if we're doing an add
		 * or if it's a modify and the name has changed.
		 */
		if ((!(v instanceof IncludeOptionValue)
		        && (src == addButton))
			|| ((src == modifyButton)
			&& !savedOptionName.equals(v.getName()))) {
		    if (macroTableModel.macro.getOption(v.getName()) != null) {
		    	optionName.requestFocus();
		    	MessageFormat form = new MessageFormat(
			    ResourceStrings.getString("macro_contains_option"));
			Object [] args = new Object[1];
			args[0] = v.getName();
			JOptionPane.showMessageDialog(macroTable,
			    form.format(args),
			    ResourceStrings.getString("input_error"),
			    JOptionPane.ERROR_MESSAGE);
			return;
		    }
		}
		// If adding, append it at the end
		if (src == addButton) {
		    row = macroTableModel.getRowCount();
		}
		macroTableModel.setOptionAt(v, row);
		macroTable.clearSelection();
		macroTable.addRowSelectionInterval(row, row);
		macroTable.scrollRectToVisible(
		    macroTable.getCellRect(row, 0, false));
	    }		
	}
    };
    
    public CreateMacroDialog(Frame f, int mode) {
	super(f);
	setLocationRelativeTo(f);

	listeners = new Vector();
	
	this.mode = mode;
	switch (mode) {
	case CREATE:
	    setTitle(ResourceStrings.getString("create_macro_title"));
	    break;
	case EDIT:
	    setTitle(ResourceStrings.getString("edit_macro_title"));
	    break;
	case DUPLICATE:
	    setTitle(ResourceStrings.getString("duplicate_macro_title"));
	    break;
	default:
	    break;
	}	
	
	getContentPane().setLayout(new BoxLayout(getContentPane(),
	    BoxLayout.Y_AXIS));
	JPanel mainPanel = new JPanel(new BorderLayout());
	mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	
	// Name cannot have blanks in it so use a control which disallows them
	name = new MacroNameField("", 30);
	JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

	Mnemonic mnName =
            new Mnemonic(ResourceStrings.getString("md_name_label"));
	JLabel nameLbl = new JLabel(mnName.getString());
        nameLbl.setLabelFor(name);
        nameLbl.setToolTipText(mnName.getString());
	nameLbl.setDisplayedMnemonic(mnName.getMnemonic());
	panel.add(nameLbl);

	panel.add(name);
	mainPanel.add(panel, BorderLayout.NORTH);
	
	JPanel contentsPanel = new JPanel();
	contentsPanel.setLayout(new BorderLayout());
	// Put a titled border on the contents panel
	Border b = BorderFactory.createCompoundBorder(
	    BorderFactory.createLineBorder(Color.black),
	    BorderFactory.createEmptyBorder(5, 10, 5, 10));
	contentsPanel.setBorder(BorderFactory.createTitledBorder(b,
	    ResourceStrings.getString("contents_label")));
	
	/*
	 * Create a panel using a couple of text fields to edit the options
	 * included in the macro
	 */
	JPanel fieldPanel = new JPanel(new FieldLayout());
	// Field for option name

	panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
	optionName = new JTextField("", 20);
        Mnemonic mnOptName =
            new Mnemonic(ResourceStrings.getString("md_option_name"));
        JLabel optNameLbl =
            new JLabel(mnOptName.getString());
	fieldPanel.add(FieldLayout.LABEL, optNameLbl);
        optNameLbl.setLabelFor(optionName);
        optNameLbl.setToolTipText(mnOptName.getString());
        optNameLbl.setDisplayedMnemonic(mnOptName.getMnemonic());

	panel.add(optionName);
	panel.add(Box.createHorizontalStrut(5));

	Mnemonic mnSelect = 
	    new Mnemonic(ResourceStrings.getString("select"));
	selectButton = new JButton(mnSelect.getString());
	selectButton.setToolTipText(mnSelect.getString());
	selectButton.setMnemonic(mnSelect.getMnemonic());

	selectButton.addActionListener(listener);
	panel.add(selectButton);
	fieldPanel.add(FieldLayout.FIELD, panel);

	// Field for option value

	optionValue = new JTextField();

        Mnemonic mnOptVal =
            new Mnemonic(ResourceStrings.getString("md_option_value"));
        JLabel optValLbl = new JLabel(mnOptVal.getString());
        fieldPanel.add(FieldLayout.LABEL, optValLbl);
        optValLbl.setLabelFor(optionValue);
        optValLbl.setToolTipText(mnOptVal.getString());
        optValLbl.setDisplayedMnemonic(mnOptVal.getMnemonic());

	fieldPanel.add(FieldLayout.FIELD, optionValue);

	// Buttons for add/modify

        Mnemonic mnAdd = 
            new Mnemonic(ResourceStrings.getString("add"));
        addButton = new JButton(mnAdd.getString());        
        addButton.setToolTipText(mnAdd.getString());
        addButton.setMnemonic(mnAdd.getMnemonic());

	addButton.addActionListener(listener);
	addButton.setEnabled(false);

  	Mnemonic mnModify =
	    new Mnemonic(ResourceStrings.getString("modify"));
	modifyButton = new JButton(mnModify.getString());
	modifyButton.setToolTipText(mnModify.getString()); 
	modifyButton.setMnemonic(mnModify.getMnemonic()); 

	modifyButton.addActionListener(listener);
	modifyButton.setEnabled(false);
	panel = new JPanel(new VerticalButtonLayout());
	panel.add(addButton);
	panel.add(modifyButton);
	
	JPanel editPanel = new JPanel(new BorderLayout());
	editPanel.add(fieldPanel, BorderLayout.WEST);
	editPanel.add(panel, BorderLayout.EAST);
	contentsPanel.add(editPanel, BorderLayout.NORTH);
	
	// Use a table to display the contents of the macro
	macroTableModel = new MacroTableModel();
	macroTable = new AutosizingTable(macroTableModel);
	macroTable.getTableHeader().setReorderingAllowed(false);
	macroTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	JScrollPane macroTablePane = new JScrollPane(macroTable);
	// Resize table as otherwise it asks for a huge area
	Dimension d = macroTable.getPreferredScrollableViewportSize();
	d.height = 100;
	d.width = 300;
	macroTable.setPreferredScrollableViewportSize(d);

	contentsPanel.add(macroTablePane, BorderLayout.CENTER);
	
	// Create buttons for controlling table
	JPanel editButtonPanel = new JPanel(new VerticalButtonLayout());
	
	upButton = new UpButton();
	upButton.setEnabled(false);
	upButton.addActionListener(listener);
	editButtonPanel.add(upButton);

	downButton = new DownButton();
	downButton.setEnabled(false);
	downButton.addActionListener(listener);
	editButtonPanel.add(downButton);

        Mnemonic mnDelete =
            new Mnemonic(ResourceStrings.getString("delete"));
        deleteButton = new JButton(mnDelete.getString());
        deleteButton.setToolTipText(mnDelete.getString());
        deleteButton.setMnemonic(mnDelete.getMnemonic());

	deleteButton.setEnabled(false);
	deleteButton.addActionListener(listener);
	editButtonPanel.add(deleteButton);
	contentsPanel.add(editButtonPanel, BorderLayout.EAST);
	
	mainPanel.add(contentsPanel, BorderLayout.CENTER);
		
	signalBox = new JCheckBox(ResourceStrings.getString("signal_server"),
	    true);
	signalBox.setToolTipText(
	    ResourceStrings.getString("signal_server"));
	signalBox.setHorizontalAlignment(SwingConstants.CENTER);
	mainPanel.add(signalBox, BorderLayout.SOUTH);
	
	getContentPane().add(mainPanel);
	getContentPane().add(new JSeparator());
	
	buttonPanel = new ButtonPanel(true);
	buttonPanel.addButtonPanelListener(this);
	getContentPane().add(buttonPanel);
	
	// Listen to table selection state and set state of buttons accordingly
	macroTable.getSelectionModel().addListSelectionListener(
		new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		int index = macroTable.getSelectedRow();
		if (index == -1) {
		    // Nothing selected, disable all
		    upButton.setEnabled(false);
		    downButton.setEnabled(false);
		    deleteButton.setEnabled(false);
		    // Clear the option name we saved
		    savedOptionName = "";
		} else {
		    if (macroTable.getRowCount() > 0) {
                        /*
                         * Only allow deleteButton to be activated when 
			 * the table is not empty regardless of selection
                         * method, mouse or keyboard
                         */
		        deleteButton.setEnabled(true);
		    }
		    if (index == 0) {
			// First row can't move up
			upButton.setEnabled(false);
		    } else {
			upButton.setEnabled(true);
		    }
		    if (index == (macroTable.getRowCount() - 1)) {
			// Last row can't move down
			downButton.setEnabled(false);
		    } else {
			if (macroTable.getRowCount() > 0) {
			    /* 
			     * Only allow downButton to be activated when the 
			     * table is not empty regardless of selection
			     * method, mouse or keyboard 
			     */
			    downButton.setEnabled(true);
			}	
		    }
		    // Save editing name so we can detect name change
		    savedOptionName =
		        (String)macroTableModel.getValueAt(index, 0);
		    optionName.setText(savedOptionName);
		    optionValue.setText(
			(String)macroTableModel.getValueAt(index, 1));
		}
	    }
	});
	
	// Only enable OK if the name is not empty
	name.getDocument().addDocumentListener(new DocumentListener() {
	    public void insertUpdate(DocumentEvent e) {
		buttonPanel.setOkEnabled(e.getDocument().getLength() != 0);
	    }
	    public void changedUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	    public void removeUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	});

	// Only enable add/modify when option name is non-empty
	optionName.getDocument().addDocumentListener(new DocumentListener() {
	    public void insertUpdate(DocumentEvent e) {
		boolean state = (optionName.getDocument().getLength() != 0);
		addButton.setEnabled(state);
		if (state == false) {
		    modifyButton.setEnabled(state);
		} else if (macroTable.getSelectedRowCount() > 0) {
		    modifyButton.setEnabled(state);
		}
	    }
	    public void changedUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	    public void removeUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	});
	
	if (mode == EDIT) {
	    buttonPanel.setOkEnabled(true);
	}
	setMacro(new Macro());
    }

    /**
     * Display this dialog, and auto-validate its contents to start with
     */
    public void setVisible(boolean visible) {
    	super.setVisible(visible);
	/*
	 * If we're being hidden, then just return
	 */
	if (!visible)
		return;
	/*
	 * Validate the current contents of the macro so we can tell the user
	 * about any syntax errors in the existing definition.
	 */
	try {
	    macroTableModel.macro.validate();
	} catch (ValidationException e) {
	    // Errors; advise user by putting up a dialog
	    MessageFormat form = new MessageFormat(
	        ResourceStrings.getString("bad_option_value"));
	    Object [] args = new Object[2];
	    OptionValue ov = macroTableModel.macro.getOption(e.getMessage());
	    if (ov == null) {
	        args[0] = "";
	    } else {
		args[0] = ov.getValue();
	    }
	    args[1] = e.getMessage();
	    JOptionPane.showMessageDialog(this, form.format(args),
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	    int row = macroTableModel.findRowForOption(e.getMessage());
	    if (row != -1) {
		macroTable.clearSelection();
		macroTable.addRowSelectionInterval(row, row);
		macroTable.scrollRectToVisible(
		    macroTable.getCellRect(row, 0, false));
	    }
	} 
    }
    
    public void setMacro(Macro m) {
	originalMacro = (Macro)m.clone(); // Keep a copy so we can do a reset
	if (mode != DUPLICATE) {
	    name.setText(m.getKey());
	}
	macroTableModel.setMacro(m);
    }
    
    public void buttonPressed(int buttonId) {
	switch (buttonId) {
	case OK:
	    // A macro with no options is not useful, so don't allow it
	    if (macroTableModel.getRowCount() == 0) {
		JOptionPane.showMessageDialog(this,
		    ResourceStrings.getString("empty_macro_error"),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    try {
		macroTableModel.macro.setKey(name.getText());
	    } catch (ValidationException e) {
	        // Not a valid macro name
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("bad_macro_name"));
		Object [] args = new Object[] { name.getText() };
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    try {
		// Validate the macro
		macroTableModel.macro.validate();
		DhcptabMgr server = DataManager.get().getDhcptabMgr();
	    	if ((mode == CREATE) || (mode == DUPLICATE)) {
	    	    server.createRecord(macroTableModel.macro,
		        signalBox.isSelected());
	    	} else if (mode == EDIT) {
	    	    server.modifyRecord(originalMacro, macroTableModel.macro,
		        signalBox.isSelected());
	    	}
		fireActionPerformed();
		setVisible(false);
		dispose();
	    } catch (ValidationException ve) {
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("bad_option_value"));
		Object [] args = new Object[2];
		OptionValue ov =
		    macroTableModel.macro.getOption(ve.getMessage());
		if (ov == null) {
		    args[0] = "";
		} else {
		    args[0] = ov.getValue();
		}
		args[1] = ve.getMessage();
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    } catch (NotRunningException e) {
		    // Server not running, put up a warning
		    JOptionPane.showMessageDialog(this,
		        ResourceStrings.getString("server_not_running"),
			ResourceStrings.getString("warning"),
			JOptionPane.WARNING_MESSAGE);
	            fireActionPerformed();
		    setVisible(false);
		    dispose();
	    } catch (Exception e) {
		MessageFormat form = null;
		Object [] args = new Object[2];
		switch (mode) {
		case CREATE:
		case DUPLICATE:
		    form = new MessageFormat(
			ResourceStrings.getString("create_macro_error"));
		    args[0] = macroTableModel.macro.getKey();
		    break;
		case EDIT:
		    form = new MessageFormat(
			ResourceStrings.getString("edit_macro_error"));
		    args[0] = originalMacro.getKey();
		    break;
		}
		args[1] = e.getMessage();
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
	    }
	    break;
	case CANCEL:
	    setVisible(false);
	    dispose();
	    break;
	case HELP:
	    String helpTag = null;
	    switch (mode) {
	    case CREATE:
		helpTag = "create_macro";
		break;
	    case DUPLICATE:
		helpTag = "duplicate_macro";
		break;
	    case EDIT:
		helpTag = "modify_macro";
		break;
	    }
	    DhcpmgrApplet.showHelp(helpTag);
	    break;
	case RESET:
	    setMacro(originalMacro);
	    signalBox.setSelected(true);
	    break;
	}
    }
    
    public void addActionListener(ActionListener l) {
	listeners.addElement(l);
    }
    
    public void removeActionListener(ActionListener l) {
	listeners.removeElement(l);
    }
    
    protected void fireActionPerformed() {
	String command = null;
	switch (mode) {
	case CREATE:
	    command = DialogActions.CREATE;
	case DUPLICATE:
	    command = DialogActions.DUPLICATE;
	    break;
	case EDIT:
	    command = DialogActions.EDIT;
	    break;
	}
	ActionEvent e = new ActionEvent(this, ActionEvent.ACTION_PERFORMED,
	    command);
	Enumeration en = listeners.elements();
	while (en.hasMoreElements()) {
	    ActionListener l = (ActionListener)en.nextElement();
	    l.actionPerformed(e);
	}
    }
}
