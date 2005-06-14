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
import java.text.MessageFormat;
import java.util.*;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.bridge.NotRunningException;


/**
 * Dialog to create/duplicate/edit an option.
 */
public class CreateOptionDialog extends JDialog implements ButtonPanelListener {
    public static final int CREATE = 0;
    public static final int EDIT = 1;
    public static final int DUPLICATE = 2;
    
    private int mode = CREATE;
    private OptionNameField name;
    private JComboBox category;
    private IntegerField code;
    private JComboBox type;
    private JList classList;
    private JTextField clientClass;
    private IntegerField granularity;
    private IntegerField maximum;
    private JCheckBox signalBox;
    private Vector listeners;
    private Option option, originalOption;
    private ButtonPanel buttonPanel;
    private ClassListModel classListModel;
    private JButton add, delete;
    private UpButton moveUp;
    private DownButton moveDown;
    private OptionContext [] categories = {
	Option.ctxts[Option.EXTEND],
	Option.ctxts[Option.VENDOR],
	Option.ctxts[Option.SITE]
    };
    
    // Model for the list of vendor classes
    class ClassListModel extends AbstractListModel {
    
	public ClassListModel() {
	    super();
	}
	
	public int getSize() {
	    return option.getVendorCount();
	}
	
	public Object getElementAt(int index) {
	    return option.getVendorAt(index);
	}

	public void addElement(String v) throws ValidationException {
	    option.addVendor(v);
	    fireIntervalAdded(this, option.getVendorCount()-1,
		option.getVendorCount()-1);
	}
	
	public void removeElementAt(int index) {
	    option.removeVendorAt(index);
	    fireIntervalRemoved(this, index, index);
	}
	
	public void moveUp(int index) {
	    String t = (String)option.getVendorAt(index-1);
	    option.setVendorAt(option.getVendorAt(index), index-1);
	    option.setVendorAt(t, index);
	    fireContentsChanged(this, index-1, index);
	}
	
	public void moveDown(int index) {
	    String t = (String)option.getVendorAt(index+1);
	    option.setVendorAt(option.getVendorAt(index), index+1);
	    option.setVendorAt(t, index);
	    fireContentsChanged(this, index, index+1);
	}
	
	public void reset() {
	    fireContentsChanged(this, 0, getSize());
	}
    }	

    public CreateOptionDialog(Frame f, int mode) {
	super(f);
	setLocationRelativeTo(f);
        JPanel classPanel;

	listeners = new Vector();
	
	this.mode = mode;
	switch (mode) {
	case CREATE:
	    setTitle(ResourceStrings.getString("create_option_title"));
	    break;
	case EDIT:
	    setTitle(ResourceStrings.getString("edit_option_title"));
	    break;
	case DUPLICATE:
	    setTitle(ResourceStrings.getString("duplicate_option_title"));
	    break;
	default:
	    break;
	}
	
	getContentPane().setLayout(new BoxLayout(getContentPane(),
	    BoxLayout.Y_AXIS));
	
	JPanel mainPanel = new JPanel(new BorderLayout());
	mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	
	JPanel fieldPanel = new JPanel();
	GridBagLayout bag = new GridBagLayout();
	fieldPanel.setLayout(bag);

	// Initialize constraints
	GridBagConstraints c = new GridBagConstraints();
	c.gridx = c.gridy = 0;
	c.gridwidth = c.gridheight = 1;
	c.fill = GridBagConstraints.HORIZONTAL;
	c.insets = new Insets(5, 5, 5, 5);
	c.weightx = c.weighty = 1.0;

	// Label and text field for name
        Mnemonic mnOname =
            new Mnemonic(ResourceStrings.getString("op_name"));
        JLabel l = new JLabel(mnOname.getString(), SwingConstants.RIGHT);

	bag.setConstraints(l, c);
	fieldPanel.add(l);
	name = new OptionNameField("");

        l.setLabelFor(name);
        l.setToolTipText(mnOname.getString());
        l.setDisplayedMnemonic(mnOname.getMnemonic());

	l.setLabelFor(name);
	++c.gridx;
	bag.setConstraints(name, c);
	fieldPanel.add(name);
	
	// Label and combo box for category
        Mnemonic mnCat =
            new Mnemonic(ResourceStrings.getString("category_label"));
        l = new JLabel(mnCat.getString(), SwingConstants.RIGHT);

	c.gridx = 0;
	++c.gridy;
	bag.setConstraints(l, c);
	fieldPanel.add(l);
	category = new JComboBox(categories);

        l.setLabelFor(category);
        l.setToolTipText(mnCat.getString());
        l.setDisplayedMnemonic(mnCat.getMnemonic());

	category.setEditable(false);
	++c.gridx;
	bag.setConstraints(category, c);
	fieldPanel.add(category);
	
	// Label and text field for code
        Mnemonic mnCode =
            new Mnemonic(ResourceStrings.getString("option_code_label"));
	l = new JLabel(mnCode.getString(), SwingConstants.RIGHT);

	c.gridx = 0;
	++c.gridy;
	bag.setConstraints(l, c);
	fieldPanel.add(l);
	code = new IntegerField();

        l.setLabelFor(code);
        l.setToolTipText(mnCode.getString());
        l.setDisplayedMnemonic(mnCode.getMnemonic());

	++c.gridx;
	bag.setConstraints(code, c);
	fieldPanel.add(code);
	
	// Label and combo box for data type
        Mnemonic mnType =
            new Mnemonic(ResourceStrings.getString("data_type_label"));
        l = new JLabel(mnType.getString(), SwingConstants.RIGHT);

	c.gridx = 0;
	++c.gridy;
	bag.setConstraints(l, c);
	fieldPanel.add(l);
	type = new JComboBox(Option.types);

        l.setLabelFor(type);
        l.setToolTipText(mnType.getString());
        l.setDisplayedMnemonic(mnType.getMnemonic());

	type.setEditable(false);
	++c.gridx;
	bag.setConstraints(type, c);
	fieldPanel.add(type);
	
	// Label and text field for granularity
        Mnemonic mnGran =
            new Mnemonic(ResourceStrings.getString("granularity_label"));
        l = new JLabel(mnGran.getString(), SwingConstants.RIGHT);

	c.gridx = 0;
	++c.gridy;
	bag.setConstraints(l, c);
	fieldPanel.add(l);
	granularity = new IntegerField(5);

        l.setLabelFor(granularity);
        l.setToolTipText(mnGran.getString());
        l.setDisplayedMnemonic(mnGran.getMnemonic());

	++c.gridx;
	bag.setConstraints(granularity, c);
	fieldPanel.add(granularity);
	
	// Label and text field for maximum
        Mnemonic mnMax =
            new Mnemonic(ResourceStrings.getString("maximum_label"));
        l = new JLabel(mnMax.getString(), SwingConstants.RIGHT);

	c.gridx = 0;
	++c.gridy;
	bag.setConstraints(l, c);
	fieldPanel.add(l);
	maximum = new IntegerField(5);

        l.setLabelFor(maximum);
        l.setToolTipText(mnMax.getString());
        l.setDisplayedMnemonic(mnMax.getMnemonic());

	++c.gridx;
	bag.setConstraints(maximum, c);
	fieldPanel.add(maximum);
	
	mainPanel.add(fieldPanel, BorderLayout.WEST);
	
	// Editing controls for client classes
	bag = new GridBagLayout();
	classPanel = new JPanel(bag);
	Border tb = BorderFactory.createTitledBorder(
	    BorderFactory.createLineBorder(Color.black),
	    ResourceStrings.getString("client_classes_label"));
	classPanel.setBorder(BorderFactory.createCompoundBorder(tb,
	    BorderFactory.createEmptyBorder(5, 5, 5, 5)));
	
	c = new GridBagConstraints();
	c.gridx = c.gridy = 0;
	c.weightx = c.weighty = 1.0;
	c.gridheight = 1;
	c.gridwidth = 1;
	
	// Field to type in new classes
	clientClass = new JTextField("", 20);
	c.fill = GridBagConstraints.HORIZONTAL;
	bag.setConstraints(clientClass, c);
	classPanel.add(clientClass);

	// Button for Add operation
	Mnemonic mnAdd = 
	    new Mnemonic(ResourceStrings.getString("add"));
	add = new JButton(mnAdd.getString());
	add.setToolTipText(mnAdd.getString());
	add.setMnemonic(mnAdd.getMnemonic());

	c.fill = GridBagConstraints.NONE;
	++c.gridx;
	c.weightx = 0.5;
	bag.setConstraints(add, c);
	classPanel.add(add);
	
	// List for classes
	classListModel = new ClassListModel();
	classList = new JList(classListModel);

	// Make sure it's approximately wide enough for our purposes, 20 chars
	classList.setPrototypeCellValue("abcdefghijklmnopqrst");
	classList.setSelectionMode(
	    ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
	JScrollPane scrollPane = new JScrollPane(classList);
	c.fill = GridBagConstraints.BOTH;
	c.gridx = 0;
	++c.gridy;
	c.weightx = 1.0;
	bag.setConstraints(scrollPane, c);
	classPanel.add(scrollPane);
	
	// Buttons to manipulate the list contents
	JPanel editButtonPanel = new JPanel(new VerticalButtonLayout());
	moveUp = new UpButton();
	editButtonPanel.add(moveUp);
	moveDown = new DownButton();
	editButtonPanel.add(moveDown);

        Mnemonic mnDelete = 
            new Mnemonic(ResourceStrings.getString("delete"));
        delete = new JButton(mnDelete.getString());
        delete.setToolTipText(mnDelete.getString());
        delete.setMnemonic(mnDelete.getMnemonic());

	editButtonPanel.add(delete);
	++c.gridx;
	c.weightx = 0.5;
	bag.setConstraints(editButtonPanel, c);
	classPanel.add(editButtonPanel);
	
	/*
	 * Disable all buttons to start; selection changes will adjust button
	 * state as necessary
	 */
	add.setEnabled(false);
	delete.setEnabled(false);
	moveUp.setEnabled(false);
	moveDown.setEnabled(false);
	
	// Create listener for button presses, take action as needed
	ActionListener al = new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		if (e.getSource() == add || e.getSource() == clientClass) {
		    try {
		        classListModel.addElement(clientClass.getText());
		    } catch (ValidationException ex) {
		        // Something wrong with class name
			MessageFormat form = new MessageFormat(
			    ResourceStrings.getString("invalid_client_class"));
			Object [] args = new Object[] { clientClass.getText() };
			JOptionPane.showMessageDialog(CreateOptionDialog.this,
			    form.format(args),
			    ResourceStrings.getString("input_error"),
			    JOptionPane.ERROR_MESSAGE);
			return;
		    }
		} else if (e.getSource() == delete) {
		    int [] indices = classList.getSelectedIndices();
		    if (indices.length > 1) {
			/*
			 * Need to sort them so that the delete's don't
			 * interfere with each other
			 */
			for (int i = 0; i < indices.length; ++i) {
			    for (int j = i; j < indices.length; ++j) {
				if (indices[i] > indices[j]) {
				    int k = indices[i];
				    indices[i] = indices[j];
				    indices[j] = k;
				}
			    }
			}
		    }
		    // Now delete from high index to low
		    for (int i = indices.length - 1; i >= 0; --i) {
			classListModel.removeElementAt(indices[i]);
		    }
		    if (indices.length > 1) {
			// Clear selection if multiple deleted
			classList.clearSelection();
			/*
			 * XXX We don't get a selection event for some reason,
			 * make it work for now
			 */
			delete.setEnabled(false);
		    } else {
			// Make sure to select something in the list
			if (classListModel.getSize() == 0) {
			    // List is empty, so disable delete
			    delete.setEnabled(false);
			} else if (indices[0] >= classListModel.getSize()) {
			    // Select last one if we're off the end
			    classList.setSelectedIndex(
				classListModel.getSize()-1);
			} else {
			    // Select next one in list
			    classList.setSelectedIndex(indices[0]);
			}
		    }
		} else if (e.getSource() == moveUp) {
		    int i = classList.getSelectedIndex();
		    classListModel.moveUp(i);
		    // Keep item selected so repeated moveUp's affect same item
		    classList.setSelectedIndex(i-1);
		} else if (e.getSource() == moveDown) {
		    int i = classList.getSelectedIndex();
		    classListModel.moveDown(i);
		    // Keep item selected so repeated moveDowns affect same item
		    classList.setSelectedIndex(i+1);
		}
	    }
	};
	clientClass.addActionListener(al);
	add.addActionListener(al);
	delete.addActionListener(al);
	moveUp.addActionListener(al);
	moveDown.addActionListener(al);
	
	// Put a selection listener on the list to enable buttons appropriately
	classList.addListSelectionListener(new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		int [] indices = classList.getSelectedIndices();
		switch (indices.length) {
		case 0:
		    // Nothing selected; disable them all
		    delete.setEnabled(false);
		    moveUp.setEnabled(false);
		    moveDown.setEnabled(false);
		    break;
		case 1:
		    delete.setEnabled(true);
		    // Can't move first one up
		    moveUp.setEnabled(indices[0] != 0);
		    // Can't move last one down
		    if (indices[0] == (classListModel.getSize() - 1)) {
			moveDown.setEnabled(false);
		    } else {
			moveDown.setEnabled(true);
		    }
		    break;
		default:
		    // More than one; only delete is allowed
		    delete.setEnabled(true);
		    moveUp.setEnabled(false);
		    moveDown.setEnabled(false);
		}
	    }
	});
	// Enable Add when class is not empty.
	clientClass.getDocument().addDocumentListener(new DocumentListener() {
	    public void insertUpdate(DocumentEvent e) {
		add.setEnabled(clientClass.getText().length() != 0);
	    }
	    public void changedUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	    public void removeUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	});

	mainPanel.add(classPanel, BorderLayout.CENTER);
	
	signalBox = new JCheckBox(ResourceStrings.getString("signal_server"),
	    true);
	signalBox.setToolTipText(
	    ResourceStrings.getString("signal_server"));
	signalBox.setHorizontalAlignment(SwingConstants.CENTER);
	JPanel signalPanel = new JPanel();
	signalPanel.add(signalBox);
	mainPanel.add(signalPanel, BorderLayout.SOUTH);
	
	getContentPane().add(mainPanel);
	getContentPane().add(new JSeparator());
	
	buttonPanel = new ButtonPanel(true);
	buttonPanel.addButtonPanelListener(this);
	getContentPane().add(buttonPanel);
	
	setOption(new Option());
	
	if (mode == EDIT) {
	    buttonPanel.setOkEnabled(true);
	}

	// Enable OK when there is data in the name field
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
	
	// If category != VENDOR you can't mess with the client class data
	category.addItemListener(new ItemListener() {
	    public void itemStateChanged(ItemEvent e) {
		OptionContext ctxt = categories[category.getSelectedIndex()];
		boolean isVendor =
		    (ctxt.getCode() == Option.ctxts[Option.VENDOR].getCode());
		if (!isVendor) {
		    option.clearVendors();
		    clientClass.setText("");
		}
		clientClass.setEnabled(isVendor);
		classList.setEnabled(isVendor);		
	    }
	});
	
	// Update state of granularity & maximum depending on data type selected
	type.addItemListener(new ItemListener() {
	    public void itemStateChanged(ItemEvent e) {
		OptionType stype = Option.types[type.getSelectedIndex()];
		byte code = stype.getCode();
		// Set granularity to correct minimum for type
		if (code == Option.types[Option.BOOLEAN].getCode()) {
		    granularity.setText("0");
		} else if ("0".equals(granularity.getText())) {
		    granularity.setText("1");
		}
		// Now set editability of the granularity and max fields
		if (code == Option.types[Option.ASCII].getCode() ||
		    code == Option.types[Option.OCTET].getCode()) {
		    granularity.setEditable(false);
		    maximum.setEditable(true);
		} else if (code == Option.types[Option.BOOLEAN].getCode()) {
		    granularity.setEditable(false);
		    // Also reset maximum value in this case
		    maximum.setText("0");
		    maximum.setEditable(false);
		} else if (code == Option.types[Option.NUMBER].getCode() ||
		    code == Option.types[Option.UNUMBER8].getCode() ||
		    code == Option.types[Option.UNUMBER16].getCode() ||
		    code == Option.types[Option.UNUMBER32].getCode() ||
		    code == Option.types[Option.UNUMBER64].getCode() ||
		    code == Option.types[Option.SNUMBER8].getCode() ||
		    code == Option.types[Option.SNUMBER16].getCode() ||
		    code == Option.types[Option.SNUMBER32].getCode() ||
		    code == Option.types[Option.SNUMBER64].getCode() ||
		    code == Option.types[Option.IP].getCode()) {
		    granularity.setEditable(true);
		    maximum.setEditable(true);
		}
	    }
	});
    }
    
    public void setOption(Option o) {
	originalOption = o; // Keep a copy so reset will work
	option = (Option)o.clone();
	resetValues();
    }
    
    private void resetValues() {
	if (mode == DUPLICATE) {
	    name.setText("");
	} else {
	    name.setText(option.getKey());
	}
	for (int i = 0; i < categories.length; i++) {
	    if (categories[i].getCode() == option.getContext()) {
		category.setSelectedIndex(i);
		break;
	    }
	}

	for (int i = 0; i < Option.types.length; i++) {
	    if (Option.types[i].getCode() == option.getType()) {
		type.setSelectedIndex(i);
		break;
	    }
	}

	code.setValue(option.getCode());
	granularity.setValue(option.getGranularity());
	maximum.setValue(option.getMaximum());
	classListModel.reset();
	signalBox.setSelected(true);
    }
    
    public void buttonPressed(int buttonId) {
	switch (buttonId) {
	case OK:
	    try {
		OptionContext sctxt = categories[category.getSelectedIndex()];
		OptionType stype = Option.types[type.getSelectedIndex()];
		option.setKey(name.getText());
		option.setContext(sctxt.getCode());
		option.setCode((short)code.getValue());
		option.setType(stype.getCode());
		option.setGranularity(granularity.getValue());
		option.setMaximum(maximum.getValue());
		if (sctxt.getCode() == Option.ctxts[Option.VENDOR].getCode() &&
			option.getVendorCount() == 0) {
		    JOptionPane.showMessageDialog(this,
		    	ResourceStrings.getString("empty_vendor_error"),
		    	ResourceStrings.getString("server_error_title"),
		    	JOptionPane.ERROR_MESSAGE);
		    return;
		}
		DhcptabMgr server = DataManager.get().getDhcptabMgr();
		if ((mode == CREATE) || (mode == DUPLICATE)) {
		    server.createRecord(option, signalBox.isSelected());
		} else if (mode == EDIT) {
		    server.modifyRecord(originalOption, option,
			signalBox.isSelected());
		}
		fireActionPerformed();
		setVisible(false);
		dispose();
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
			ResourceStrings.getString("create_option_error"));
		    args[0] = option.getKey();
		    break;
		case EDIT:
		    form = new MessageFormat(
			ResourceStrings.getString("edit_option_error"));
		    args[0] = originalOption.getKey();
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
		helpTag = "create_option";
		break;
	    case DUPLICATE:
		helpTag = "duplicate_option";
		break;
	    case EDIT:
		helpTag = "modify_option";
		break;
	    }
	    DhcpmgrApplet.showHelp(helpTag);
	    break;
	case RESET:
	    setOption(originalOption);
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
