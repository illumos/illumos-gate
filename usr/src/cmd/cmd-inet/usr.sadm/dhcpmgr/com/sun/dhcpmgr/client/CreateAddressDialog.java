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
 * Copyright 1998-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;
import java.text.*;
import java.util.*;
import java.net.*;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.bridge.ExistsException;
import com.sun.dhcpmgr.bridge.NoEntryException;
import com.sun.dhcpmgr.bridge.HostExistsException;
import com.sun.dhcpmgr.bridge.NoHostsEntryException;
import com.sun.dhcpmgr.bridge.NoTableException;
import com.sun.dhcpmgr.bridge.BridgeException;

/**
 * This dialog is used to create/duplicate/modify a DHCP address record.
 */
public class CreateAddressDialog extends JDialog
	implements ButtonPanelListener {

    // Model class for the drop-down list of macros user may select from
    class MacroListModel extends AbstractListModel implements ComboBoxModel {
	private Object currentValue;
	private Macro [] data = null;
	private String noMacro;

	public MacroListModel() {
	    try {
		noMacro = ResourceStrings.getString("no_macro_item");
		DhcptabMgr server = DataManager.get().getDhcptabMgr();
		data = server.getMacros();
	    } catch (NoTableException e) {
		// can function without table
	    } catch (Throwable e) {
		e.printStackTrace();
	    }
	}

	public int getSize() {
	    if (data == null)
		return 1;
	    else
		return data.length+1;
	}

	public Object getElementAt(int index) {
	    if (index == 0) {
		return noMacro;
	    } else {
		return data[index-1].getKey();
	    }
	}

	public void setSelectedItem(Object anItem) {
	    currentValue = anItem;
	    fireContentsChanged(this, -1, -1);
	}

	public Object getSelectedItem() {
	    return currentValue;
	}
    }

    public static final int CREATE = 0;
    public static final int EDIT = 1;
    public static final int DUPLICATE = 2;

    private int mode = EDIT;
    private Network network;
    private IPAddressField address;
    private JTextField server;
    private JComboBox macro;
    private JTextField clientId;
    private JTextField comment;
    private JTextField expirationDate;
    private JCheckBox unusable;
    private JCheckBox bootp;
    private JCheckBox manual;
    private JRadioButton temporary;
    private JRadioButton permanent;
    private ButtonGroup buttonGroup;
    private ButtonPanel buttonPanel;
    private DhcpClientRecord client, originalClient;
    private Vector listeners;
    private DateFormat dateFormat =
	DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);

    public CreateAddressDialog(Frame f, int mode, DhcpClientRecord rec,
	    Network net) {
	super(f);
	setLocationRelativeTo(f);

	listeners = new Vector();
	this.mode = mode;
	network = net;
	switch (mode) {
	case CREATE:
	    setTitle(ResourceStrings.getString("create_address_title"));
	    break;
	case EDIT:
	    setTitle(ResourceStrings.getString("edit_address_title"));
	    break;
	case DUPLICATE:
	    setTitle(ResourceStrings.getString("duplicate_address_title"));
	    break;
	default:
	    break;
	}

	getContentPane().setLayout(new BorderLayout());

	JTabbedPane tabbedPane = new JTabbedPane();

	GridBagLayout bag = new GridBagLayout();
	JPanel mainPanel = new JPanel(bag);
	GridBagConstraints c = new GridBagConstraints();
	c.gridx = c.gridy = 0;
	c.gridwidth = c.gridheight = 1;
	c.fill = GridBagConstraints.HORIZONTAL;
	c.insets = new Insets(5, 5, 5, 5);
	c.weightx = c.weighty = 1.0;

	// Label and text field for address
	Mnemonic mnIP =
            new Mnemonic(ResourceStrings.getString("ip_address_label"));
	JLabel l = new JLabel(mnIP.getString(), SwingConstants.RIGHT);
        bag.setConstraints(l, c);
        mainPanel.add(l);
        address = new IPAddressField();
        l.setLabelFor(address);
        l.setToolTipText(mnIP.getString());
	l.setDisplayedMnemonic(mnIP.getMnemonic());

	if (mode == EDIT) {
	    address.setEditable(false);
	}
	++c.gridx;
	bag.setConstraints(address, c);
	mainPanel.add(address);

	// label and field for owning server
	Mnemonic mnOwn =
            new Mnemonic(ResourceStrings.getString("owning_server_label"));
        l = new JLabel(mnOwn.getString(), SwingConstants.RIGHT);
        ++c.gridy;
        c.gridx = 0;
        bag.setConstraints(l, c);
        mainPanel.add(l);
        server = new JTextField(20);

        l.setLabelFor(server);
        l.setToolTipText(mnOwn.getString());
	l.setDisplayedMnemonic(mnOwn.getMnemonic());

	++c.gridx;
	bag.setConstraints(server, c);
	mainPanel.add(server);

	// label and combo box for macro
	Mnemonic mnMacro =
            new Mnemonic(ResourceStrings.getString("config_macro_label"));
        l = new JLabel(mnMacro.getString(), SwingConstants.RIGHT);
        ++c.gridy;
        c.gridx = 0;
        bag.setConstraints(l, c);
        mainPanel.add(l);
        MacroListModel macroListModel = new MacroListModel();
        macro = new JComboBox(macroListModel);

        l.setLabelFor(macro);
        l.setToolTipText(mnMacro.getString());
	l.setDisplayedMnemonic(mnMacro.getMnemonic());

	macro.setEditable(false);
	++c.gridx;
	bag.setConstraints(macro, c);
	mainPanel.add(macro);

	// Comment
	Mnemonic mnComm =
            new Mnemonic(ResourceStrings.getString("comment_label"));
        l = new JLabel(mnComm.getString(), SwingConstants.RIGHT);
        ++c.gridy;
        c.gridx = 0;
        bag.setConstraints(l, c);
        mainPanel.add(l);
        comment = new JTextField(20);

        l.setLabelFor(comment);
        l.setToolTipText(mnComm.getString());
	l.setDisplayedMnemonic(mnComm.getMnemonic());

	++c.gridx;
	bag.setConstraints(comment, c);
	mainPanel.add(comment);

	// Create first panel of tabs
	tabbedPane.addTab(ResourceStrings.getString("address_tab_label"),
	    mainPanel);

	mainPanel = new JPanel(new BorderLayout(5, 5));

	// Client ID
	Mnemonic mnID =
            new Mnemonic(ResourceStrings.getString("client_id_label"));
        JPanel idPanel = new JPanel();
        l = new JLabel(mnID.getString());
        idPanel.add(l);
        clientId = new JTextField(20);

        l.setLabelFor(clientId);
        l.setToolTipText(mnID.getString());
	l.setDisplayedMnemonic(mnID.getMnemonic());
	idPanel.add(clientId);

	manual = new JCheckBox(ResourceStrings.getString("manual_checkbox"));
	idPanel.add(manual);
	manual.setToolTipText(
	    ResourceStrings.getString("manual_checkbox"));

	mainPanel.add(idPanel, BorderLayout.NORTH);

	// radio buttons for lease state
	bag = new GridBagLayout();
	JPanel leasePanel = new JPanel(bag);
	/*
	 * Create a compound border with empty space on the outside and line
	 * border on the inside, then title it.
	 */
	Border b = BorderFactory.createCompoundBorder(
	    BorderFactory.createEmptyBorder(0, 5, 0, 5),
	    BorderFactory.createLineBorder(Color.black));
	leasePanel.setBorder(BorderFactory.createTitledBorder(b,
	    ResourceStrings.getString("lease_policy_label")));

	// Reset constraints
	c.gridx = c.gridy = 0;
	c.gridwidth = 1;

	buttonGroup = new ButtonGroup();
	temporary = new JRadioButton();
	buttonGroup.add(temporary);
	c.weightx = 0.0;
	bag.setConstraints(temporary, c);
	leasePanel.add(temporary);

	Mnemonic mnDyn =
            new Mnemonic(ResourceStrings.getString("leased_label"));
	l = new JLabel(mnDyn.getString());
	++c.gridx;
	c.weightx = 1.0;
	bag.setConstraints(l, c);
	leasePanel.add(l);

	expirationDate = new JTextField(30);

        l.setLabelFor(expirationDate);
	l.setToolTipText(mnDyn.getString());
	l.setDisplayedMnemonic(mnDyn.getMnemonic());

	++c.gridy;
	bag.setConstraints(expirationDate, c);
	leasePanel.add(expirationDate);

	permanent = new JRadioButton();
	buttonGroup.add(permanent);
	++c.gridy;
	c.gridx = 0;
	c.weightx = 0.0;
	bag.setConstraints(permanent, c);
	leasePanel.add(permanent);

	Mnemonic mnPerm =
            new Mnemonic(ResourceStrings.getString("permanent_label"));
	l = new JLabel(mnPerm.getString());
        l.setLabelFor(leasePanel);
        l.setToolTipText(mnPerm.getString());
	l.setDisplayedMnemonic(mnPerm.getMnemonic());

	++c.gridx;
	c.weightx = 1.0;
	bag.setConstraints(l, c);
	leasePanel.add(l);

	mainPanel.add(leasePanel, BorderLayout.CENTER);

	// Flag checkboxes
	JPanel southPanel = new JPanel(new BorderLayout(5, 5));
	southPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));
	bootp = new JCheckBox(ResourceStrings.getString("bootp_checkbox"));

	bootp.setToolTipText(
	    ResourceStrings.getString("bootp_checkbox"));

	bootp.setHorizontalAlignment(SwingConstants.LEFT);
	southPanel.add(bootp, BorderLayout.CENTER);

	unusable = new JCheckBox(
	    ResourceStrings.getString("unusable_checkbox"));

        unusable.setToolTipText(
            ResourceStrings.getString("unusable_checkbox"));

	unusable.setHorizontalAlignment(SwingConstants.LEFT);
	southPanel.add(unusable, BorderLayout.SOUTH);

	mainPanel.add(southPanel, BorderLayout.SOUTH);

	tabbedPane.addTab(ResourceStrings.getString("lease_tab_label"),
	    mainPanel);
	JPanel borderPanel = new JPanel(new BorderLayout());
	borderPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
	borderPanel.add(tabbedPane, BorderLayout.CENTER);

	getContentPane().add(borderPanel, BorderLayout.CENTER);

	buttonPanel = new ButtonPanel(true);
	buttonPanel.addButtonPanelListener(this);
	getContentPane().add(buttonPanel, BorderLayout.SOUTH);

	setClient(rec);

	DocumentListener docListener = new DocumentListener() {
	    public void insertUpdate(DocumentEvent e) {
		buttonPanel.setOkEnabled(address.getDocument().getLength() != 0
		    && server.getDocument().getLength() != 0);
	    }
	    public void changedUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	    public void removeUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	};

	address.getDocument().addDocumentListener(docListener);
	server.getDocument().addDocumentListener(docListener);

	if (mode == EDIT) {
	    buttonPanel.setOkEnabled(true);
	}
    }

    public void setClient(DhcpClientRecord c) {
	originalClient = (DhcpClientRecord)c.clone();
	client = c;
	resetValues();
    }

    private void resetValues() {
	if (mode == DUPLICATE) {
	    address.setText("");
	} else {
	    address.setText(client.getClientIPAddress());
	}
	if (mode == CREATE && (client.getServerName() == null ||
		client.getServerName().length() == 0)) {
	    server.setText(DataManager.get().getShortServerName());
	} else {
	    server.setText(client.getServerName());
	}
	if (mode == CREATE) {
	    macro.setSelectedItem(DataManager.get().getShortServerName());
	} else {
	    macro.setSelectedItem(client.getMacro());
	}
	comment.setText(client.getComment());
	clientId.setText(client.getClientId());
	manual.setSelected(client.isManual());
	if (client.isPermanent()) {
	    permanent.setSelected(true);
	} else {
	    temporary.setSelected(true);
	}
	bootp.setSelected(client.isBootp());
	unusable.setSelected(client.isUnusable());
	Date d = client.getExpiration();
	if (d == null || d.getTime() == 0) {
	    expirationDate.setText("");
	} else {
	    expirationDate.setText(dateFormat.format(d));
	}
    }

    public void buttonPressed(int buttonId) {
	switch (buttonId) {
	case OK:
	    IPAddress addr = address.getValue();
	    if (addr == null) {
		// Bad IP address
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_address"));
		Object [] args = new Object[] { address.getText() };
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    if (!network.containsAddress(addr)) {
		// Address is not on the network we're editing
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("bad_network_address"));
		Object [] args = new Object[] {
		    addr.getHostAddress(),
		    network.getAddress()
		};
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    try {
		client.setClientIP(address.getValue());
	    } catch (ValidationException e) {
		// This shouldn't happen, should have caught any problem already
	    }

	    try {
		if (!server.getText().equals(client.getServerName())) {
		    // Don't bother resetting if it hasn't changed
		    client.setServerIP(new IPAddress(server.getText()));
		}
	    } catch (ValidationException e) {
		// Bad server name
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_server"));
		Object [] args = new Object[] { server.getText() };
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    int i = macro.getSelectedIndex();
	    if (i == 0) {
		client.setMacro("");
	    } else {
		client.setMacro((String)macro.getItemAt(i));
	    }
	    client.setComment(comment.getText());
	    try {
		client.setClientId(clientId.getText());
	    } catch (ValidationException e) {
		// Bad client ID
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_client_id"));
		Object [] args = new Object[] { clientId.getText() };
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    client.setManual(manual.isSelected());
	    client.setPermanent(permanent.isSelected());
	    client.setBootp(bootp.isSelected());
	    client.setUnusable(unusable.isSelected());
	    try {
		if (expirationDate.getText().length() == 0) {
		    client.setExpiration(new Date(0));
		} else {
		    Date d = dateFormat.parse(expirationDate.getText());
		    client.setExpiration(d);
		}
	    } catch (ParseException e) {
		// Bad date/time entered
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("invalid_date"));
		Object [] args = new Object[] {
		    expirationDate.getText(),
		    dateFormat.format(new Date())
		};
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	    // Got all the data, now update the data store
	    try {
		DhcpNetMgr server = DataManager.get().getDhcpNetMgr();
		if (mode == EDIT) {
		    server.modifyClient(originalClient, client,
			network.toString());
		} else {
		    server.addClient(client, network.toString());
		}
		fireActionPerformed();
		setVisible(false);
		dispose();
	    } catch (Exception e) {
		/*
		 * Display an error message dialog.  However, if the error
		 * related to editing the hosts table, we merely consider it
		 * a warning as the network table stuff actually was done.
		 */
		String msg = e.getMessage();
		int msgType = JOptionPane.ERROR_MESSAGE;
		if (e instanceof ExistsException) {
		    msg = ResourceStrings.getString("address_exists");
		} else if (e instanceof NoEntryException) {
		    msg = ResourceStrings.getString("address_missing");
		} else if (e instanceof HostExistsException) {
		    msg = ResourceStrings.getString("host_exists");
		    msgType = JOptionPane.ERROR_MESSAGE;
		} else if (e instanceof NoHostsEntryException) {
		    msg = ResourceStrings.getString("host_missing");
		    msgType = JOptionPane.WARNING_MESSAGE;
		}
		JOptionPane.showMessageDialog(this, msg,
		    ResourceStrings.getString("server_error_title"), msgType);
		if (msgType == JOptionPane.WARNING_MESSAGE) {
		    fireActionPerformed();
		    setVisible(false);
		    dispose();
		}
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
		helpTag = "create_address";
		break;
	    case DUPLICATE:
		helpTag = "duplicate_address";
		break;
	    case EDIT:
		helpTag = "modify_address";
		break;
	    }
	    DhcpmgrApplet.showHelp(helpTag);
	    break;
	case RESET:
	    setClient(originalClient);
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
	    break;
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
