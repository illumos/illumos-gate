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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.NoEntryException;
import com.sun.dhcpmgr.bridge.ExistsException;
import com.sun.dhcpmgr.bridge.HostExistsException;
import com.sun.dhcpmgr.bridge.NoTableException;
import com.sun.dhcpmgr.server.DhcpNetMgr;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.border.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.MessageFormat;
import java.net.*;

/**
 * A wizard to configure a group of addresses.
 */
public class AddressWizard extends Wizard {
    private Network network;
    private int number = 10;
    private String comment = "";
    private String server = DataManager.get().getShortServerName();
    private IPAddress serverIP;
    private IPAddress startAddress;
    private String macro = DataManager.get().getShortServerName();
    private boolean unusable = false;
    private boolean dynamic = true;
    private WizardTableModel addressTableModel;
    private Macro noMacro;

    class Address {
	IPAddress addr;
	String name;

	public Address() {
	    addr = null;
	    name = "";
	}

	public Address(int a, String n) {
	    name = n;
	    setAddr(a);
	}

	public Address(String a, String n) {
	    name = n;
	    setAddr(a);
	}

	public void setAddr(int a) {
	    addr = new IPAddress(a);
	}

	public void setAddr(String a) {
	    try {
		addr = new IPAddress(a);
	    } catch (ValidationException e) {
		// Do nothing
	    }
	}

	public String toString() {
	    return addr.getHostAddress();
	}
    }

    class WizardTableModel extends AbstractTableModel {
	private Vector addrs = new Vector();

	public int getRowCount() {
	    return addrs.size();
	}

	public int getColumnCount() {
	    return 2;
	}

	public Object getValueAt(int row, int column) {
	    if (column == 0) {
		return ((Address)addrs.elementAt(row)).addr;
	    } else {
		return ((Address)addrs.elementAt(row)).name;
	    }
	}

	public Class getColumnClass(int column) {
	    if (column == 0) {
		return IPAddress.class;
	    } else {
		return String.class;
	    }
	}

	public String getColumnName(int column) {
	    if (column == 0) {
		return ResourceStrings.getString("address_column");
	    } else {
		return ResourceStrings.getString("client_name_column");
	    }
	}

	public long generateAddresses() {
	    if (!network.containsAddress(startAddress)) {
		return 0;
	    }

	    int net = network.getAddress().intValue();
	    int mask = network.getMask().intValue();
	    int start = startAddress.intValue();

	    addrs.removeAllElements();
	    long max = (long)(net + ~mask) & 0xffffffffL;
	    int count = 0;
	    int index = start - net;
	    if (index == 0) {
		// Don't try allocating the network address as a client address
		++index;
	    }
	    DhcpClientRecord [] clients = null;
	    try {
		/*
		 * Sort the data so we can generate the list of addresses
		 * with a minimal number of comparisons here.  First, though,
		 * clone the array so that sorting won't affect the original
		 * data set and throw off the main display.
		 */
		clients = (DhcpClientRecord [])DataManager.get().getClients(
		    network.getAddress().toString(), false).clone();
		Arrays.sort(clients);
	    } catch (Throwable e) {
		// XXX What to do here???
		e.printStackTrace();
	    }
	    int base = 0;
	    long searchAddress = 0;
	    while (count < number) {
		long address = (long)(net + index) & 0xffffffffL;
		if (address == max) {
		    // We finished searching before satisfying the request
		    break;
		}
		/*
		 * If clients == null then this is an empty network,
		 * so searching for holes is unnecessary
		 */
		if (clients != null) {
		    // Advance search pointer past lower-numbered addresses
		    while ((base < clients.length)
			    && ((searchAddress =
			    clients[base].getBinaryAddress()) < address)) {
			++base;
		    }
		}
		if (searchAddress != address) {
		    // found an empty slot; create the address
		    addrs.addElement(new Address((int)address, ""));
		    ++count;
		}
		++index;
	    }

	    // Inform UI that the data is ready.
	    fireTableDataChanged();
	    return count;
	}

	public Address getAddressAt(int index) {
	    return (Address)addrs.elementAt(index);
	}
    }

    // This step selects the number of addresses and a comment
    class NumberStep implements WizardStep {
	private Box stepBox;
	private IntegerField addressCount;
	private JTextField commentField;

	public NumberStep() {
	    stepBox = Box.createVerticalBox();

	    // Explanatory text at the top
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_explain"), 4, 45));
	    stepBox.add(Box.createVerticalStrut(10));
	    stepBox.add(Box.createVerticalGlue());

	    // Get the number of addresses to create
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_count_explain"), 1, 45));

	    Mnemonic mnCount =
                new Mnemonic(ResourceStrings.getString("add_wiz_count_label"));
	    JLabel label = new JLabel(mnCount.getString());
            addressCount = new IntegerField(); // Ensure numeric input
            addressCount.setMaximumSize(addressCount.getPreferredSize());

            label.setLabelFor(addressCount);
            label.setToolTipText(mnCount.getString());
            label.setDisplayedMnemonic(mnCount.getMnemonic());

	    Box box = Box.createHorizontalBox();
	    box.add(Box.createHorizontalStrut(10));
	    box.add(label);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(addressCount);
	    box.add(Box.createHorizontalGlue());
	    stepBox.add(box);

	    stepBox.add(Box.createVerticalStrut(10));
	    stepBox.add(Box.createVerticalGlue());
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_comment_explain"), 2, 45));

	    // Let user supply a comment
	    Mnemonic mnComm =
                new Mnemonic(ResourceStrings.getString(
		    "add_wiz_comment_label"));
	    label = new JLabel(mnComm.getString());
	    commentField = new JTextField("", 20);

	    label.setLabelFor(commentField);
	    label.setToolTipText(mnComm.getString());
	    label.setDisplayedMnemonic(mnComm.getMnemonic());

	    commentField.setMaximumSize(commentField.getPreferredSize());
	    box = Box.createHorizontalBox();
	    box.add(Box.createHorizontalStrut(10));
	    box.add(label);
	    box.add(Box.createHorizontalStrut(5));
	    box.add(commentField);
	    stepBox.add(box);
	    stepBox.add(Box.createVerticalGlue());

	    /*
	     * This listener ensures that the forward button is enabled only
	     * when there is a count of addresses in the addressCount field.
	     */
	    addressCount.getDocument().addDocumentListener(
		    new DocumentListener() {
		public void insertUpdate(DocumentEvent e) {
		    setForwardEnabled(e.getDocument().getLength() != 0);
		}
		public void changedUpdate(DocumentEvent e) {
		    insertUpdate(e);
		}
		public void removeUpdate(DocumentEvent e) {
		    insertUpdate(e);
		}
	    });
	}

	public String getDescription() {
	    return ResourceStrings.getString("add_wiz_number_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    addressCount.setValue(number);
	    commentField.setText(comment);
	    setForwardEnabled(addressCount.getValue() != 0);
	}

	public boolean setInactive(int direction) {
	    number = addressCount.getValue();
	    if (number == 0) {
		/*
		 *  Going forward with 0 addresses makes no sense,
		 * display error and veto the move.
		 */
		JOptionPane.showMessageDialog(AddressWizard.this,
		    ResourceStrings.getString("add_wiz_count_error"),
		    ResourceStrings.getString("error_message"),
		    JOptionPane.ERROR_MESSAGE);
		return false;
	    }
	    comment = commentField.getText();
	    return true;
	}
    }

    // This step selects the server and starting address
    class ServerStep implements WizardStep {
	private Box stepBox;
	private IPAddressField startField;
	private HostnameField serverField;

	public ServerStep() {
	    stepBox = Box.createVerticalBox();

	    // Explanatory text at the top
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_server_explain"), 1, 45));

	    // Server to own these addresses
	    Mnemonic mnMan =
                new Mnemonic(ResourceStrings.getString("add_wiz_server_label"));
            JLabel jl = new JLabel(mnMan.getString());
            Box box = Box.createHorizontalBox();
            box.add(jl);
            box.add(Box.createHorizontalStrut(5));
            serverField = new HostnameField("", 15);
            jl.setLabelFor(serverField);
            jl.setToolTipText(mnMan.getString());
	    jl.setDisplayedMnemonic(mnMan.getMnemonic());

	    serverField.setMaximumSize(serverField.getPreferredSize());
	    box.add(serverField);
	    box.add(Box.createHorizontalGlue());
	    stepBox.add(box);

	    // Add some spacing
	    stepBox.add(Box.createVerticalStrut(5));
	    stepBox.add(Box.createVerticalGlue());

	    // Starting address
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_start_explain"), 2, 45));
	    box = Box.createHorizontalBox();

	    Mnemonic mnStart =
                new Mnemonic(ResourceStrings.getString("add_wiz_start_label"));
	    JLabel startLbl = new JLabel(mnStart.getString());
            box.add(startLbl);
            box.add(Box.createHorizontalStrut(5));
            startField = new IPAddressField();  // Ensure it's an IP address
            startLbl.setLabelFor(startField);
            startLbl.setToolTipText(mnStart.getString());
	    startLbl.setDisplayedMnemonic(mnStart.getMnemonic());

	    startField.setMaximumSize(startField.getPreferredSize());
	    box.add(startField);
	    stepBox.add(box);

	    DocumentListener docListener = new DocumentListener() {
		public void insertUpdate(DocumentEvent e) {
		    setForwardEnabled((startField.getText().length() != 0)
			&& (serverField.getText().length() != 0));
		}
		public void changedUpdate(DocumentEvent e) {
		    insertUpdate(e);
		}
		public void removeUpdate(DocumentEvent e) {
		    insertUpdate(e);
		}
	    };

	    startField.getDocument().addDocumentListener(docListener);
	    serverField.getDocument().addDocumentListener(docListener);
	}

	public String getDescription() {
	    return ResourceStrings.getString("add_wiz_server_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    serverField.setText(server);
	    startField.setValue(startAddress);
	    setForwardEnabled(true);
	}

	public boolean setInactive(int direction) {
	    if (direction == FORWARD) {
		// Validate that address is on the network we're working on
		IPAddress a = startField.getValue();
		if (a == null) {
		    // Not a valid address at all
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("add_wiz_invalid_address"));
		    Object [] args = new Object[1];
		    args[0] = startField.getText();
		    JOptionPane.showMessageDialog(AddressWizard.this,
			form.format(args),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		} else if (!network.containsAddress(a)) {
		    // Address is not on network
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("bad_network_address"));
		    Object [] args = new Object[2];
		    args[0] = startField.getText();
		    args[1] = network.getAddress();
		    JOptionPane.showMessageDialog(AddressWizard.this,
			form.format(args),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		}
		try {
		    serverIP = new IPAddress(serverField.getText());
		} catch (Throwable e) {
		    /*
		     * Unknown hostname, probably, so put up the message and
		     * decline to continue
		     */
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("bad_server_name"));
		    Object [] args = new Object[1];
		    args[0] = serverField.getText();
		    JOptionPane.showMessageDialog(AddressWizard.this,
			form.format(args),
			ResourceStrings.getString("error_message"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		}
	    }
	    server = serverField.getText();
	    startAddress = startField.getValue();
	    return true;
	}
    }

    // This step confirms the list of addresses to be generated
    class ConfirmStep implements WizardStep {
	private JPanel stepPanel;
	private JTable addressTable;

	public ConfirmStep() {
	    stepPanel = new JPanel(new BorderLayout(10, 10));

	    // Explanatory text at the top
	    stepPanel.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_confirm_explain"), 3, 45),
		BorderLayout.NORTH);

	    // Label the table
	    JPanel panel = new JPanel(new BorderLayout());
            panel.setBorder(BorderFactory.createEmptyBorder(0, 15, 0, 15));
	    Mnemonic mnIP =
		new Mnemonic(ResourceStrings.getString(
		    "add_wiz_confirm_label"));
            JLabel label = new JLabel(mnIP.getString());
            panel.add(label, BorderLayout.NORTH);

            // Display the addresses in a table
            addressTable = new JTable(addressTableModel);

            label.setLabelFor(addressTable);
            label.setToolTipText(mnIP.getString());
	    label.setDisplayedMnemonic(mnIP.getMnemonic());

	    addressTable.setDefaultRenderer(IPAddress.class,
		new ExtendedCellRenderer());

	    // Table is not selectable in any way
	    addressTable.setRowSelectionAllowed(false);
	    addressTable.setColumnSelectionAllowed(false);
	    addressTable.setCellSelectionEnabled(false);

	    // Wrap in a scroll pane so column headings display
	    JScrollPane scrollPane = new JScrollPane(addressTable);
	    panel.add(scrollPane, BorderLayout.CENTER);
	    stepPanel.add(panel, BorderLayout.CENTER);
	}

	public String getDescription() {
	    return ResourceStrings.getString("add_wiz_confirm_desc");
	}

	public Component getComponent() {
	    return stepPanel;
	}

	public void setActive(int direction) {
	    /*
	     * If we're activating coming from the previous step,
	     * generate the address list
	     */
	    if (direction == FORWARD) {
		long count = addressTableModel.generateAddresses();
		// Error if no addresses could be generated
		if (count == 0) {
		    JOptionPane.showMessageDialog(AddressWizard.this,
			ResourceStrings.getString("add_wiz_none_available"),
			ResourceStrings.getString("error_message"),
			JOptionPane.ERROR_MESSAGE);
		    setForwardEnabled(false);
		} else {
		    if (count != number) {
			/*
			 * Warn if we couldn't generate the number of addresses
			 * requested
			 */
			MessageFormat form = new MessageFormat(
			    ResourceStrings.getString(
			    "generate_addresses_warning"));
			Object [] args = new Object[2];
			args[0] = new Long(count);
			args[1] = new Long(number);
			JOptionPane.showMessageDialog(AddressWizard.this,
			    form.format(args),
			    ResourceStrings.getString("warning"),
			    JOptionPane.WARNING_MESSAGE);
		    }
		    setForwardEnabled(true);
		}
	    } else {
		setForwardEnabled(true);
	    }
	}

	public boolean setInactive(int direction) {
	    return true; // Nothing to do when leaving
	}
    }

    // This step selects the macro and flags
    class ConfigureStep implements WizardStep {

	// Model class for the macro list
	class MacroListModel extends AbstractListModel
		implements ComboBoxModel {
	    private Object currentValue;
	    private Macro data[] = null;

	    public int getSize() {
		if (data == null) {
		    try {
			// If we don't have data yet, grab currently cached list
			data = DataManager.get().getMacros(false);
		    } catch (NoTableException e) {
			// can function without table
		    } catch (Throwable e) {
			e.printStackTrace();
		    }
		}

		if (data == null || data.length == 0) {
		    return 1;
		} else {
		    return data.length+1;
		}
	    }

	    public Object getElementAt(int index) {
		if (data == null) {
		    try {
			// If we don't have data yet, grab currently cached list
			data = DataManager.get().getMacros(false);
		    } catch (NoTableException e) {
			// can function without table
		    } catch (Throwable e) {
			e.printStackTrace();
		    }
		}
		if (index == 0) {
		    return noMacro.getKey();
		} else {
		    return data[index-1].getKey();
		}
	    }

	    public void setSelectedItem(Object anItem) {
		currentValue = noMacro.getKey();
		for (int i = 0; data != null && i < data.length; i++) {
		    if (((String)(anItem)).equals(((Macro)data[i]).getKey())) {
			currentValue = anItem;
		    }
		}
		fireContentsChanged(this, -1, -1);
	    }

	    public Object getSelectedItem() {
		return currentValue;
	    }

	    public Macro getMacroAt(int index) {
		if (index == 0) {
		    return noMacro;
		} else {
		    return data[index-1];
		}
	    }
	}

	private Box stepBox;
	private JComboBox macroBox;
	private MacroListModel macroBoxModel;
	private JButton viewButton;
	private JCheckBox unusableBox;

	public ConfigureStep() {
	    stepBox = Box.createVerticalBox();

	    // Start with some explanatory text
	    JComponent component = Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_macro_explain"), 3, 45);
	    component.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(component);
	    // Add some spacing
	    stepBox.add(Box.createVerticalStrut(10));

	    // Let 'em select the macro to use
	    Mnemonic mnConf =
                new Mnemonic(ResourceStrings.getString("add_wiz_macro_label"));
	    JLabel label = new JLabel(mnConf.getString());
	    label.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(label);
	    JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
	    macroBoxModel = new MacroListModel();
	    macroBox = new JComboBox(macroBoxModel);

	    label.setLabelFor(macroBox);
	    label.setToolTipText(mnConf.getString());
	    label.setDisplayedMnemonic(mnConf.getMnemonic());

	    panel.add(macroBox);
	    // Button to view the contents of the selected macro

	    Mnemonic mnView =
		new Mnemonic(ResourceStrings.getString("add_wiz_view_button"));
	    viewButton = new JButton(mnView.getString());
	    viewButton.setToolTipText(mnView.getString());
	    viewButton.setMnemonic(mnView.getMnemonic());

	    panel.add(viewButton);
	    panel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(panel);

	    // Give the option to mark them unusable for now
	    component = Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_flag_explain"), 2, 45);
	    component.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(component);
	    unusableBox = new JCheckBox(
		ResourceStrings.getString("add_wiz_unusable_label"));
	    unusableBox.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(unusableBox);
	    stepBox.add(Box.createVerticalGlue());

	    // When user presses View, show the macro's contents
	    viewButton.addActionListener(new ActionListener() {
		public void actionPerformed(ActionEvent e) {
		    /*
		     * viewButton is passed as component relative to which the
		     * dialog should be displayed, keeping user more in
		     * context with the task.
		     */
		    ViewMacroDialog d = new ViewMacroDialog(
			AddressWizard.this, viewButton,
			macroBoxModel.getMacroAt(macroBox.getSelectedIndex()));
		    d.pack();
		    d.setVisible(true);
		}
	    });
	}

	public String getDescription() {
	    return ResourceStrings.getString("add_wiz_configure_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    macroBox.setSelectedItem(macro);
	    unusableBox.setSelected(unusable);
	    setForwardEnabled(true);
	}

	public boolean setInactive(int direction) {
	    macro = (String)macroBox.getSelectedItem();
	    unusable = unusableBox.isSelected();
	    return true;
	}
    }

    // This step selects the lease type
    class LeaseStep implements WizardStep {
	private Box stepBox;
	private JRadioButton dynamicButton, permanentButton;
	private ButtonGroup buttonGroup;

	public LeaseStep() {
	    stepBox = Box.createVerticalBox();

	    // Start with explanatory text
	    JComponent component = Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_lease_explain"), 0, 45);
	    component.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(component);
	    stepBox.add(Box.createVerticalStrut(10));

	    // User has choice of dynamic or permanent leases
	    Mnemonic mnLease =
                new Mnemonic(ResourceStrings.getString("add_wiz_lease_label"));
	    JLabel label = new JLabel(mnLease.getString());
            JPanel panel = new JPanel(new FieldLayout(10, 0));
            label.setToolTipText(mnLease.getString());
	    label.setDisplayedMnemonic(mnLease.getMnemonic());

	    panel.add(FieldLayout.LABEL, label);
	    buttonGroup = new ButtonGroup();
	    dynamicButton = new JRadioButton(
		ResourceStrings.getString("dynamic"), true);
	    buttonGroup.add(dynamicButton);
	    permanentButton = new JRadioButton(
		ResourceStrings.getString("permanent"), false);
	    buttonGroup.add(permanentButton);
	    label.setLabelFor(dynamicButton);
	    panel.add(FieldLayout.FIELD, dynamicButton);
	    panel.add(FieldLayout.LABEL, new JLabel(""));
	    panel.add(FieldLayout.FIELD, permanentButton);
	    panel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(panel);
	    stepBox.add(Box.createVerticalGlue());
	}

	public String getDescription() {
	    return ResourceStrings.getString("add_wiz_lease_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    dynamicButton.setSelected(dynamic);
	    setForwardEnabled(true);
	}

	public boolean setInactive(int direction) {
	    dynamic = dynamicButton.isSelected();
	    return true;
	}
    }

    // Last chance to check work before committing to it
    class ReviewStep implements WizardStep {
	private Box stepBox;
	private JPanel panel;
	private JTable addressTable;
	private JLabel numberLabel;
	private JLabel commentLabel;
	private JLabel serverLabel;
	private JLabel macroLabel;
	private JLabel flagLabel;
	private JLabel leaseLabel;

	public ReviewStep() {
	    stepBox = Box.createVerticalBox();
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("add_wiz_review_explain"), 4, 45));

	    panel = new JPanel(new FieldLayout());
	    JLabel tmpL;

	    tmpL = addLabelMnemonic("add_wiz_count_label");
	    numberLabel = addField("20");
	    tmpL.setLabelFor(numberLabel);

	    tmpL = addLabelMnemonic("add_wiz_comment_label");
	    commentLabel = addField("Marketing");
	    tmpL.setLabelFor(commentLabel);

	    tmpL = addLabelMnemonic("add_wiz_server_label");
	    serverLabel = addField("atlantic");
	    tmpL.setLabelFor(serverLabel);

	    tmpL = addLabelMnemonic("add_wiz_macro_label");
	    macroLabel = addField("atlantic");
	    tmpL.setLabelFor(macroLabel);

	    tmpL = addLabel("add_wiz_review_unusable");
	    flagLabel = addField("Yes");
	    tmpL.setLabelFor(flagLabel);
	    tmpL.setToolTipText(
		ResourceStrings.getString("add_wiz_review_unusable"));

	    tmpL = addLabelMnemonic("add_wiz_lease_label");
	    leaseLabel = addField(ResourceStrings.getString("dynamic"));
	    tmpL.setLabelFor(leaseLabel);

	    panel.setAlignmentX(Component.LEFT_ALIGNMENT);
	    stepBox.add(panel);

	    stepBox.add(Box.createVerticalStrut(5));

	    Mnemonic mnAdd =
                new Mnemonic(ResourceStrings.getString(
		    "add_wiz_confirm_label"));
            JLabel label = new JLabel(mnAdd.getString());
            stepBox.add(label);
            stepBox.add(Box.createVerticalStrut(2));
            addressTable = new JTable(addressTableModel);
            label.setLabelFor(addressTable);
            label.setToolTipText(mnAdd.getString());
	    label.setDisplayedMnemonic(mnAdd.getMnemonic());

	    addressTable.setDefaultRenderer(IPAddress.class,
		new ExtendedCellRenderer());

	    // Table should not be selectable in any way
	    addressTable.setRowSelectionAllowed(false);
	    addressTable.setColumnSelectionAllowed(false);
	    addressTable.setCellSelectionEnabled(false);
	    JScrollPane scrollPane = new JScrollPane(addressTable);
	    Dimension d = addressTable.getPreferredScrollableViewportSize();
	    d.height = 50;
	    addressTable.setPreferredScrollableViewportSize(d);
	    stepBox.add(scrollPane);
	    stepBox.add(Box.createVerticalGlue());
	}

	private JLabel addLabel(String s) {
	    JLabel l = new JLabel(ResourceStrings.getString(s));
	    panel.add(FieldLayout.LABEL, l);
	    return l;
	}

	private JLabel addLabelMnemonic(String s) {
            Mnemonic mnStr =
                new Mnemonic(ResourceStrings.getString(s));
	    JLabel l = new JLabel(mnStr.getString());
	    l.setToolTipText(mnStr.getString());
            panel.add(FieldLayout.LABEL, l);
            return l;
        }

	private JLabel addField(String s) {
	    JLabel l = new JLabel(s);
	    l.setForeground(Color.black);
	    panel.add(FieldLayout.FIELD, l);
	    return l;
	}

	public String getDescription() {
	    return ResourceStrings.getString("add_wiz_review_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    // Use number of addresses actually generated, not requested
	    numberLabel.setText(
		String.valueOf(addressTableModel.getRowCount()));
	    commentLabel.setText(comment);
	    serverLabel.setText(server);
	    macroLabel.setText(macro);
	    if (unusable) {
		flagLabel.setText(ResourceStrings.getString("yes"));
	    } else {
		flagLabel.setText(ResourceStrings.getString("no"));
	    }
	    if (dynamic) {
		leaseLabel.setText(ResourceStrings.getString("dynamic"));
	    } else {
		leaseLabel.setText(ResourceStrings.getString("permanent"));
	    }
	    setFinishEnabled(true);
	}

	public boolean setInactive(int direction) {
	    // Nothing to do
	    return true;
	}
    }

    public AddressWizard(Frame owner, Network net) {
	super(owner, "");
	setTitle(MessageFormat.format(
	    ResourceStrings.getString("address_wizard_title"), net.toString()));

	network = net;
	startAddress = network.getAddress();

	try {
	    noMacro = new Macro(ResourceStrings.getString("no_macro_item"));
	} catch (ValidationException e) {
	    // this should never happen!
	    System.err.println(e.getMessage());
	}
	addressTableModel = new WizardTableModel();

	// Create steps in order of appearance
	addStep(new NumberStep());
	addStep(new ServerStep());
	addStep(new ConfirmStep());
	addStep(new ConfigureStep());
	addStep(new LeaseStep());
	addStep(new ReviewStep());
	showFirstStep();
    }

    public void doFinish() {
	/*
	 * Method here is as follows:
	 * 1. Create a ProgressManager which will apprise user of our progress
	 * 2. Create a background thread to execute the add operations
	 * 3. Within the background thread, update the progress monitor
	 *    as each address is created.
	 * 4. At completion, the background thread displays the error
	 *    output, if any, before it invokes one last runnable which pops
	 *    down and cleans up.
	 */
	// final so that ProgressUpdater can access it
	final ProgressManager progress = new ProgressManager(this,
	    ResourceStrings.getString("add_wiz_progress"), "", 0,
	    addressTableModel.getRowCount());
	final Runnable finisher = new Runnable() {
	    public void run() {
		reallyFinish();
	    }
	};

	// Here's the thread which does the adds
	Thread addThread = new Thread() {
	    public void run() {
		DhcpNetMgr server = DataManager.get().getDhcpNetMgr();
		// Create a template object which we'll use for all the adds
		DhcpClientRecord rec = new DhcpClientRecord();
		rec.setExpiration(new Date(0));
		rec.setUnusable(unusable);
		rec.setPermanent(!dynamic);
		try {
		    rec.setServerIP(serverIP);
		} catch (ValidationException e) {
		    // Should never happen as we have a valid IP already
		}
		if (macro.equals(noMacro.getKey())) {
			rec.setMacro("");
		} else {
			rec.setMacro(macro);
		}
		rec.setComment(comment);

		// This is final so it can be used in the errorDisplay Runnable
		final ErrorTable failedTable = new ErrorTable(
		    ResourceStrings.getString("address_column"),
		    IPAddress.class);

		/*
		 * For each address, create a client record and possibly a
		 * hosts record, log any errors for later consumption.
		 */
		for (int i = 0; i < addressTableModel.getRowCount(); ++i) {
		    Address addr = addressTableModel.getAddressAt(i);
		    try {
			rec.setClientIP(addr.addr);
			rec.setClientName(addr.name);
			server.addClient(rec, network.toString());
			progress.update(i+1, addr.addr.toString());
		    } catch (InterruptedException e) {
			SwingUtilities.invokeLater(finisher);
			return;
		    } catch (Throwable e) {
			// Pick the best message for the exception thrown
			String msg;
			if (e instanceof ExistsException) {
			    msg = ResourceStrings.getString("address_exists");
			} else if (e instanceof HostExistsException) {
			    msg = ResourceStrings.getString("host_exists");
			} else {
			    msg = e.getMessage();
			}
			failedTable.addError(addr.addr, msg);
		    }
		}

		// If any errors occurred, display them all at once.
		if (!failedTable.isEmpty()) {
		    Runnable errorDisplay = new Runnable() {
			public void run() {
			    Object [] objs = new Object[2];
			    objs[0] =
				ResourceStrings.getString("add_wiz_error");
			    JScrollPane scrollPane =
				new JScrollPane(failedTable);
			    // Resize the table to something kind of small
			    Dimension d =
				failedTable.
				getPreferredScrollableViewportSize();
			    d.height = 80;
			    failedTable.setPreferredScrollableViewportSize(d);
			    objs[1] = scrollPane;
			    JOptionPane.showMessageDialog(AddressWizard.this,
				objs,
				ResourceStrings.getString("server_error_title"),
				JOptionPane.ERROR_MESSAGE);
			}
		    };
		    try {
			SwingUtilities.invokeAndWait(errorDisplay);
		    } catch (Throwable e) {
			e.printStackTrace();
		    }
		}
		SwingUtilities.invokeLater(finisher);
	    }
	};
	addThread.start();
    }

    protected void reallyFinish() {
        super.doFinish();
    }

    public void doHelp() {
	DhcpmgrApplet.showHelp("address_wizard");
    }
}
