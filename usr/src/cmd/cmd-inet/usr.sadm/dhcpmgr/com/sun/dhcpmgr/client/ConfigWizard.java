/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.MessageFormat;
import java.net.*;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;
import javax.swing.border.*;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.ExistsException;

/**
 * This wizard configures the DHCP service.  It also has a mode switch so
 * that it is also usable for just adding a single network, so that in
 * the tool it actually performs the Network Wizard function as well.
 */
public class ConfigWizard extends DSWizard {
    private boolean fullConfig;
    private DhcpServiceMgr server;
    private int leaseLength = 3600*24;
    private boolean leaseNegotiable = true;
    private String dnsDomain;
    private Vector dnsServs;
    private Network network;
    private boolean isLan = true;
    private boolean routerDiscovery = true;
    private IPAddress router = null;
    private String nisDomain;
    private Vector nisServs;
    private static final String [] unitChoices = {
	ResourceStrings.getString("cfg_wiz_hours"),
	ResourceStrings.getString("cfg_wiz_days"),
	ResourceStrings.getString("cfg_wiz_weeks") };
    private static final int [] unitMultiples = { 60*60, 24*60*60, 7*24*60*60 };

    // This step specifies lease length and renewal policies for the server
    class LeaseStep implements WizardStep {
	private IntegerField length;
	private JComboBox units;
	private JCheckBox negotiable;
	private Box stepBox;

	public LeaseStep() {
	    stepBox = Box.createVerticalBox();

	    // Explanatory text
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("cfg_wiz_lease_explain"), 3, 45));

	    // Need to input a number together with units
	    JPanel flowPanel = new JPanel();

	    Mnemonic mnLease =
                new Mnemonic(ResourceStrings.getString("cfg_wiz_lease_length"));
            JLabel lblLeaseLen = new JLabel(
                mnLease.getString());

	    flowPanel.add(lblLeaseLen);

	    // Use a box for the value and units to keep together in layout
	    Box leaseBox = Box.createHorizontalBox();
	    length = new IntegerField();
	    leaseBox.add(length);
	    leaseBox.add(Box.createHorizontalStrut(5));

	    lblLeaseLen.setLabelFor(length);
	    lblLeaseLen.setToolTipText(mnLease.getString());
	    lblLeaseLen.setDisplayedMnemonic(mnLease.getMnemonic());

	    units = new JComboBox(unitChoices);
	    leaseBox.add(units);
	    flowPanel.add(leaseBox);
	    stepBox.add(flowPanel);
	    stepBox.add(Box.createVerticalStrut(10));

	    // Explain negotiable, provide selection for it
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("cfg_wiz_negotiable_explain"), 6,
		45));

	    negotiable = new JCheckBox(
		ResourceStrings.getString("cfg_wiz_negotiable"), true);
	    negotiable.setToolTipText(
		ResourceStrings.getString("cfg_wiz_negotiable"));
	    negotiable.setAlignmentX(Component.CENTER_ALIGNMENT);
	    stepBox.add(negotiable);
	    stepBox.add(Box.createVerticalGlue());
	}

	public String getDescription() {
	    return ResourceStrings.getString("cfg_wiz_lease_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	    // Set the units field to the maximum unit this value expresses
	    int lengthVal = 0;
	    int i;
	    for (i = unitMultiples.length - 1; i >= 0; --i) {
		lengthVal = leaseLength / unitMultiples[i];
		if (lengthVal != 0) {
		    if (leaseLength % unitMultiples[i] == 0) {
			break;
		    }
		}
	    }
	    if (i == -1) {
		i = 0;
	    }
	    units.setSelectedIndex(i);
	    length.setValue(lengthVal);
	    negotiable.setSelected(leaseNegotiable);
	}

	public boolean setInactive(int direction) {
	    // Leases cannot be zero length
	    long lease = (long)length.getValue();
	    if (lease == 0) {
		JOptionPane.showMessageDialog(ConfigWizard.this,
		    ResourceStrings.getString("cfg_wiz_zero_lease"),
		    ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return false;
	    }
	    int multiplier = unitMultiples[units.getSelectedIndex()];
	    lease *= multiplier;
	    if (lease > Integer.MAX_VALUE) {
		// Value is too large
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("cfg_wiz_lease_overflow"));
		Object args = new Object[] {
		    new Integer(Integer.MAX_VALUE / multiplier),
		    units.getSelectedItem()
		};
		JOptionPane.showMessageDialog(ConfigWizard.this,
		    form.format(args), ResourceStrings.getString("input_error"),
		    JOptionPane.ERROR_MESSAGE);
		return false;
	    }
	    leaseLength = (int)lease;
	    leaseNegotiable = negotiable.isSelected();
	    return true;
	}
    }

    // Step to configure DNS
    class DnsStep implements WizardStep {
	private NoSpaceField domain;
	private IPAddressList serverList;
	private Box stepBox;
	private boolean firstActive = true;

	public DnsStep() {
	    stepBox = Box.createVerticalBox();

	    // Explanatory text
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("cfg_wiz_dns_explain"), 5, 45));
	    stepBox.add(Box.createVerticalStrut(10));

	    // Domain first
	    JPanel fieldPanel = new JPanel(new FieldLayout());

	    Mnemonic mnDNS =
                new Mnemonic(ResourceStrings.getString("cfg_wiz_dns_domain"));
            JLabel jlDNSDomain = new JLabel(mnDNS.getString());
            fieldPanel.add(FieldLayout.LABEL, jlDNSDomain);

	    domain = new NoSpaceField();
	    jlDNSDomain.setLabelFor(domain);
	    jlDNSDomain.setToolTipText(mnDNS.getString());
	    jlDNSDomain.setDisplayedMnemonic(mnDNS.getMnemonic());
	    fieldPanel.add(FieldLayout.FIELD, domain);
	    stepBox.add(fieldPanel);

	    serverList = new IPAddressList();
	    Border tb = BorderFactory.createTitledBorder(
		BorderFactory.createLineBorder(Color.black),
		ResourceStrings.getString("cfg_wiz_dns_servers"));
	    serverList.setBorder(BorderFactory.createCompoundBorder(tb,
		BorderFactory.createEmptyBorder(5, 5, 5, 5)));
	    stepBox.add(serverList);
	}

	public String getDescription() {
	    return ResourceStrings.getString("cfg_wiz_dns_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);

	    // First time through, ask the server for the defaults
	    if (firstActive) {
		firstActive = false;
		try {
		    domain.setText(
			server.getStringOption(StandardOptions.CD_DNSDOMAIN,
			""));
		    serverList.setAddressList(
			server.getIPOption(StandardOptions.CD_DNSSERV, ""));
		} catch (Throwable e) {
		    // Ignore errors, we're just supplying defaults
		}
	    }
	}

	public boolean setInactive(int direction) {
	    if (direction == FORWARD) {
		/*
		 * Either must supply both a domain and a list of servers, or
		 * neither
		 */
		if ((domain.getText().length() == 0)
			!= (serverList.getListSize() == 0)) {
		    JOptionPane.showMessageDialog(ConfigWizard.this,
			ResourceStrings.getString("cfg_wiz_dns_both"),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		}
	    }
	    dnsDomain = domain.getText();
	    dnsServs = serverList.getAddressList();
	    return true;
	}
    }

    // Select the network to configure
    class NetworkStep implements WizardStep {
	private JComboBox networkBox;
	private NetworkListModel networkListModel;
	private IPAddressField mask;
	private Box stepBox;
	private boolean firstActive = true;
	private Hashtable maskTable;

	// Model for the list of networks
	class NetworkListModel extends AbstractListModel
		implements ComboBoxModel {
	    private Object currentValue;
	    private String [] data = null;

	    public int getSize() {
		if (data == null) {
		    return 0;
		} else {
		    return data.length;
		}
	    }

	    public Object getElementAt(int index) {
		if (data == null) {
		    return null;
		} else {
		    return data[index];
		}
	    }

	    public void setSelectedItem(Object anItem) {
		currentValue = anItem;
		fireContentsChanged(this, -1, -1);
	    }

	    public Object getSelectedItem() {
		return currentValue;
	    }

	    public void setData(Vector addrs) {
		data = new String[addrs.size()];
		addrs.copyInto(data);
		fireContentsChanged(this, 0, data.length);
	    }
	}

	/*
	 * Editor for the Network combo box, ensures that a valid IP address
	 * is entered. This implementation cribbed from Swing's
	 * BasicComboBoxEditor in plaf/basic
	 */
	class NetworkComboBoxEditor implements ComboBoxEditor, FocusListener {
	    private IPAddressField editor;

	    public NetworkComboBoxEditor() {
		editor = new IPAddressField();
		editor.addFocusListener(this);
	    }

	    public Component getEditorComponent() {
		return editor;
	    }

	    public void setItem(Object obj) {
		if (obj != null) {
		    editor.setText((String)obj);
		} else {
		    editor.setText("");
		}
	    }

	    public Object getItem() {
		return editor.getText();
	    }

	    public void selectAll() {
		editor.selectAll();
		editor.requestFocus();
	    }

	    public void focusGained(FocusEvent e) {
	    }

	    public void focusLost(FocusEvent e) {
	    }

	    public void addActionListener(ActionListener l) {
		editor.addActionListener(l);
	    }

	    public void removeActionListener(ActionListener l) {
		editor.removeActionListener(l);
	    }
	}

	public NetworkStep() {
	    stepBox = Box.createVerticalBox();

	    // Start with intro text, depending on mode.
	    if (fullConfig) {
		stepBox.add(Wizard.createTextArea(
		    ResourceStrings.getString("cfg_wiz_network_explain"), 4,
		    45));
	    } else {
		stepBox.add(Wizard.createTextArea(
		    ResourceStrings.getString("net_wiz_net_explain"), 6, 45));
	    }
	    stepBox.add(Box.createVerticalStrut(10));

            JPanel panel = new JPanel(new FieldLayout());
	    Mnemonic mnAddr =
                new Mnemonic(ResourceStrings.getString("cfg_wiz_network"));
	    JLabel jlNetworkAddr = new JLabel(mnAddr.getString());
            panel.add(FieldLayout.LABEL, jlNetworkAddr);
            networkListModel = new NetworkListModel();
            networkBox = new JComboBox(networkListModel);
            networkBox.setEditable(true);
            networkBox.setEditor(new NetworkComboBoxEditor());
            panel.add(FieldLayout.FIELD, networkBox);
	    jlNetworkAddr.setLabelFor(networkBox);
            jlNetworkAddr.setToolTipText(mnAddr.getString());
	    jlNetworkAddr.setDisplayedMnemonic(mnAddr.getMnemonic());

	    // Label and text field for subnet mask
	    Mnemonic mnMask =
            new Mnemonic(ResourceStrings.getString("cfg_wiz_mask"));
	    JLabel addrLbl =
                new JLabel(mnMask.getString());
            addrLbl.setToolTipText(mnMask.getString());
            panel.add(FieldLayout.LABEL, addrLbl);
            mask = new IPAddressField();
            addrLbl.setLabelFor(mask);
	    addrLbl.setDisplayedMnemonic(mnMask.getMnemonic());

	    panel.add(FieldLayout.FIELD, mask);
	    stepBox.add(panel);

	    stepBox.add(Box.createVerticalStrut(10));

	    if (fullConfig) {
		stepBox.add(Wizard.createTextArea(
		    ResourceStrings.getString("cfg_wiz_network_explainmore"), 4,
		    45));
	    }
	    stepBox.add(Box.createVerticalGlue());

	    /*
	     * Listen to selection changes on the network box and change the
	     * netmask accordingly.
	     */
	    networkBox.addItemListener(new ItemListener() {
		public void itemStateChanged(ItemEvent e) {
		    if (e.getStateChange() == ItemEvent.SELECTED) {
			String s = (String)e.getItem();
			IPAddress a = (IPAddress)maskTable.get(s);
			if (a != null) {
			    // We know the correct value, so set it
			    mask.setValue(a);
			}
		    }
		}
	    });
	}

	public String getDescription() {
	    return ResourceStrings.getString("cfg_wiz_network_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	    if (firstActive) {
		firstActive = false;
		maskTable = new Hashtable();
		try {
		    /*
		     * Initialize list to all networks directly attached to
		     * the server
		     */
		    IPInterface[] ifs = new IPInterface[0];
		    try {
			ifs = server.getInterfaces();
		    } catch (BridgeException e) {
			// we're not configured yet, apparently
			ifs = null;
		    }
		    Vector addrs = new Vector();

		    // Get list of already-configured networks
		    Network [] nets = new Network[0];
		    try {
			nets = DataManager.get().getNetworks(true);
		    } catch (BridgeException e) {
			// Ignore; we're not configured yet, apparently
		    }
		    /*
		     * Now filter the list so only unconfigured networks
		     * show up in the selection list.
		     */
		    if (ifs != null) {
		    for (int i = 0; i < ifs.length; ++i) {
			boolean alreadyConfigured = false;
			for (int j = 0; j < nets.length; ++j) {
			    if (ifs[i].getNetwork().equals(nets[j])) {
				alreadyConfigured = true;
				break;
			    }
			}
			if (!alreadyConfigured) {
			    // Add to list
			    String s = ifs[i].getNetwork().
				getNetworkNumber().getHostAddress();
			    addrs.addElement(s);
			    // Save netmask for retrieval later
			    maskTable.put(s, ifs[i].getNetwork().getMask());
			}
		    }
		    }
		    networkListModel.setData(addrs);
		    if (networkBox.getItemCount() > 0) {
			networkBox.setSelectedIndex(0);
		    }
		} catch (Throwable e) {
		    // Do nothing, we're just setting defaults
		    e.printStackTrace();
		}
	    }
	}

	public boolean setInactive(int direction) {
	    if (direction == FORWARD) {
		try {
		    network = new Network((String)networkBox.getSelectedItem());
		    if (mask.getValue() == null) {
			/*
			 * Check for empty, in which case we just let the
			 * default happen
			 */
			if (mask.getText().length() != 0) {
			    // Not a valid subnet mask
			    MessageFormat form = new MessageFormat(
				ResourceStrings.getString("cfg_wiz_bad_mask"));
			    Object [] args = new Object[1];
			    args[0] = mask.getText();
			    JOptionPane.showMessageDialog(ConfigWizard.this,
				form.format(args),
				ResourceStrings.getString("input_error"),
				JOptionPane.ERROR_MESSAGE);
			    return false;
			}
		    } else {
			network.setMask(mask.getValue());
		    }

		    // Check for network already configured, error if so
		    Network [] nets = new Network[0];
		    try {
			nets = DataManager.get().getNetworks(false);
		    } catch (BridgeException e) {
			// Ignore; must not be configured yet
		    }
		    for (int i = 0; i < nets.length; ++i) {
			if (network.equals(nets[i])) {
			    MessageFormat form = new MessageFormat(
				ResourceStrings.getString(
				"cfg_wiz_network_configured"));
			    Object [] args = new Object[1];
			    args[0] = network.getAddress().getHostAddress();
			    JOptionPane.showMessageDialog(ConfigWizard.this,
				form.format(args),
				ResourceStrings.getString("input_error"),
				JOptionPane.ERROR_MESSAGE);
			    return false;
			}
		    }
		} catch (ValidationException e) {
		    // Not a valid IP address
		    MessageFormat form = new MessageFormat(
			ResourceStrings.getString("cfg_wiz_bad_network"));
		    Object [] args = new Object[1];
		    args[0] = (String)networkBox.getSelectedItem();
		    if (args[0] == null) {
			args[0] = "";
		    }
		    JOptionPane.showMessageDialog(ConfigWizard.this,
			form.format(args),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		} catch (Throwable e) {
		    e.printStackTrace();
		    // Ignore other exceptions
		}
	    }
	    return true;
	}
    }

    // Get the type of network and routing policy
    class NetTypeStep implements WizardStep {
	private JRadioButton lan, ptp;
	private ButtonGroup typeGroup, routingGroup;
	private JRadioButton discover, specify;
	private IPAddressField address;
	private Box stepBox;
	private boolean firstTime = true;

	public NetTypeStep() {
	    stepBox = Box.createVerticalBox();

	    // Explanatory text at the top
	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("cfg_wiz_nettype_explain"), 2, 45));
	    stepBox.add(Box.createVerticalStrut(10));

	    // Label and radio buttons for type of network
	    JPanel panel = new JPanel(new GridLayout(2, 1));
	    /*
	     * Create a compound border with empty space on the outside and
	     * a line border on the inside, then title it amd put a space
	     * around the outside.
	     */
	    Border b = BorderFactory.createCompoundBorder(
		BorderFactory.createEmptyBorder(0, 5, 0, 5),
		BorderFactory.createLineBorder(Color.black));
	    Border tb = BorderFactory.createTitledBorder(b,
		ResourceStrings.getString("cfg_wiz_nettype_label"));
	    panel.setBorder(BorderFactory.createCompoundBorder(tb,
		BorderFactory.createEmptyBorder(0, 5, 0, 5)));

            lan = new JRadioButton(ResourceStrings.getString("cfg_wiz_lan"),
                true);
            lan.setToolTipText(ResourceStrings.getString("cfg_wiz_lan"));
            typeGroup = new ButtonGroup();
            typeGroup.add(lan);
            panel.add(lan);
            ptp = new JRadioButton(ResourceStrings.getString("cfg_wiz_point"),
                false);
            ptp.setToolTipText(ResourceStrings.getString("cfg_wiz_point"));
            typeGroup.add(ptp);
            panel.add(ptp);
            stepBox.add(panel);
            stepBox.add(Box.createVerticalStrut(20));

	    // Routing policy
	    panel = new JPanel(new GridLayout(2, 1));
	    tb = BorderFactory.createTitledBorder(b,
		ResourceStrings.getString("cfg_wiz_routing_label"));
	    panel.setBorder(BorderFactory.createCompoundBorder(tb,
		BorderFactory.createEmptyBorder(0, 5, 0, 5)));

	    discover = new JRadioButton(
		ResourceStrings.getString("cfg_wiz_router_discovery"), true);
	    discover.setToolTipText(ResourceStrings.getString(
		"cfg_wiz_router_discovery"));
	    routingGroup = new ButtonGroup();
	    routingGroup.add(discover);
	    panel.add(discover);

	    Box routerBox = Box.createHorizontalBox();
	    specify = new JRadioButton(
		ResourceStrings.getString("cfg_wiz_router_specify"), false);
	    specify.setToolTipText(ResourceStrings.getString(
		"cfg_wiz_router_specify"));
	    routingGroup.add(specify);
	    routerBox.add(specify);
	    routerBox.add(Box.createHorizontalStrut(2));
	    address = new IPAddressField();
	    address.setEnabled(false); // Start off disabled
	    address.setMaximumSize(address.getPreferredSize());

	    // Box is sensitive to alignment, make sure they all agree
	    address.setAlignmentY(specify.getAlignmentY());

	    routerBox.add(address);
	    panel.add(routerBox);
	    stepBox.add(panel);

	    stepBox.add(Box.createVerticalStrut(10));
	    stepBox.add(Box.createVerticalGlue());

	    /*
	     * Enable forward if router discovery, or if specifying router and
	     * address is not empty.
	     */
	    specify.addChangeListener(new ChangeListener() {
		public void stateChanged(ChangeEvent e) {
		    address.setEnabled(specify.isSelected());
		    setForwardEnabled(!specify.isSelected()
			|| (address.getText().length() != 0));
		}
	    });

	    // Enable forward when address is not empty.
	    address.getDocument().addDocumentListener(new DocumentListener() {
		public void insertUpdate(DocumentEvent e) {
		    setForwardEnabled(address.getText().length() != 0);
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
	    return ResourceStrings.getString("cfg_wiz_nettype_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	    lan.setSelected(isLan);
	    discover.setSelected(routerDiscovery);
	    address.setValue(router);
	}

	public boolean setInactive(int direction) {
	    isLan = lan.isSelected();
	    if (direction == FORWARD) {
		routerDiscovery = discover.isSelected();
		if (!routerDiscovery) {
		    IPAddress addr = address.getValue();
		    if (addr == null) {
			// Invalid IP address
			MessageFormat form = new MessageFormat(
			    ResourceStrings.getString(
			    "cfg_wiz_router_addr_err"));
			Object [] args = new Object[1];
			args[0] = address.getText();
			JOptionPane.showMessageDialog(ConfigWizard.this,
				form.format(args),
				ResourceStrings.getString("input_error"),
				JOptionPane.ERROR_MESSAGE);
			return false;
		    } else if (!network.containsAddress(addr)) {
			// Router is not on the network we're configuring
			MessageFormat form = new MessageFormat(
			    ResourceStrings.getString(
			    "cfg_wiz_router_net_err"));
			Object [] args = new Object[2];
			args[0] = address.getText();
			args[1] = network.toString();
			JOptionPane.showMessageDialog(ConfigWizard.this,
			    form.format(args),
			    ResourceStrings.getString("input_error"),
			    JOptionPane.ERROR_MESSAGE);
			return false;
		    }
		    router = addr;
		}
	    }
	    return true;
	}
    }

    // Get the NIS configuration
    class NisStep implements WizardStep {
	private NoSpaceField domain;
	private Box stepBox;
	private IPAddressField address;
	private JButton add, delete, moveUp, moveDown;
	private IPAddressList serverList;
	boolean firstActive = true;

	public NisStep() {
	    stepBox = Box.createVerticalBox();

	    stepBox.add(Wizard.createTextArea(
		ResourceStrings.getString("cfg_wiz_nis_explain"), 6, 45));
	    stepBox.add(Box.createVerticalStrut(10));

            JPanel fieldPanel = new JPanel(new FieldLayout());
	    Mnemonic mnNis =
		new Mnemonic(ResourceStrings.getString("cfg_wiz_nis_domain"));
            JLabel jlNISDomain =
		new JLabel(mnNis.getString());
	    fieldPanel.add(FieldLayout.LABEL, jlNISDomain);
	    domain = new NoSpaceField();
	    jlNISDomain.setLabelFor(domain);
	    jlNISDomain.setToolTipText(mnNis.getString());
	    jlNISDomain.setDisplayedMnemonic(mnNis.getMnemonic());
	    fieldPanel.add(FieldLayout.FIELD, domain);
            stepBox.add(fieldPanel);

	    serverList = new IPAddressList();
	    Border tb = BorderFactory.createTitledBorder(
		BorderFactory.createLineBorder(Color.black),
		ResourceStrings.getString("cfg_wiz_nis_servers"));
	    serverList.setBorder(BorderFactory.createCompoundBorder(tb,
		BorderFactory.createEmptyBorder(5, 5, 5, 5)));
	    stepBox.add(serverList);
	}

	public String getDescription() {
	    return ResourceStrings.getString("cfg_wiz_nis_desc");
	}

	public Component getComponent() {
	    return stepBox;
	}

	public void setActive(int direction) {
	    setForwardEnabled(true);
	    if (firstActive) {
		firstActive = false;
		try {
		    /*
		     * Order here is important; do the servers first because if
		     * there's an error, we don't retrieve a domain name, which
		     * appears to never fail.
		     */
		    serverList.setAddressList(
			server.getIPOption(StandardOptions.CD_NIS_SERV, ""));
		    domain.setText(
			server.getStringOption(StandardOptions.CD_NIS_DOMAIN,
			""));
		} catch (Throwable e) {
		    // Do nothing, just setting defaults
		}
	    }
	}

	public boolean setInactive(int direction) {
	    if (direction == FORWARD) {
		/*
		 * Either must supply both a domain and a list of servers, or
		 * neither
		 */
		if ((domain.getText().length() == 0)
			!= (serverList.getListSize() == 0)) {
		    JOptionPane.showMessageDialog(ConfigWizard.this,
			ResourceStrings.getString("cfg_wiz_nis_both"),
			ResourceStrings.getString("input_error"),
			JOptionPane.ERROR_MESSAGE);
		    return false;
		}
	    }
	    nisDomain = domain.getText();
	    nisServs = serverList.getAddressList();
	    return true;
	}
    }

    class ReviewStep implements WizardStep {
	private JLabel storeLabel;
	private JLabel leaseLabel;
	private JLabel networkLabel;
	private JLabel netTypeLabel;
	private JLabel netmaskLabel;
	private JLabel routerLabel;
	private JLabel dnsLabel;
	private JLabel dnsServLabel;
	private JLabel nisLabel;
	private JLabel nisServLabel;
	private JPanel panel;
	private JScrollPane scrollPane;

	public ReviewStep() {
	    Box stepBox = Box.createVerticalBox();
	    if (fullConfig) {
		stepBox.add(Wizard.createTextArea(
		    ResourceStrings.getString("cfg_wiz_review_explain"), 3,
		    45));
	    } else {
		stepBox.add(Wizard.createTextArea(
		    ResourceStrings.getString("net_wiz_review_explain"), 3,
		    45));
	    }

	    panel = new JPanel(new FieldLayout());
	    JLabel jlTmp;

	    if (fullConfig) {
		addLabel("cfg_wiz_datastore");
		storeLabel = addField("uninitialized");

		jlTmp = addLabelMnemonic("cfg_wiz_lease_length");
		leaseLabel = addField("1 day");

		jlTmp = addLabelMnemonic("cfg_wiz_dns_domain");
		dnsLabel = addField("Bar.Sun.COM");

		addLabel("cfg_wiz_dns_servers");
		dnsServLabel = addField("109.151.1.15, 109.148.144.2");
	    }

	    jlTmp = addLabelMnemonic("cfg_wiz_network");
	    networkLabel = addField("109.148.21.0");
	    jlTmp.setLabelFor(networkLabel);

	    jlTmp = addLabelMnemonic("cfg_wiz_mask");
	    netmaskLabel = addField("255.255.255.0");
	    jlTmp.setLabelFor(netmaskLabel);

	    addLabel("cfg_wiz_nettype");
	    netTypeLabel = addField(ResourceStrings.getString("cfg_wiz_lan"));

	    addLabel("cfg_wiz_router");
	    routerLabel = addField(
		ResourceStrings.getString("cfg_wiz_router_discovery"));

	    jlTmp = addLabelMnemonic("cfg_wiz_nis_domain");
	    nisLabel = addField("Foo.Bar.Sun.COM");
	    jlTmp.setLabelFor(nisLabel);

	    addLabel("cfg_wiz_nis_servers");
	    nisServLabel = addField("109.148.21.21, 109.148.21.44");

	    stepBox.add(panel);
	    stepBox.add(Box.createVerticalGlue());

	    scrollPane = new JScrollPane(stepBox,
		JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
		JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
	}

	private void addLabel(String s) {
	    JLabel jl;
	    jl = new JLabel(ResourceStrings.getString(s));
	    panel.add(FieldLayout.LABEL, jl);
	    jl.setLabelFor(panel);
	    jl.setToolTipText(ResourceStrings.getString(s));
	}

	private JLabel addLabelMnemonic(String s) {
	    JLabel jl;
	    Mnemonic mnStr =
                new Mnemonic(ResourceStrings.getString(s));
	    jl = new JLabel(mnStr.getString());
	    panel.add(FieldLayout.LABEL, jl);
            jl.setToolTipText(mnStr.getString());
	    return jl;
        }

	private JLabel addField(String s) {
	    JLabel l = new JLabel(s);
	    l.setForeground(Color.black);
	    panel.add(FieldLayout.FIELD, l);
	    l.setLabelFor(panel);
	    l.setToolTipText(s);
	    return l;
	}

	public String getDescription() {
	    return ResourceStrings.getString("cfg_wiz_review_desc");
	}

	public Component getComponent() {
	    return scrollPane;
	}

	public void setActive(int direction) {
	    StringBuffer b = new StringBuffer();
	    setFinishEnabled(true);
	    if (fullConfig) {
		storeLabel.setText(getDsconf().getModule().getDescription());

		// Display lease length, reducing to largest units possible
		int lengthVal = 0;
		int i;
		for (i = unitMultiples.length - 1; i >= 0; --i) {
		    lengthVal = leaseLength / unitMultiples[i];
		    if ((lengthVal != 0)
			    && (leaseLength % unitMultiples[i] == 0)) {
			break;
		    }
		}
		if (i == -1) {
		    i = 0;
		}
		Object [] objs = new Object[3];
		objs[0] = new Integer(lengthVal);
		objs[1] = unitChoices[i];
		if (leaseNegotiable) {
		    objs[2] = ResourceStrings.getString("cfg_wiz_renewable");
		} else {
		    objs[2] = ResourceStrings.getString("cfg_wiz_nonrenewable");
		}
		leaseLabel.setText(MessageFormat.format(
		    ResourceStrings.getString("cfg_wiz_lease_fmt"), objs));

		// Set DNS info
		dnsLabel.setText(dnsDomain);
		b.setLength(0);
		Enumeration en = dnsServs.elements();
		while (en.hasMoreElements()) {
		    IPAddress a = (IPAddress)en.nextElement();
		    if (b.length() != 0) {
			b.append(", ");
		    }
		    b.append(a.getHostAddress());
		}
		dnsServLabel.setText(b.toString());
	    }

	    // Set network address
	    networkLabel.setText(network.toString());
	    // Set subnet mask
	    netmaskLabel.setText(network.getMask().getHostAddress());

	    // Set network type
	    if (isLan) {
		netTypeLabel.setText(ResourceStrings.getString("cfg_wiz_lan"));
	    } else {
		netTypeLabel.setText(
		    ResourceStrings.getString("cfg_wiz_point"));
	    }

	    // Set router
	    if (routerDiscovery) {
		routerLabel.setText(
		    ResourceStrings.getString("cfg_wiz_router_discovery"));
	    } else {
		routerLabel.setText(router.getHostAddress());
	    }

	    // Set NIS info
	    nisLabel.setText(nisDomain);
	    b.setLength(0);
	    Enumeration en = nisServs.elements();
	    while (en.hasMoreElements()) {
		IPAddress a = (IPAddress)en.nextElement();
		if (b.length() != 0) {
		    b.append(", ");
		}
		b.append(a.getHostAddress());
	    }
	    nisServLabel.setText(b.toString());
	}

	public boolean setInactive(int direction) {
	    return true;
	}
    }

    public ConfigWizard(Frame owner, String title, boolean fullConfig) {
	super(owner, title);

	try {
	    server = DataManager.get().getDhcpServiceMgr();
	    if (fullConfig) {
		dsconfList = new DSConfList();
		dsconfList.init(server);
	    }
	} catch (Throwable e) {
	    e.printStackTrace(); // XXX Need to do something to handle this...
	    return;
	}

	this.fullConfig = fullConfig;

	// If running as Config Wizard, put in the initial steps.
	if (fullConfig) {
	    addStep(new DatastoreStep(
		ResourceStrings.getString("cfg_wiz_explain"),
		ResourceStrings.getString("cfg_wiz_store_explain")));
	    addStep(new DatastoreModuleStep());
	    addStep(new LeaseStep());
	    addStep(new DnsStep());
	}
	// Now the steps that are common to both wizards.
	addStep(new NetworkStep());
	addStep(new NetTypeStep());
	addStep(new NisStep());
	addStep(new ReviewStep());
	showFirstStep();
    }

    public void doFinish() {
	/*
	 * To activate the server, we have to do the following items:
	 * 1. Create the location/path if necessary.
	 * 2. Create the defaults file.
	 * 3. Create the dhcptab; ignore errors if it already exists
	 *    (as in NIS+ case)
	 * 4. Create the Locale macro; ignore the error if it already exists
	 * 5. Create the server macro; if it exists we just overwrite it
	 * 6. Create the network macro;
	 * 7. Create the network table
	 * 8. Start the service
	 */
	if (fullConfig) {
	    getDsconf().setConfig();
	    getDsconf().setLocation();
	    // Create the location/path.
	    try {
		server.makeLocation(getDsconf().getDS());
	    } catch (ExistsException e) {
		// this is o.k.
	    } catch (Throwable e) {
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("create_location_error"));
		Object [] args = new Object[1];
		args[0] = getDsconf().getDS().getLocation();
		String msg = form.format(args);
		JOptionPane.showMessageDialog(ConfigWizard.this,
		    msg,
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }

	    // Create the defaults file.
	    DhcpdOptions options = new DhcpdOptions();
	    options.setDaemonEnabled(true);
	    options.setDhcpDatastore(getDsconf().getDS());
	    try {
		server.writeDefaults(options);
	    } catch (Throwable e) {
		e.printStackTrace();
		return;
	    }

	    // Create the dhcptab
	    try {
		DataManager.get().getDhcptabMgr().createDhcptab();
	    } catch (Throwable e) {
		// Not an error; some data stores are shared by multiple servers
	    }
	}

	if (fullConfig) {
	    try {
		DataManager.get().getDhcptabMgr().createLocaleMacro();
	    } catch (Throwable e) {
		/*
		 * Ignore this error, if one's already there we'll assume
		 * it's correct
		 */
	    }

	    // Create the Server macro
	    try {
		String svrName =
		    DataManager.get().getDhcpServiceMgr().getShortServerName();
		InetAddress svrAddress =
		    DataManager.get().getDhcpServiceMgr().getServerAddress();
		DataManager.get().getDhcptabMgr().createServerMacro(svrName,
		    svrAddress, leaseLength, leaseNegotiable, dnsDomain,
		    dnsServs);
	    } catch (Throwable e) {
		// Couldn't create it; inform user because this is serious
		Object [] args = new Object[2];
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("create_macro_error"));
		args[0] = DataManager.get().getShortServerName();
		args[1] = e.getMessage();
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.ERROR_MESSAGE);
		return;
	    }
	}

	// Create the network macro
	IPAddress [] routers = null;
	if (router != null) {
	    routers = new IPAddress[] { router };
	}
	try {
	    DataManager.get().getDhcptabMgr().createNetworkMacro(network,
		routers, isLan, nisDomain, nisServs);
	} catch (Throwable e) {
	    // Ignore this error? dhcpconfig gives a merge option
	}

	// Create the network table
	try {
	    DataManager.get().getDhcpNetMgr().createNetwork(network.toString());
	} catch (BridgeException e) {
	    // This indicates table existed; no error
	} catch (Throwable e) {
	    Object [] args = new Object[2];
	    MessageFormat form = new MessageFormat(
		ResourceStrings.getString("create_network_table_error"));
	    args[0] = network.toString();
	    args[1] = e.getMessage();
	    JOptionPane.showMessageDialog(this, form.format(args),
		ResourceStrings.getString("server_error_title"),
		JOptionPane.ERROR_MESSAGE);
	    return;
	}

	// Start the server in the initial configuration case
	if (fullConfig) {
	    try {
		DataManager.get().getDhcpServiceMgr().startup();
	    } catch (Throwable e) {
		// Just warn user; this isn't disastrous
		Object [] args = new Object[1];
		MessageFormat form = new MessageFormat(
		    ResourceStrings.getString("startup_server_error"));
		args[0] = e.getMessage();
		JOptionPane.showMessageDialog(this, form.format(args),
		    ResourceStrings.getString("server_error_title"),
		    JOptionPane.WARNING_MESSAGE);
	    }
	}

	super.doFinish();
    }

    public void doHelp() {
	if (fullConfig) {
	    DhcpmgrApplet.showHelp("config_wizard");
	} else {
	    DhcpmgrApplet.showHelp("network_wizard");
	}
    }
}
