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
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.text.*;
import java.net.*;

import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.bridge.BridgeException;
import com.sun.dhcpmgr.bridge.NoEntryException;

/**
 * Address View displays the networks currently under DHCP management, and
 * as a network is selected from the list its addresses are displayed.
 */
public class AddressView implements View {
    private JPanel displayPanel;
    protected static AutosizingTable addressTable;
    private JScrollPane addressPane;
    private boolean firstActivation = true;
    private NetworkListModel networkListModel;
    private JList networkList;
    protected static AddressTableModel addressTableModel = null;
    private TableSorter sortedTableModel;
    private JCheckBoxMenuItem showGrid;
    private JCheckBoxMenuItem showAddresses;
    private JMenuItem addAddrs;
    private JMenuItem releaseAddrs;
    private JMenuItem addNet;
    private JMenuItem deleteNets;
    private JMenuItem addressHelp;
    private Vector[] menuItems;
    private Frame myFrame;
    private Vector selectionListeners = new Vector();
    private int sortModelIndex = -1;
    private static final String NO_NETWORKS =
	ResourceStrings.getString("no_networks");

    // Model class for the network list
    class NetworkListModel extends AbstractListModel {
	private Object currentValue;
	private Network data[] = null;

	public void load() {
	    try {
		MainFrame.setStatusText(
		    ResourceStrings.getString("loading_networks"));
		data = DataManager.get().getNetworks(true);
	    } catch (Throwable e) {
		e.printStackTrace();
	    } finally {
		int len = 0;
		if (data != null) {
		    len = data.length;
		}
		MainFrame.setStatusText(
		    MessageFormat.format(
		    ResourceStrings.getString("networks_loaded"), len));
	    }
	}

	public void reload() {
	    load();
	    fireContentsChanged(this, -1, -1);
	}

	public int getSize() {
	    if (data == null) {
		load();
	    }
	    if (data == null) {
		return 0;
	    } else {
		return data.length;
	    }
	}

	public Object getElementAt(int index) {
	    if (data == null) {
		load();
	    }
	    if (data == null || index >= data.length) {
		return "";
	    } else {
		return data[index].toString();
	    }
	}

	public Network getNetworkAt(int index) {
	    if (data == null || index >= data.length) {
		return null;
	    } else {
		return data[index];
	    }
	}
    }

    // Container class for the address data
    class AddressTableModel extends AbstractTableModel {
	private DhcpClientRecord [] data;
	private String network;
	private boolean showAddresses;
	private boolean firstLoad;

	public AddressTableModel() {
	    data = null;
	    network = "";
	    showAddresses = false;
	    firstLoad = true;
	}

	public void load(String network) {
	    data = null;
	    fireTableDataChanged();
	    if (network.length() == 0) {
		// No network number supplied, so can't load
		return;
	    }
	    this.network = network;

	    // Update the status line
	    Object [] objs = {network};
	    String s = MessageFormat.format(
		ResourceStrings.getString("loading_addresses"), objs);
	    MainFrame.setStatusText(s);

	    // Kick off background loading of addresses
	    AddressLoader loader = new AddressLoader();

	}

	// Loading is done, re-sort and tell the view to repaint
	protected void doneLoading() {
	    sortedTableModel.reallocateIndexes();
	    if (firstLoad) {
		sortedTableModel.sortByColumn(0);
		firstLoad = false;
	    }
	    fireTableDataChanged();
	}

	protected String getNetwork() {
	    return network;
	}

	protected void setData(DhcpClientRecord [] newdata) {
	    data = newdata;
	}

	public void setShowAddresses(boolean state) {
	    showAddresses = state;
	    fireTableStructureChanged();
	    sortedTableModel.sortByColumn(sortModelIndex);
	}

	public int getRowCount() {
	    if (data == null) {
		return 0;
	    } else {
		return data.length;
	    }
	}

	public int getColumnCount() {
	    return 7;
	}

	public Object getValueAt(int row, int column) {
	    switch (column) {
	    case 0:
		if (showAddresses) {
		    return data[row].getClientIP();
		} else {
		    return data[row].getClientName();
		}
	    case 1:
		if (data[row].isUnusable()) {
		    return ResourceStrings.getString("unusable");
		} else if (data[row].isBootp()) {
		    return ResourceStrings.getString("bootp");
		} else if (data[row].isManual()) {
		    return ResourceStrings.getString("manual");
		} else if (data[row].isPermanent()) {
		    return ResourceStrings.getString("permanent");
		} else {
		    return ResourceStrings.getString("dynamic");
		}
	    case 2:
		return data[row].getExpiration();
	    case 3:
		if (showAddresses) {
		    return data[row].getServerIP();
		} else {
		    return data[row].getServerName();
		}
	    case 4:
		return data[row].getMacro();
	    case 5:
		return data[row].getClientId();
	    case 6:
		return data[row].getComment();
	    default:
		return null;
	    }
	}

	public Class getColumnClass(int column) {
	    switch (column) {
	    case 0:
	    case 3:
		if (showAddresses) {
		    return IPAddress.class;
		} else {
		    return String.class;
		}
	    case 2:
		return Date.class;
	    case 1:
	    case 4:
	    case 5:
	    case 6:
		return String.class;
	    default:
		return super.getColumnClass(column);
	    }
	}

	public String getColumnName(int column) {
	    switch (column) {
	    case 0:
		if (showAddresses) {
		    return ResourceStrings.getString("address_column");
		} else {
		    return ResourceStrings.getString("client_name_column");
		}
	    case 1:
		return ResourceStrings.getString("flags_column");
	    case 2:
		return ResourceStrings.getString("expires_column");
	    case 3:
		return ResourceStrings.getString("server_column");
	    case 4:
		return ResourceStrings.getString("macro_column");
	    case 5:
		return ResourceStrings.getString("client_column");
	    case 6:
		return ResourceStrings.getString("comment_column");
	    default:
		return super.getColumnName(column);
	    }
	}

	protected DhcpClientRecord getClientAt(int row) {
	    return data[row];
	}
    }

    // Background loader for addresses.
    class AddressLoader extends com.sun.dhcpmgr.ui.SwingWorker {
	public Object construct() {
	    try {
		String net = addressTableModel.getNetwork();
		return DataManager.get().getClients(net, true);
	    } catch (final BridgeException e) {
		// Since we're in a background thread, ask Swing to run ASAP.
		SwingUtilities.invokeLater(new Runnable() {
		    Object [] args = new Object[] { e.getMessage() };
		    public void run() {
			MessageFormat form = new MessageFormat(
			    ResourceStrings.getString("error_loading_addrs"));
			JOptionPane.showMessageDialog(null, form.format(args),
			    ResourceStrings.getString("server_error_title"),
			    JOptionPane.ERROR_MESSAGE);
		    }
		});
	    }
	    return null;
	}

	public void finished() {
	    addressTableModel.setData((DhcpClientRecord [])get());
	    addressTableModel.doneLoading();
	    MainFrame.setStatusText(
		MessageFormat.format(
		ResourceStrings.getString("address_status_message"),
		addressTableModel.getRowCount()));
	    addressTable.clearSelection();
	}
    }

    // Renderer class used to make unusable addresses bold in the display
    class AddressTableCellRenderer extends ExtendedCellRenderer {
	public Component getTableCellRendererComponent(JTable table,
		Object value, boolean isSelected, boolean hasFocus, int row,
		int column) {
	    Component c = super.getTableCellRendererComponent(table, value,
		isSelected, hasFocus, row, column);
	    int modelRow = sortedTableModel.mapRowAt(row);
	    if (modelRow != -1) {
		if (addressTableModel.getClientAt(modelRow).isUnusable()) {
		    Font f = c.getFont();
		    c.setFont(new Font(f.getName(), Font.BOLD, f.getSize()));
		}
	    }
	    return c;
	}
    }

    // Recipient of update messages sent when the editing dialogs exit
    class DialogListener implements ActionListener {
	public void actionPerformed(ActionEvent e) {
	    // Don't reload if cancel happened
	    if (!e.getActionCommand().equals(DialogActions.CANCEL)) {
		AddressView.this.reload();
	    }
	}
    }

    public AddressView() {
	displayPanel = new JPanel(new BorderLayout());

	// Create network selection list, tie it to table
	networkListModel = new NetworkListModel();
	networkList = new JList(networkListModel);
	networkList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
	networkList.addListSelectionListener(new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		// Ignore all but the last in a series of these events
		if (e.getValueIsAdjusting()) {
		    return;
		}
		String net = "";
		int index = networkList.getSelectedIndex();
		if (index != -1) {
		    net = (String)networkListModel.getElementAt(
			networkList.getSelectedIndex());
		}
		if (net.length() == 0) {
		    // No networks are selected; disable menu items
		    deleteNets.setEnabled(false);
		    addAddrs.setEnabled(false);
		    showAddresses.setEnabled(false);
		    showGrid.setEnabled(false);
		} else {
		    deleteNets.setEnabled(true);
		    addAddrs.setEnabled(true);
		    showAddresses.setEnabled(true);
		    showGrid.setEnabled(true);
		}
		addressTableModel.load(net);
	    }
	});

	// Use a prototype value as a performance enhancement
	networkList.setPrototypeCellValue("222.222.222.222");
	JScrollPane networkPane = new JScrollPane(networkList);
	JPanel networkPanel = new JPanel(new BorderLayout());
	networkPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));

	Mnemonic mnNetwork = new Mnemonic(ResourceStrings.getString("network"));
        JLabel nwLbl = new JLabel(mnNetwork.getString());
        nwLbl.setLabelFor(networkPanel);
	nwLbl.setToolTipText(mnNetwork.getString());
        networkPanel.add(nwLbl, BorderLayout.NORTH);
	nwLbl.setDisplayedMnemonic(mnNetwork.getMnemonic());

	networkPanel.add(networkPane, BorderLayout.CENTER);
	displayPanel.add(networkPanel, BorderLayout.WEST);

	// Create table to display in data area
	addressTableModel = new AddressTableModel();
	sortedTableModel = new TableSorter(addressTableModel);
	addressTable = new AutosizingTable(sortedTableModel);
	sortedTableModel.addMouseListenerToHeaderInTable(addressTable);
	addressTable.getTableHeader().setReorderingAllowed(true);
	addressTable.getTableHeader().setResizingAllowed(true);
	addressTable.setSelectionMode(
	    ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

	sortedTableModel.addActionListener(new ActionListener() {
	    private SortedHeaderRenderer sortedRenderer =
		new SortedHeaderRenderer(addressTable);
	    private TableCellRenderer savedRenderer;
	    public void actionPerformed(ActionEvent e) {
		// Clear the selection when sorting is changed
		addressTable.clearSelection();
		/*
		 * Change the header rendering to show which column is
		 * being used for sorting of the data.
		 */
		int modelIndex = Integer.parseInt(e.getActionCommand());
		int viewIndex =
		    addressTable.convertColumnIndexToView(modelIndex);
		if (sortModelIndex != -1) {
		    int sortViewIndex =
			addressTable.convertColumnIndexToView(sortModelIndex);
		    addressTable.getColumnModel().getColumn(
			sortViewIndex).setHeaderRenderer(savedRenderer);
		}
		/*
		 * Save the column currently being sorted so we can restore
		 * the renderer later.  We save model columns rather than
		 * view columns because model columns are invariant while
		 * view columns can be reordered with confusion resulting.
		 */
		TableColumn c =
		    addressTable.getColumnModel().getColumn(viewIndex);
		savedRenderer = c.getHeaderRenderer();
		c.setHeaderRenderer(sortedRenderer);
		sortModelIndex = modelIndex;
	    }
	});

	// Make double-clicks the same as Edit->Properties
	addressTable.addMouseListener(new MouseAdapter() {
	    public void mouseClicked(MouseEvent e) {
		if (e.getClickCount() == 2) {
			handleProperties();
		}
	    }
	});

	// Install custom renderer to bold the entries which are unusable
	TableCellRenderer renderer = new AddressTableCellRenderer();
	addressTable.setDefaultRenderer(String.class, renderer);
	addressTable.setDefaultRenderer(IPAddress.class, renderer);
	addressTable.setDefaultRenderer(Date.class, renderer);

	// Wrap it in a scroll pane
	addressPane = new JScrollPane(addressTable);

	displayPanel.add(addressPane, BorderLayout.CENTER);

	// Create menu items
	Mnemonic mnShowAddrs =
            new Mnemonic(ResourceStrings.getString("show_addresses"));
	showAddresses = new JCheckBoxMenuItem(mnShowAddrs.getString(),
	    false);
	showAddresses.setMnemonic(mnShowAddrs.getMnemonic());
	showAddresses.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		addressTableModel.setShowAddresses(showAddresses.getState());
	    }
	});

	Mnemonic mnShowGrid =
            new Mnemonic(ResourceStrings.getString("show_grid"));
	showGrid = new JCheckBoxMenuItem(mnShowGrid.getString(),
            true);
	showGrid.setMnemonic(mnShowGrid.getMnemonic());
	showGrid.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		addressTable.setShowGrid(showGrid.getState());
	    }
	});

  	Mnemonic mnAddNet =
            new Mnemonic(ResourceStrings.getString("add_network"));
	addNet = new JMenuItem(mnAddNet.getString());
	addNet.setMnemonic(mnAddNet.getMnemonic());
	addNet.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		ConfigWizard wiz = new ConfigWizard(myFrame,
		    ResourceStrings.getString("net_wiz_title"), false);
		wiz.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
			if (e.getActionCommand().equals("finished")) {
			    reload();
			}
		    }
		});
		wiz.pack();
		wiz.setVisible(true);
	    }
	});


	Mnemonic mnDelNets =
            new Mnemonic(ResourceStrings.getString("delete_networks"));
	deleteNets = new JMenuItem(mnDelNets.getString());
	deleteNets.setMnemonic(mnDelNets.getMnemonic());
	deleteNets.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		DeleteNetworksDialog d = new DeleteNetworksDialog(myFrame);
		d.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
			if (e.getActionCommand().equals(DialogActions.OK)) {
			    reload();
			}
		    }
		});
		d.pack();
		d.setVisible(true);
	    }
	});

	Mnemonic mnAddAddr =
	    new Mnemonic(ResourceStrings.getString("add_addresses"));
	addAddrs = new JMenuItem(mnAddAddr.getString());
	addAddrs.setMnemonic(mnAddAddr.getMnemonic());
	addAddrs.setEnabled(false); // Start out disabled
	addAddrs.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		AddressWizard wiz = new AddressWizard(myFrame,
		    networkListModel.getNetworkAt(
		    networkList.getSelectedIndex()));
		wiz.addActionListener(new DialogListener());
		wiz.pack();
		wiz.setVisible(true);
	    }
	});

	Mnemonic mnRelAddr =
            new Mnemonic(ResourceStrings.getString("release_addresses"));
	releaseAddrs = new JMenuItem(mnRelAddr.getString());
	releaseAddrs.setMnemonic(mnRelAddr.getMnemonic());
	releaseAddrs.setEnabled(false); // Start out disabled
	releaseAddrs.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		int [] rows = addressTable.getSelectedRows();
		if (rows.length == 0) {
		    return;
		}
		DhcpClientRecord [] recs = new DhcpClientRecord[rows.length];
		for (int i = 0; i < rows.length; ++i) {
		    recs[i] = addressTableModel.getClientAt(
			sortedTableModel.mapRowAt(rows[i]));
		}
		ReleaseAddressDialog d = new ReleaseAddressDialog(myFrame, recs,
		    (String)networkListModel.getElementAt(
		    networkList.getSelectedIndex()),
		    showAddresses.isSelected());
		d.addActionListener(new DialogListener());
		d.pack();
		d.setVisible(true);
	    }
	});

	Mnemonic mnOnAddrs =
            new Mnemonic(ResourceStrings.getString("on_addresses_item"));
	addressHelp = new JMenuItem(mnOnAddrs.getString());
	addressHelp.setMnemonic(mnOnAddrs.getMnemonic());
	addressHelp.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		DhcpmgrApplet.showHelp("addresses_reference");
	    }
	});

	/*
	 * Construct the menu lists
	 */
	menuItems = new Vector[MainFrame.MENU_COUNT];
	for (int i = 0; i < menuItems.length; ++i) {
	    menuItems[i] = new Vector();
	}
	menuItems[MainFrame.VIEW_MENU].addElement(showAddresses);
	menuItems[MainFrame.VIEW_MENU].addElement(showGrid);
	menuItems[MainFrame.EDIT_MENU].addElement(addAddrs);
	menuItems[MainFrame.EDIT_MENU].addElement(releaseAddrs);
	menuItems[MainFrame.EDIT_MENU].addElement(addNet);
	menuItems[MainFrame.EDIT_MENU].addElement(deleteNets);
	menuItems[MainFrame.HELP_MENU].addElement(addressHelp);

	// Listen for selections events, manipulate menu item state as needed
	addressTable.getSelectionModel().addListSelectionListener(
		new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		if (addressTable.getSelectionModel().isSelectionEmpty()) {
		    // Disable menu items
		    releaseAddrs.setEnabled(false);
		} else {
		    // Enable menu items
		    releaseAddrs.setEnabled(true);
		}
		// Notify listeners that our selection state may have changed
		notifySelectionListeners();
	    }
	});
    }

    public String getName() {
	return ResourceStrings.getString("address_view_name");
    }

    // Return custom menus for this view, which is nothing at this time
    public Enumeration menus() {
	return null;
    }

    // Return custom menu items for each menu as requested.
    public Enumeration menuItems(int menu) {
	return menuItems[menu].elements();
    }

    public Component getDisplay() {
	return displayPanel;
    }

    public void setActive(boolean state) {
	if (state) {
	    if (firstActivation) {
		// Find frame we're in for use when creating dialogs
		myFrame = (Frame)SwingUtilities.getAncestorOfClass(
		    MainFrame.class, addressTable);
		if (networkListModel.getSize() != 0) {
			networkList.setSelectedIndex(0);
		}
		firstActivation = false;
	    } else {
		// Clear any messages left from other views
		MainFrame.setStatusText("");
	    }
	}
    }

    // Handle a find
    public void find(String s) {
	int startRow = addressTable.getSelectedRow() + 1;
	for (int i = startRow; i < sortedTableModel.getRowCount(); ++i) {
	    DhcpClientRecord rec =
		addressTableModel.getClientAt(sortedTableModel.mapRowAt(i));
	    if (rec.getClientName().indexOf(s) != -1 ||
		    rec.toString().indexOf(s) != -1) {
		addressTable.setRowSelectionInterval(i, i);
		addressTable.scrollRectToVisible(
		    addressTable.getCellRect(i, 0, false));
		return;
	    }
	}
	// Got to the end, wrap around
	for (int i = 0; i < startRow; ++i) {
	    DhcpClientRecord rec =
		addressTableModel.getClientAt(sortedTableModel.mapRowAt(i));
	    if (rec.getClientName().indexOf(s) != -1 ||
		    rec.toString().indexOf(s) != -1) {
		addressTable.setRowSelectionInterval(i, i);
		addressTable.scrollRectToVisible(
		    addressTable.getCellRect(i, 0, false));
		return;
	    }
	}
    }

    public void handleCreate() {
	if (networkList.getSelectedIndex() == -1) {
	    // Tell user to use Network Wizard
	    JOptionPane.showMessageDialog(myFrame,
		ResourceStrings.getString("run_network_wizard"),
		ResourceStrings.getString("error_message"),
		JOptionPane.ERROR_MESSAGE);
	} else {
	    CreateAddressDialog d = new CreateAddressDialog(myFrame,
		CreateAddressDialog.CREATE, new DhcpClientRecord(),
		networkListModel.getNetworkAt(networkList.getSelectedIndex()));
	    d.addActionListener(new DialogListener());
	    d.pack();
	    d.setVisible(true);
	}
    }

    public void handleDelete() {
	int [] rows = addressTable.getSelectedRows();
	if (rows.length == 0) {
	    return;
	}
	DhcpClientRecord [] recs = new DhcpClientRecord[rows.length];
	for (int i = 0; i < rows.length; ++i) {
	    recs[i] = addressTableModel.getClientAt(
		sortedTableModel.mapRowAt(rows[i]));
	}
	DeleteAddressDialog d = new DeleteAddressDialog(myFrame, recs,
	    (String)networkListModel.getElementAt(
	    networkList.getSelectedIndex()));
	d.addActionListener(new DialogListener());
	d.pack();
	d.setVisible(true);
    }

    public void handleDuplicate() {
	int row = addressTable.getSelectedRow();
	if (row == -1) {
	    return;
	}
	DhcpClientRecord rec =
	    addressTableModel.getClientAt(sortedTableModel.mapRowAt(row));
	if (rec == null) {
	    return;
	}
	CreateAddressDialog d = new CreateAddressDialog(myFrame,
	    CreateAddressDialog.DUPLICATE, (DhcpClientRecord)rec.clone(),
	    networkListModel.getNetworkAt(networkList.getSelectedIndex()));
	d.addActionListener(new DialogListener());
	d.pack();
	d.setVisible(true);
    }

    public void handleProperties() {
	int [] rows = addressTable.getSelectedRows();
	if (rows.length == 0) {
	    return;
	}
	DhcpClientRecord [] recs = new DhcpClientRecord[rows.length];
	for (int i = 0; i < rows.length; ++i) {
	    recs[i] =
		addressTableModel.getClientAt(
		sortedTableModel.mapRowAt(rows[i]));
	}
	if (recs.length == 1) {
	    // Edit a single address
	    CreateAddressDialog d = new CreateAddressDialog(myFrame,
		CreateAddressDialog.EDIT, (DhcpClientRecord)recs[0].clone(),
		networkListModel.getNetworkAt(networkList.getSelectedIndex()));
	    d.addActionListener(new DialogListener());
	    d.pack();
	    d.setVisible(true);
	} else {
	    // Edit a group of addresses
	    ModifyAddressesDialog d = new ModifyAddressesDialog(myFrame, recs,
		(String)networkListModel.getElementAt(
		networkList.getSelectedIndex()));
	    d.addActionListener(new DialogListener());
	    d.pack();
	    d.setVisible(true);
	}
    }

    public void handleUpdate() {
	reload();
    }

    protected void reload() {
	Object value = networkList.getSelectedValue();
	networkListModel.reload();
	networkList.clearSelection();
	networkList.setSelectedValue(value, true);
	if (networkListModel.getSize() != 0 &&
	    networkList.getSelectedIndex() == -1) {
	    // Didn't get selected, must be gone.  Select first item in list
	    networkList.setSelectedIndex(0);
	}
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
	return addressTable.getSelectionModel().isSelectionEmpty();
    }

    public boolean isSelectionMultiple() {
	return (addressTable.getSelectedRowCount() > 1);
    }

    public void startAddressWizard() {
	addAddrs.doClick();
    }
}
