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
 * Copyright 1998-2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.client;

import java.awt.*;
import java.awt.event.*;
import java.text.MessageFormat;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.bridge.BridgeException;

/**
 * This dialog is used to delete one or more addresses from a network
 */

public class DeleteAddressDialog extends MultipleOperationDialog {
    private DhcpClientRecord [] recs;
    private String table;

    // Model for the list of addresses to be deleted
    class AddressTableModel extends AbstractTableModel {
	public int getRowCount() {
	    if (recs == null) {
		return 0;
	    } else {
		return recs.length;
	    }
	}

	public int getColumnCount() {
	    return 2;
	}

	public Object getValueAt(int row, int column) {
	    if (column == 0) {
		return recs[row].getClientIP();
	    } else {
		if (recs[row].getClientName().equals(
			recs[row].getClientIPAddress())) {
		    // Name returned is IP address, so there is no name
		    return "";
		} else {
		    return recs[row].getClientName();
		}
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
    }

    public DeleteAddressDialog(Frame f, DhcpClientRecord [] clients,
	    String table) {
	// Create the dialog without a reset button
	super(f, false);
	recs = clients;
	this.table = table;
    }

    public String getTitle() {
	return ResourceStrings.getString("delete_address_title");
    }

    protected JPanel getMainPanel() {
	JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
	mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

	// Place a message at the top of the display
	JLabel message = new JLabel(
	    ResourceStrings.getString("delete_address_confirm"));

	message.setLabelFor(mainPanel);
	message.setToolTipText(
	    ResourceStrings.getString("delete_address_confirm"));

	mainPanel.add(message, BorderLayout.NORTH);

	// Now show the list of addresses to be deleted in a table in the middle
	JTable addressTable = new JTable(new AddressTableModel());
	JScrollPane scrollPane = new JScrollPane(addressTable);
	Dimension d = addressTable.getPreferredScrollableViewportSize();
	d.height = 100;
	addressTable.setPreferredScrollableViewportSize(d);
	addressTable.setDefaultRenderer(IPAddress.class,
	    new ExtendedCellRenderer());
	mainPanel.add(scrollPane, BorderLayout.CENTER);

	buttonPanel.setOkEnabled(true);
	return mainPanel;
    }

    protected String getProgressMessage() {
    	return ResourceStrings.getString("delete_addr_progress");
    }

    protected int getProgressLength() {
    	return recs.length;
    }

    protected String getErrorHeading() {
        return ResourceStrings.getString("address_column");
    }

    protected Class getErrorClass() {
    	return IPAddress.class;
    }

    protected Thread getOperationThread() {
	// Create the thread we'll use
        return new Thread() {
	    public void run() {
		DhcpNetMgr server = DataManager.get().getDhcpNetMgr();
		for (int i = 0; i < recs.length; ++i) {
		    try {
			server.deleteClient(recs[i], table);
			updateProgress(i+1, recs[i].getClientIPAddress());
		    } catch (InterruptedException e) {
			// User asked us to stop
			closeDialog();
			return;
		    } catch (Throwable e) {
                        addError(recs[i].getClientIP(), e.getMessage());
		    }
		}
		// Errors occurred, display them
		if (errorsOccurred()) {
		    displayErrors(
			ResourceStrings.getString("delete_address_error"));
		}
		closeDialog();
	    }
	};
    }

    protected String getHelpKey() {
	return "delete_address";
    }

    protected void fireActionPerformed() {
	fireActionPerformed(this, DialogActions.DELETE);
    }
}
