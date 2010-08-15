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

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;

import java.awt.*;
import java.awt.event.*;
import java.text.*;
import java.util.*;

import com.sun.dhcpmgr.server.*;
import com.sun.dhcpmgr.data.*;
import com.sun.dhcpmgr.ui.*;
import com.sun.dhcpmgr.bridge.BridgeException;

/**
 * A dialog to remove one or more networks from the DHCP configuration.
 */
public class DeleteNetworksDialog extends MultipleOperationDialog {

    class NetworkListModel extends AbstractListModel {
	private Vector networks;

	public NetworkListModel() {
	    networks = new Vector();
	}

	public void setNetworks(Network [] nets) {
	    networks.removeAllElements();
	    addNetworks(nets);
	}

	public void addNetworks(Object [] nets) {
	    if (nets != null) {
		for (int i = 0; i < nets.length; ++i) {
		    networks.addElement((Network)nets[i]);
		}
	    }
	    fireContentsChanged(this, 0, networks.size()-1);
	}

	public void deleteNetworks(Object [] nets) {
	    for (int i = 0; i < nets.length; ++i) {
		networks.removeElement((Network)nets[i]);
	    }
	    fireContentsChanged(this, 0, networks.size()-1);
	}

	public Object getElementAt(int index) {
	    return networks.elementAt(index);
	}

	public int getSize() {
	    return networks.size();
	}
    }

    private JList keepNets, deleteNets;
    private LeftButton leftButton;
    private RightButton rightButton;

    public DeleteNetworksDialog(Frame f) {
	// We want a reset button
	super(f, true);
    }

    public String getTitle() {
	return ResourceStrings.getString("delete_networks_title");
    }

    protected JPanel getMainPanel() {
	JPanel mainPanel = new JPanel(new BorderLayout());
	mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

	JPanel netBox = new JPanel(new ProportionalLayout());
	JPanel panel = new JPanel(new BorderLayout(5, 5));

	Mnemonic mnKeep =
            new Mnemonic(ResourceStrings.getString("delete_networks_keep"));
 	JLabel delNetsLbl = new JLabel(mnKeep.getString());
        panel.add(delNetsLbl, BorderLayout.NORTH);
        delNetsLbl.setToolTipText(mnKeep.getString());
        keepNets = new JList(new NetworkListModel());
        delNetsLbl.setLabelFor(keepNets);
	delNetsLbl.setDisplayedMnemonic(mnKeep.getMnemonic());

	keepNets.setSelectionMode(
	    ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
	JScrollPane scrollPane = new JScrollPane(keepNets);
	panel.add(scrollPane, BorderLayout.CENTER);
	netBox.add("2", panel);

	panel = new JPanel(new VerticalButtonLayout());
	leftButton = new LeftButton();
	rightButton = new RightButton();
	rightButton.setEnabled(false);
	leftButton.setEnabled(false);
	panel.add(rightButton);
	panel.add(leftButton);
	netBox.add("1", panel);

	panel = new JPanel(new BorderLayout(5, 5));

	Mnemonic mnDel =
            new Mnemonic(ResourceStrings.getString("delete_networks_delete"));
	JLabel delNets = new JLabel(mnDel.getString());
        panel.add(delNets, BorderLayout.NORTH);

        deleteNets = new JList(new NetworkListModel());
        deleteNets.setSelectionMode(
            ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        delNets.setLabelFor(deleteNets);
        delNets.setToolTipText(mnDel.getString());
	delNets.setDisplayedMnemonic(mnDel.getMnemonic());

	scrollPane = new JScrollPane(deleteNets);
	panel.add(scrollPane, BorderLayout.CENTER);
	netBox.add("2", panel);

	mainPanel.add(netBox, BorderLayout.CENTER);

	// Handle enable and disable of buttons based on selection state
	keepNets.addListSelectionListener(new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		rightButton.setEnabled(!keepNets.isSelectionEmpty());
		if (!keepNets.isSelectionEmpty()) {
		    deleteNets.clearSelection();
		}
	    }
	});

	deleteNets.addListSelectionListener(new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		leftButton.setEnabled(!deleteNets.isSelectionEmpty());
		if (!deleteNets.isSelectionEmpty()) {
		    keepNets.clearSelection();
		}
	    }
	});

	// Handle button presses
	rightButton.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		Object [] nets = keepNets.getSelectedValues();
		((NetworkListModel)deleteNets.getModel()).addNetworks(nets);
		((NetworkListModel)keepNets.getModel()).deleteNetworks(nets);
		if (deleteNets.getModel().getSize() != 0) {
		    buttonPanel.setOkEnabled(true);
		}
		/*
		 * Clear the selection; prevents exceptions from selection
		 * having been deleted
		 */
		keepNets.clearSelection();
	    }
	});

	leftButton.addActionListener(new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		Object [] nets = deleteNets.getSelectedValues();
		((NetworkListModel)keepNets.getModel()).addNetworks(nets);
		((NetworkListModel)deleteNets.getModel()).deleteNetworks(nets);
		/*
		 * Clear the selection; prevents exceptions from selection
		 * having been deleted
		 */
		deleteNets.clearSelection();
		if (deleteNets.getModel().getSize() == 0) {
		    buttonPanel.setOkEnabled(false);
		}
	    }
	});

	doReset();

	return mainPanel;
    }

    protected void doReset() {
	try {
	    buttonPanel.setOkEnabled(false);
	    ((NetworkListModel)deleteNets.getModel()).setNetworks(null);
	    ((NetworkListModel)keepNets.getModel()).setNetworks(
		DataManager.get().getNetworks(false));
	} catch (Throwable e) {
	    e.printStackTrace();
	    // Do nothing
	}
    }

    protected String getProgressMessage() {
    	return ResourceStrings.getString("delete_networks_progress");
    }

    protected int getProgressLength() {
        return deleteNets.getModel().getSize();
    }

    protected String getErrorHeading() {
    	return ResourceStrings.getString("network_column");
    }

    protected Thread getOperationThread() {
    	return new Thread() {
	    public void run() {
		NetworkListModel model =
		    (NetworkListModel)deleteNets.getModel();
		for (int i = 0; i < model.getSize(); ++i) {
		    Network net = (Network)model.getElementAt(i);
		    try {
			DataManager.get().getDhcpNetMgr().deleteNetwork(
			    net.toString(), true);
			updateProgress(i+1, net.toString());
		    } catch (InterruptedException e) {
			// User asked us to stop
			closeDialog();
			return;
		    } catch (Throwable e) {
			addError(net.toString(), e.getMessage());
		    }
		}
		if (errorsOccurred()) {
		    displayErrors(
			ResourceStrings.getString("delete_networks_error"));
    		}
		closeDialog();
	    }
	};
    }

    protected String getHelpKey() {
    	return "delete_network";
    }

    protected void fireActionPerformed() {
	fireActionPerformed(this, DialogActions.OK);
    }
}
