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
 * Copyright 2002 by Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
package com.sun.dhcpmgr.ui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import java.util.*;

import com.sun.dhcpmgr.data.IPAddress;
import com.sun.dhcpmgr.data.ValidationException;

/**
 * A panel which allows the user to edit a list of IP addresses.  Consists of
 * a text field for entering new data, paired with a list which allows the
 * addresses entered to be ordered or deleted.
 */
public class IPAddressList extends JPanel {
    IPAddressField address;
    JList serverList;
    IPAddressListModel serverListModel;
    JButton add, delete;
    UpButton moveUp;
    DownButton moveDown;
    
    /**
     * Construct the address list.
     */
    public IPAddressList() {
	super();
	GridBagLayout bag = new GridBagLayout();
	setLayout(bag);
	
	GridBagConstraints c = new GridBagConstraints();
	c.gridx = c.gridy = 0;
	c.weightx = c.weighty = 1.0;
	c.gridheight = 1;
	c.gridwidth = 1;
	
	// Field to type in addresses
	address = new IPAddressField();
	address.getAccessibleContext().setAccessibleDescription(
	    ResourceStrings.getString("dhcp_server_address"));

	c.fill = GridBagConstraints.HORIZONTAL;
	bag.setConstraints(address, c);
	add(address);

	// Button for Add operation
	Mnemonic mnAdd = new Mnemonic(ResourceStrings.getString("add"));
	add = new JButton(mnAdd.getString());
	add.setToolTipText(mnAdd.getString());      
        add.setMnemonic(mnAdd.getMnemonic()); 

	c.fill = GridBagConstraints.NONE;
	++c.gridx;
	c.weightx = 0.5;
	bag.setConstraints(add, c);
	add(add);
	
	// List for addresses
	serverListModel = new IPAddressListModel();
	serverList = new JList(serverListModel);
	// Make sure it's wide enough for our purposes
	serverList.setPrototypeCellValue("222.222.222.222");
	serverList.setSelectionMode(
	    ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
	JScrollPane scrollPane = new JScrollPane(serverList);
	// Don't allow horizontal scrolling here
	scrollPane.setHorizontalScrollBarPolicy(
	    JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
	c.fill = GridBagConstraints.BOTH;
	c.gridx = 0;
	++c.gridy;
	c.weightx = 1.0;
	bag.setConstraints(scrollPane, c);
	add(scrollPane);
	
	// Buttons to manipulate the list contents
	JPanel buttonPanel = new JPanel(new VerticalButtonLayout());
	moveUp = new UpButton();
	moveUp.setToolTipText(ResourceStrings.getString("move_up"));
	buttonPanel.add(moveUp);
	moveDown = new DownButton();
	moveDown.setToolTipText(ResourceStrings.getString("move_down"));
	buttonPanel.add(moveDown);

	Mnemonic mnDelete = new Mnemonic(ResourceStrings.getString("delete"));
	delete = new JButton(mnDelete.getString());
	delete.setToolTipText(mnDelete.getString());	
	delete.setMnemonic(mnDelete.getMnemonic());	

	buttonPanel.add(delete);
	++c.gridx;
	c.weightx = 0.5;
	bag.setConstraints(buttonPanel, c);
	add(buttonPanel);
	
	// Disable all buttons to start; selection changes adjust button state
	add.setEnabled(false);
	delete.setEnabled(false);
	moveUp.setEnabled(false);
	moveDown.setEnabled(false);
	
	// Create listener for button presses, take action as needed
	ActionListener l = new ActionListener() {
	    public void actionPerformed(ActionEvent e) {
		if (e.getSource() == add || e.getSource() == address) {
		    IPAddress a = address.getValue();
		    if (a != null) {
		        serverListModel.addElement(a);
		    }
		} else if (e.getSource() == delete) {
		    int [] indices = serverList.getSelectedIndices();
		    if (indices.length > 1) {
			/*
			 * Need to sort the indices so that the delete's
			 * don't interfere with each other
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
			serverListModel.removeElementAt(indices[i]);
		    }
		    if (indices.length > 1) {
			// Clear selection if multiple deleted
			serverList.clearSelection();
			/*
			 * We don't get a selection event for some reason
			 * so make it work for now
			 */
			delete.setEnabled(false);
		    } else {
			// Make sure to select something in the list
			if (serverListModel.getSize() == 0) {
			    /*
			     * List is empty, nothing to select so disable
			     * delete
			     */
			    delete.setEnabled(false);
			} else if (indices[0] >= serverListModel.getSize()) {
			    // Select last one if we're off the end
			    serverList.setSelectedIndex(
				serverListModel.getSize()-1);
			} else {
			    // Select next one in list
			    serverList.setSelectedIndex(indices[0]);
			}
		    }
		} else if (e.getSource() == moveUp) {
		    int i = serverList.getSelectedIndex();
		    serverListModel.moveUp(i);
		    // Keep item selected so repeated moveUp's affect same item
		    serverList.setSelectedIndex(i-1);
		} else if (e.getSource() == moveDown) {
		    int i = serverList.getSelectedIndex();
		    serverListModel.moveDown(i);
		    // Keep item selected so repeated moveDowns affect same item
		    serverList.setSelectedIndex(i+1);
		}
	    }
	};
	address.addActionListener(l);
	add.addActionListener(l);
	delete.addActionListener(l);
	moveUp.addActionListener(l);
	moveDown.addActionListener(l);
	
	// Put a selection listener on the list to enable buttons appropriately
	serverList.addListSelectionListener(new ListSelectionListener() {
	    public void valueChanged(ListSelectionEvent e) {
		int [] indices = serverList.getSelectedIndices();
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
		    if (indices[0] == 0) {
			moveUp.setEnabled(false);
		    } else {
			moveUp.setEnabled(true);
		    }
		    // Can't move last one down
		    if (indices[0] == (serverListModel.getSize() - 1)) {
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
	// Enable Add when address is not empty.
	address.getDocument().addDocumentListener(new DocumentListener() {
	    public void insertUpdate(DocumentEvent e) {
		add.setEnabled(address.getText().length() != 0);
	    }
	    public void changedUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	    public void removeUpdate(DocumentEvent e) {
		insertUpdate(e);
	    }
	});
    }
    
    /**
     * Initialize the data in the list
     */
    public void setAddressList(IPAddress [] ipAddrs) {
	serverListModel.setData(ipAddrs);
    }
    
    /**
     * Set the addresses from a comma-delimited string
     */
    public void setAddressList(String s) {
	serverListModel.setData(s);
    }
    
    /** 
     * Retrieve the data in the list
     */
    public Vector getAddressList() {
	return serverListModel.getDataVector();
    }
    
    /**
     * Retrieve the list converted to a comma-delimited string
     */
    public String getAddressListString() {
	return serverListModel.getDataString();
    }
    
    /**
     * Return the size of the list
     */
    public int getListSize() {
	return serverListModel.getDataVector().size();
    }

    class IPAddressListModel extends AbstractListModel {
	private Vector addrs;
	
	public IPAddressListModel() {
	    super();
	    addrs = new Vector();
	}
	
	public int getSize() {
	    return addrs.size();
	}
	
	public Object getElementAt(int index) {
	    return addrs.elementAt(index);
	}

	public void setData(IPAddress [] ipAddrs) {
	    addrs.removeAllElements();
	    for (int i = 0; i < ipAddrs.length; ++i) {
		addrs.addElement(ipAddrs[i]);
	    }
	    fireContentsChanged(this, 0, addrs.size()-1);
	}
	
	public void setData(String s) {
	    addrs.removeAllElements();
	    StringTokenizer st = new StringTokenizer(s, ",");
	    while (st.hasMoreTokens()) {
		try {
		    addrs.addElement(new IPAddress(st.nextToken()));
		} catch (ValidationException e) {
		    // Ignore it, didn't parse for some reason
		}
	    }
	    fireContentsChanged(this, 0, addrs.size()-1);
	}
	
	public void addElement(IPAddress addr) {
	    addrs.addElement(addr);
	    fireIntervalAdded(this, addrs.size()-1, addrs.size()-1);
	}
	
	public void removeElementAt(int index) {
	    addrs.removeElementAt(index);
	    fireIntervalRemoved(this, index, index);
	}
	
	public void moveUp(int index) {
	    Object t = addrs.elementAt(index-1);
	    addrs.setElementAt(addrs.elementAt(index), index-1);
	    addrs.setElementAt(t, index);
	    fireContentsChanged(this, index-1, index);
	}
	
	public void moveDown(int index) {
	    Object t = addrs.elementAt(index+1);
	    addrs.setElementAt(addrs.elementAt(index), index+1);
	    addrs.setElementAt(t, index);
	    fireContentsChanged(this, index, index+1);
	}
	
	public Vector getDataVector() {
	    return (Vector)addrs.clone();
	}
	
	public String getDataString() {
	    StringBuffer b = new StringBuffer();
	    Enumeration en = addrs.elements();
	    while (en.hasMoreElements()) {
		if (b.length() != 0) {
		    b.append(',');
		}
		b.append(((IPAddress)en.nextElement()).getHostAddress());
	    }
	    return b.toString();
	}
    }	
}
