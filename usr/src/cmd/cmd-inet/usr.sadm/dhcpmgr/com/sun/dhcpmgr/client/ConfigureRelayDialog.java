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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
package com.sun.dhcpmgr.client;

import javax.swing.*;
import javax.swing.table.*;
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

/**
 * Dialog to configure the server as a BOOTP relay.
 */
public class ConfigureRelayDialog extends DhcpmgrDialog {
    private IPAddressList serverList;
    
    public ConfigureRelayDialog(Frame f) {
	super(f, false);

	setTitle(ResourceStrings.getString("configure_relay_title"));
	buttonPanel.setOkEnabled(true);
    }

    protected JPanel getMainPanel() {
	JPanel panel = new JPanel(new BorderLayout());
	panel.setBorder(
	    BorderFactory.createCompoundBorder(
	    BorderFactory.createEtchedBorder(),
	    BorderFactory.createEmptyBorder(10, 20, 10, 20)));
	
	// Put some explanatory text at the top.
	panel.add(Wizard.createTextArea(
	    ResourceStrings.getString("configure_relay_explain"), 3, 30),
	    BorderLayout.NORTH);
	
	// Control for entering a list of servers
	serverList = new IPAddressList();
	Border tb = BorderFactory.createTitledBorder(
	    BorderFactory.createLineBorder(Color.black),
	    ResourceStrings.getString("dhcp_servers"));
	serverList.setBorder(BorderFactory.createCompoundBorder(tb,
	    BorderFactory.createEmptyBorder(5, 5, 5, 5)));
	panel.add(serverList, BorderLayout.SOUTH);
	
        return panel;
    }

    protected void doOk() {
	if (serverList.getListSize() == 0) {
	    // Must enter at least one DHCP server
	    JOptionPane.showMessageDialog(this,
		ResourceStrings.getString("configure_relay_err_server_list"),
		ResourceStrings.getString("input_error"),
		JOptionPane.ERROR_MESSAGE);
	    return;
	}
	DhcpdOptions options = new DhcpdOptions();
	options.setDaemonEnabled(true);
	options.setRelay(true, serverList.getAddressListString());
	/*
	 * Now write the options to the defaults file, enable the relay,
	 * and start it up.
	 */
	try {
	    DataManager.get().getDhcpServiceMgr().writeDefaults(options);
	    DataManager.get().getDhcpServiceMgr().startup();
	    fireActionPerformed(this, DialogActions.OK);
	    setVisible(false);
	    dispose();
	} catch (Throwable e) {
		e.printStackTrace();
	}
    }

    protected void doCancel() {
	fireActionPerformed(this, DialogActions.CANCEL);
	super.doCancel();
    }

    protected String getHelpKey() {
	return "configure_relay";
    }

    protected void fireActionPerformed() {
        // Do nothing; this is here just to satisfy the abstractness in super
    }
}
